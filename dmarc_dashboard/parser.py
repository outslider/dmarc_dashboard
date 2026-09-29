"""DMARC 集計レポート (RFC 7489 Appendix C / DMARCbis) のパーサー。

入力は以下のいずれにも対応する:
  - 生の XML
  - gzip 圧縮された XML (.xml.gz)
  - zip 圧縮された XML (.zip)
  - 上記を添付したメール (.eml / IMAP から取得した RFC822 バイト列)
"""

import email
import email.policy
import gzip
import io
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional

# 解凍後サイズの上限 (解凍爆弾対策)。通常の集計レポートは大きくても数 MB。
MAX_XML_BYTES = 50 * 1024 * 1024


class ReportParseError(Exception):
    pass


@dataclass
class AuthResult:
    kind: str  # "dkim" or "spf"
    domain: str
    result: str
    selector: str = ""
    scope: str = ""


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str
    dkim_eval: str  # policy_evaluated/dkim (アライメント込みの評価)
    spf_eval: str  # policy_evaluated/spf (アライメント込みの評価)
    header_from: str
    envelope_from: str = ""
    envelope_to: str = ""
    reasons: List[str] = field(default_factory=list)
    auth_results: List[AuthResult] = field(default_factory=list)

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_eval == "pass" or self.spf_eval == "pass"


@dataclass
class Report:
    org_name: str
    email: str
    report_id: str
    begin_ts: int
    end_ts: int
    domain: str
    adkim: str = "r"
    aspf: str = "r"
    p: str = "none"
    sp: str = ""
    pct: int = 100
    fo: str = ""
    errors: List[str] = field(default_factory=list)
    records: List[Record] = field(default_factory=list)


def _strip_ns(root: ET.Element) -> None:
    """DMARCbis の名前空間付き XML も同じ XPath で扱えるように名前空間を除去する。"""
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el: Optional[ET.Element], path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_xml(data: bytes) -> Report:
    if len(data) > MAX_XML_BYTES:
        raise ReportParseError("XML が大きすぎます")
    # DMARC レポートに DTD やエンティティ定義は不要。XXE / billion laughs 対策で拒否する。
    head = data[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
        raise ReportParseError("DOCTYPE/ENTITY を含む XML は受け付けません")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ReportParseError(f"XML の解析に失敗しました: {e}") from e
    _strip_ns(root)
    if root.tag != "feedback":
        raise ReportParseError(f"DMARC 集計レポートではありません (root={root.tag})")

    meta = root.find("report_metadata")
    pol = root.find("policy_published")
    if meta is None or pol is None:
        raise ReportParseError("report_metadata / policy_published がありません")

    report = Report(
        org_name=_text(meta, "org_name"),
        email=_text(meta, "email"),
        report_id=_text(meta, "report_id"),
        begin_ts=_int(_text(meta, "date_range/begin")),
        end_ts=_int(_text(meta, "date_range/end")),
        domain=_text(pol, "domain").lower(),
        adkim=_text(pol, "adkim", "r") or "r",
        aspf=_text(pol, "aspf", "r") or "r",
        p=_text(pol, "p", "none") or "none",
        sp=_text(pol, "sp"),
        pct=_int(_text(pol, "pct", "100"), 100),
        fo=_text(pol, "fo"),
        errors=[e.text.strip() for e in meta.findall("error") if e.text],
    )
    if not report.report_id or not report.org_name:
        raise ReportParseError("org_name / report_id がありません")

    for rec in root.findall("record"):
        row = rec.find("row")
        ids = rec.find("identifiers")
        pe = row.find("policy_evaluated") if row is not None else None
        reasons = []
        if pe is not None:
            for r in pe.findall("reason"):
                t = _text(r, "type")
                c = _text(r, "comment")
                reasons.append(f"{t}: {c}" if c else t)
        auth = []
        ar = rec.find("auth_results")
        if ar is not None:
            for d in ar.findall("dkim"):
                auth.append(AuthResult("dkim", _text(d, "domain").lower(), _text(d, "result"),
                                       selector=_text(d, "selector")))
            for s in ar.findall("spf"):
                auth.append(AuthResult("spf", _text(s, "domain").lower(), _text(s, "result"),
                                       scope=_text(s, "scope")))
        report.records.append(Record(
            source_ip=_text(row, "source_ip"),
            count=_int(_text(row, "count")),
            disposition=_text(pe, "disposition", "none") or "none",
            dkim_eval=_text(pe, "dkim", "fail") or "fail",
            spf_eval=_text(pe, "spf", "fail") or "fail",
            header_from=_text(ids, "header_from").lower(),
            envelope_from=_text(ids, "envelope_from").lower(),
            envelope_to=_text(ids, "envelope_to").lower(),
            reasons=reasons,
            auth_results=auth,
        ))
    return report


def _read_limited(stream) -> bytes:
    data = stream.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        raise ReportParseError("解凍後のサイズが大きすぎます")
    return data


def extract_xml_blobs(data: bytes, filename: str = "") -> List[bytes]:
    """圧縮ファイル / XML を判別して XML バイト列のリストを返す。"""
    if data[:4] == b"PK\x03\x04":
        blobs = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    with zf.open(info) as f:
                        blobs.extend(extract_xml_blobs(_read_limited(f), info.filename))
        except zipfile.BadZipFile as e:
            raise ReportParseError(f"zip の展開に失敗しました: {e}") from e
        return blobs
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                return [_read_limited(g)]
        except OSError as e:
            raise ReportParseError(f"gzip の展開に失敗しました: {e}") from e
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"<"):
        return [stripped]
    return []


def _looks_like_mail(data: bytes) -> bool:
    head = data[:2048].lower()
    return any(h in head for h in (b"\nsubject:", b"\nfrom:", b"\ncontent-type:", b"received:", b"return-path:"))


def parse_mail(raw: bytes) -> List[Report]:
    """メール (RFC822) の添付からレポートを取り出す。"""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    reports = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        ctype = part.get_content_type()
        fname = part.get_filename() or ""
        candidate = (
            ctype in ("application/zip", "application/x-zip-compressed", "application/gzip",
                      "application/x-gzip", "text/xml", "application/xml", "application/octet-stream")
            or fname.lower().endswith((".xml", ".gz", ".zip"))
        )
        if not candidate:
            continue
        for blob in extract_xml_blobs(payload, fname):
            reports.append(parse_xml(blob))
    return reports


def parse_any(data: bytes, filename: str = "") -> List[Report]:
    """ファイル種別を自動判別してレポートを返す。"""
    lower = filename.lower()
    if lower.endswith((".eml", ".msg", ".mbox")) or (
        not lower.endswith((".xml", ".gz", ".zip")) and _looks_like_mail(data)
    ):
        return parse_mail(data)
    blobs = extract_xml_blobs(data, filename)
    if not blobs:
        raise ReportParseError("XML / gzip / zip / メールのいずれとしても認識できません")
    return [parse_xml(b) for b in blobs]
