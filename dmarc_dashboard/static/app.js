"use strict";

const $ = (s) => document.querySelector(s);
const nf = new Intl.NumberFormat("ja-JP");
const fmt = (n) => (n == null ? "–" : nf.format(n));
const pct = (n) => (n == null ? "–" : `${n.toFixed(1)}%`);
const SVGNS = "http://www.w3.org/2000/svg";

const STATUS = {
  ok: { label: "正常", c: "var(--good)", ic: "✓" },
  partial: { label: "一部失敗", c: "var(--warning)", ic: "!" },
  misaligned: { label: "設定不備疑い", c: "var(--serious)", ic: "!" },
  unauthenticated: { label: "なりすまし疑い", c: "var(--critical)", ic: "✕" },
};
const SEVERITY = {
  critical: { label: "重大", c: "var(--critical)", ic: "✕" },
  serious: { label: "要対応", c: "var(--serious)", ic: "!" },
  warning: { label: "注意", c: "var(--warning)", ic: "!" },
  good: { label: "良好", c: "var(--good)", ic: "✓" },
  info: { label: "情報", c: "var(--muted)", ic: "i" },
};

const state = { days: 30, from: "", to: "", domain: "", srcFilter: "" };
let data = null;

// ---------- DOM helpers (データ由来の文字列は必ず textContent で入れる) ----------
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}
function svg(tag, attrs = {}) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}
function badge(def) {
  return el("span", { class: "badge", style: `--c:${def.c}` }, def.label);
}
function meter(rate) {
  const r = rate == null ? 0 : rate;
  const c = r >= 98 ? "var(--good)" : r >= 90 ? "var(--warning)" : "var(--critical)";
  return el("span", { class: "meter" },
    el("span", { class: "bar" }, el("i", { style: `width:${r}%;background:${c}` })),
    pct(rate));
}
function table(target, columns, rows, onRow) {
  const t = typeof target === "string" ? $(target) : target;
  t.replaceChildren();
  t.append(el("thead", {}, el("tr", {}, columns.map((c) => el("th", { class: c.num ? "num" : "" }, c.label)))));
  const tb = el("tbody");
  if (!rows.length) {
    tb.append(el("tr", {}, el("td", { colspan: columns.length, class: "dim" }, "データがありません")));
  }
  for (const r of rows) {
    const tr = el("tr", onRow ? { class: "clickable", tabindex: 0 } : {},
      columns.map((c) => {
        const v = c.render(r);
        return el("td", { class: [c.num ? "num" : "", c.cls || ""].join(" ") }, v);
      }));
    if (onRow) {
      tr.addEventListener("click", () => onRow(r));
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") onRow(r); });
    }
    tb.append(tr);
  }
  t.append(tb);
}
const dateStr = (ts) => {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, "0")}/${String(d.getDate()).padStart(2, "0")}`;
};
const isoDay = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

// ---------- tooltip ----------
const tip = $("#tooltip");
function showTip(evt, header, rows) {
  tip.replaceChildren(el("div", { class: "tt-h" }, header),
    ...rows.map(([color, name, value]) => el("div", { class: "tt-r" },
      el("span", { class: "key", style: `background:${color}` }), el("b", {}, value), el("span", {}, name))));
  tip.style.display = "block";
  const x = Math.min(evt.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
  const y = Math.min(evt.clientY + 14, window.innerHeight - tip.offsetHeight - 8);
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}
function hideTip() { tip.style.display = "none"; }

// ---------- scales ----------
function niceMax(v, ticks = 4) {
  if (v <= 0) return { max: 1, step: 1 };
  const raw = v / ticks;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw);
  return { max: step * Math.ceil(v / step), step };
}
const compact = (n) => (n >= 1e6 ? `${+(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${+(n / 1e3).toFixed(1)}K` : nf.format(n));
const shortDay = (s) => s.slice(5).replace("-", "/");

// ---------- 日別積み上げ棒 ----------
function columnChart(host, rows) {
  host.replaceChildren();
  const W = Math.max(host.clientWidth, 280), H = 240, m = { t: 12, r: 8, b: 26, l: 48 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "日別メッセージ数 (合格/失敗)" });
  if (!rows.length) { host.append(el("p", { class: "dim" }, "データがありません")); return; }
  const { max, step } = niceMax(Math.max(...rows.map((r) => r.pass + r.fail)));
  const y = (v) => m.t + ih - (v / max) * ih;
  for (let v = 0; v <= max + 1e-9; v += step) {
    s.append(svg("line", { class: v === 0 ? "baseline" : "gridline", x1: m.l, x2: W - m.r, y1: y(v), y2: y(v) }));
    const t = svg("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end" }); t.textContent = compact(v); s.append(t);
  }
  const band = iw / rows.length, bw = Math.max(2, Math.min(24, band * 0.7));
  const labelEvery = Math.ceil(rows.length / Math.max(2, Math.floor(iw / 64)));
  const hover = svg("rect", { class: "col-hover", y: m.t, height: ih, width: band, visibility: "hidden" });
  s.append(hover);
  rows.forEach((r, i) => {
    const cx = m.l + band * i + band / 2, x = cx - bw / 2;
    const yPass = y(r.pass), yTop = y(r.pass + r.fail);
    const segs = [];
    if (r.pass > 0) segs.push({ y0: y(0), y1: yPass, c: "var(--good)" });
    if (r.fail > 0) segs.push({ y0: r.pass > 0 ? yPass - 2 : y(0), y1: Math.min(yTop, (r.pass > 0 ? yPass - 2 : y(0)) - 1), c: "var(--critical)" });
    segs.forEach((g, gi) => {
      const top = gi === segs.length - 1;
      const h = Math.max(1, g.y0 - g.y1), rr = top ? Math.min(4, h, bw / 2) : 0;
      const d = `M${x},${g.y0} V${g.y1 + rr} Q${x},${g.y1} ${x + rr},${g.y1} H${x + bw - rr} Q${x + bw},${g.y1} ${x + bw},${g.y1 + rr} V${g.y0} Z`;
      s.append(svg("path", { d, fill: g.c }));
    });
    if (i % labelEvery === 0) {
      const t = svg("text", { x: cx, y: H - 8, "text-anchor": "middle" }); t.textContent = shortDay(r.day); s.append(t);
    }
    const hit = svg("rect", { class: "hit", x: m.l + band * i, y: m.t, width: band, height: ih, tabindex: 0 });
    const on = (e) => {
      hover.setAttribute("x", m.l + band * i); hover.setAttribute("visibility", "visible");
      const tot = r.pass + r.fail;
      const ev = e.clientX != null ? e : { clientX: hit.getBoundingClientRect().right, clientY: hit.getBoundingClientRect().top };
      showTip(ev, r.day, [["var(--good)", "合格", fmt(r.pass)], ["var(--critical)", "失敗", fmt(r.fail)],
        ["var(--muted)", "合格率", tot ? pct((r.pass * 100) / tot) : "–"]]);
    };
    hit.addEventListener("pointermove", on); hit.addEventListener("focus", on);
    const off = () => { hover.setAttribute("visibility", "hidden"); hideTip(); };
    hit.addEventListener("pointerleave", off); hit.addEventListener("blur", off);
    s.append(hit);
  });
  host.append(s);
}

// ---------- 合格率の折れ線 ----------
function lineChart(host, rows) {
  host.replaceChildren();
  const pts = rows.filter((r) => r.pass + r.fail > 0).map((r) => ({ day: r.day, v: (r.pass * 100) / (r.pass + r.fail) }));
  if (!pts.length) { host.append(el("p", { class: "dim" }, "データがありません")); return; }
  const W = Math.max(host.clientWidth, 280), H = 240, m = { t: 12, r: 52, b: 26, l: 48 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const lo = Math.max(0, Math.min(90, Math.floor(Math.min(...pts.map((p) => p.v)) / 10) * 10));
  const y = (v) => m.t + ih - ((v - lo) / (100 - lo)) * ih;
  const x = (i) => m.l + (pts.length === 1 ? iw / 2 : (i / (pts.length - 1)) * iw);
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "日別 DMARC 合格率" });
  const step = (100 - lo) / 4;
  for (let v = lo; v <= 100.001; v += step) {
    s.append(svg("line", { class: v === lo ? "baseline" : "gridline", x1: m.l, x2: m.l + iw, y1: y(v), y2: y(v) }));
    const t = svg("text", { x: m.l - 8, y: y(v) + 4, "text-anchor": "end" }); t.textContent = `${Math.round(v)}%`; s.append(t);
  }
  const labelEvery = Math.ceil(pts.length / Math.max(2, Math.floor(iw / 64)));
  pts.forEach((p, i) => {
    if (i % labelEvery === 0) {
      const t = svg("text", { x: x(i), y: H - 8, "text-anchor": "middle" }); t.textContent = shortDay(p.day); s.append(t);
    }
  });
  s.append(svg("path", {
    d: pts.map((p, i) => `${i ? "L" : "M"}${x(i)},${y(p.v)}`).join(" "),
    fill: "none", stroke: "var(--series-1)", "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round",
  }));
  const last = pts[pts.length - 1];
  s.append(svg("circle", { cx: x(pts.length - 1), cy: y(last.v), r: 4, fill: "var(--series-1)", stroke: "var(--surface)", "stroke-width": 2 }));
  const lt = svg("text", { x: x(pts.length - 1) + 8, y: y(last.v) + 4, style: "fill:var(--text);font-weight:600" });
  lt.textContent = pct(last.v); s.append(lt);

  const cross = svg("line", { class: "crosshair", y1: m.t, y2: m.t + ih, visibility: "hidden" });
  const dot = svg("circle", { r: 4, fill: "var(--series-1)", stroke: "var(--surface)", "stroke-width": 2, visibility: "hidden" });
  s.append(cross, dot);
  const hit = svg("rect", { class: "hit", x: m.l, y: m.t, width: iw, height: ih });
  hit.addEventListener("pointermove", (e) => {
    const r = s.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = Math.max(0, Math.min(pts.length - 1, Math.round(((px - m.l) / iw) * (pts.length - 1))));
    cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.setAttribute("visibility", "visible");
    dot.setAttribute("cx", x(i)); dot.setAttribute("cy", y(pts[i].v)); dot.setAttribute("visibility", "visible");
    showTip(e, pts[i].day, [["var(--series-1)", "合格率", pct(pts[i].v)]]);
  });
  hit.addEventListener("pointerleave", () => { cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); hideTip(); });
  s.append(hit);
  host.append(s);
}

// ---------- 横棒 ----------
function hbars(host, items, legend) {
  host.replaceChildren();
  if (legend) {
    host.append(el("div", { class: "legend", style: "margin-bottom:10px" },
      legend.map(([c, n]) => el("span", {}, el("i", { class: "sw", style: `background:${c}` }), n))));
  }
  const max = Math.max(1, ...items.map((i) => i.parts.reduce((a, p) => a + p.v, 0)));
  const wrap = el("div", { class: "hbars" });
  if (!items.length) wrap.append(el("p", { class: "dim" }, "データがありません"));
  for (const it of items) {
    const total = it.parts.reduce((a, p) => a + p.v, 0);
    const track = el("div", { class: "track" },
      it.parts.filter((p) => p.v > 0).map((p) => el("div", {
        class: "seg-bar", style: `width:${(p.v / max) * 100}%;background:${p.c}`,
      })));
    const row = el("div", { class: "hbar", tabindex: 0 },
      el("span", { class: "name", title: it.name }, it.name), track,
      el("span", { class: "val" }, fmt(total), it.sub ? el("small", {}, ` ${it.sub}`) : null));
    const on = (e) => {
      const ev = e.clientX != null ? e : { clientX: row.getBoundingClientRect().right - 100, clientY: row.getBoundingClientRect().bottom };
      showTip(ev, it.name, it.parts.map((p) => [p.c, p.n, fmt(p.v)]));
    };
    row.addEventListener("pointermove", on); row.addEventListener("focus", on);
    row.addEventListener("pointerleave", hideTip); row.addEventListener("blur", hideTip);
    wrap.append(row);
  }
  host.append(wrap);
}

// ---------- ドメイン別表のセル ----------
function issues(c) {
  const parts = ["critical", "serious", "warning"].filter((k) => c && c[k])
    .map((k) => el("span", { class: "badge", style: `--c:${SEVERITY[k].c}` }, `${SEVERITY[k].label} ${c[k]}`));
  return parts.length ? el("span", { class: "issues" }, parts) : el("span", { class: "dim" }, "なし");
}
const dayRate = (r) => (r.pass + r.fail ? (r.pass * 100) / (r.pass + r.fail) : null);
// 全ドメインで同じ縦軸にそろえて比較できるようにする
function sparkFloor(domains) {
  const vals = domains.flatMap((dm) => (dm.daily || []).map(dayRate)).filter((v) => v != null);
  return vals.length ? Math.max(0, Math.min(90, Math.floor(Math.min(...vals) / 10) * 10)) : 0;
}
function sparkline(rows, lo) {
  const pts = (rows || []).filter((r) => r.pass + r.fail > 0).map((r) => ({ day: r.day, v: dayRate(r) }));
  if (!pts.length) return el("span", { class: "dim" }, "–");
  const W = 120, H = 28, pad = 4;
  const x = (i) => pad + (pts.length === 1 ? (W - 2 * pad) / 2 : (i / (pts.length - 1)) * (W - 2 * pad));
  const y = (v) => pad + (1 - (v - lo) / (100 - lo || 1)) * (H - 2 * pad);
  const s = svg("svg", { class: "spark", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img",
    "aria-label": `合格率の推移 ${pct(pts[0].v)} → ${pct(pts[pts.length - 1].v)}` });
  s.append(svg("line", { class: "gridline", x1: pad, x2: W - pad, y1: y(100), y2: y(100) }));
  s.append(svg("path", {
    d: pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join(" "),
    fill: "none", stroke: "var(--series-1)", "stroke-width": 1.5, "stroke-linejoin": "round", "stroke-linecap": "round",
  }));
  const last = pts.length - 1;
  s.append(svg("circle", { cx: x(last), cy: y(pts[last].v), r: 3, fill: "var(--series-1)", stroke: "var(--surface)", "stroke-width": 1.5 }));
  const dot = svg("circle", { r: 3, fill: "var(--series-1)", stroke: "var(--surface)", "stroke-width": 1.5, visibility: "hidden" });
  s.append(dot);
  s.addEventListener("pointermove", (e) => {
    const r = s.getBoundingClientRect();
    const i = Math.max(0, Math.min(last, Math.round((((e.clientX - r.left) / r.width) * W - pad) / (W - 2 * pad) * last)));
    dot.setAttribute("cx", x(i)); dot.setAttribute("cy", y(pts[i].v)); dot.setAttribute("visibility", "visible");
    showTip(e, pts[i].day, [["var(--series-1)", "合格率", pct(pts[i].v)]]);
  });
  s.addEventListener("pointerleave", () => { dot.setAttribute("visibility", "hidden"); hideTip(); });
  return s;
}

// ---------- render ----------
function render() {
  const d = data, k = d.kpi;
  $("#k-rate").textContent = pct(k.pass_rate);
  $("#k-rate-sub").textContent = k.messages ? `${fmt(k.pass)} / ${fmt(k.messages)} 通が合格` : "";
  $("#k-messages").textContent = fmt(k.messages);
  $("#k-fail").textContent = fmt(k.fail);
  $("#k-spf").textContent = pct(k.spf_aligned_rate);
  $("#k-dkim").textContent = pct(k.dkim_aligned_rate);
  $("#k-disp").replaceChildren(fmt(k.quarantine), el("small", {}, " / "), fmt(k.reject));
  $("#k-sources").textContent = fmt(k.sources);
  $("#period-label").textContent = k.first_ts
    ? `レポート ${fmt(k.reports)} 件 (${fmt(k.reporters)} 組織) · ${dateStr(k.first_ts)} – ${dateStr(k.last_ts)}` : "";

  const sel = $("#domain");
  const cur = state.domain;
  sel.replaceChildren(el("option", { value: "" }, "すべて"), ...d.all_domains.map((x) => el("option", { value: x }, x)));
  sel.value = cur;
  $("#fetch-btn").hidden = !d.imap_enabled;

  $("#insights").replaceChildren(...d.insights.map((i) => {
    const sv = SEVERITY[i.severity];
    const dom = i.domain && !state.domain
      ? el("button", { class: "pill link", title: `${i.domain} で絞り込む`, onclick: () => selectDomain(i.domain) }, i.domain)
      : null;
    return el("li", {}, el("span", { class: "badge", style: `--c:${sv.c}` }, sv.label),
      el("span", { class: "t" }, dom, dom ? " " : null, i.title), el("span", { class: "d" }, i.detail));
  }));

  columnChart($("#chart-daily"), d.daily);
  lineChart($("#chart-rate"), d.daily);
  const dt = el("table");
  table(dt, [
    { label: "日付", render: (r) => r.day },
    { label: "合格", num: 1, render: (r) => fmt(r.pass) },
    { label: "失敗", num: 1, render: (r) => fmt(r.fail) },
    { label: "合格率", num: 1, render: (r) => (r.pass + r.fail ? pct((r.pass * 100) / (r.pass + r.fail)) : "–") },
  ], [...d.daily].reverse());
  $("#tbl-daily").replaceChildren(el("div", { class: "table-wrap" }, dt));

  const am = {};
  d.auth_matrix.forEach((r) => { am[`${r.spf}|${r.dkim}`] = (am[`${r.spf}|${r.dkim}`] || 0) + r.messages; });
  const sum = (f) => Object.entries(am).filter(([kk]) => f(...kk.split("|"))).reduce((a, [, v]) => a + v, 0);
  const tot = k.messages || 1;
  const authItems = [
    ["SPF・DKIM とも合格", sum((s, dk) => s === "pass" && dk === "pass")],
    ["DKIM のみ合格", sum((s, dk) => s !== "pass" && dk === "pass")],
    ["SPF のみ合格", sum((s, dk) => s === "pass" && dk !== "pass")],
    ["両方失敗 (DMARC 失敗)", sum((s, dk) => s !== "pass" && dk !== "pass")],
  ].map(([n, v]) => ({ name: n, sub: pct((v * 100) / tot), parts: [{ v, c: "var(--series-1)", n: "メッセージ" }] }));
  hbars($("#chart-auth"), authItems);

  hbars($("#chart-reporters"), d.reporters.slice(0, 10).map((r) => ({
    name: r.org, sub: pct((r.pass * 100) / (r.messages || 1)),
    parts: [{ v: r.pass, c: "var(--good)", n: "合格" }, { v: r.messages - r.pass, c: "var(--critical)", n: "失敗" }],
  })), [["var(--good)", "合格"], ["var(--critical)", "失敗"]]);

  const sparkLo = sparkFloor(d.domains);
  table("#tbl-domains", [
    { label: "ドメイン", render: (r) => r.domain },
    { label: "要対応", render: (r) => issues(r.issues) },
    { label: "合格率の推移", render: (r) => sparkline(r.daily, sparkLo) },
    { label: "ポリシー", render: (r) => el("span", { class: "pill" }, `p=${r.p || "none"}${r.sp ? ` sp=${r.sp}` : ""}${r.pct != null && r.pct !== 100 ? ` pct=${r.pct}` : ""}`) },
    { label: "アライメント", render: (r) => `adkim=${r.adkim || "r"} aspf=${r.aspf || "r"}` },
    { label: "メッセージ", num: 1, render: (r) => fmt(r.messages) },
    { label: "DMARC 合格率", render: (r) => meter((r.pass * 100) / (r.messages || 1)) },
    { label: "SPF 整合", num: 1, render: (r) => pct((r.spf * 100) / (r.messages || 1)) },
    { label: "DKIM 整合", num: 1, render: (r) => pct((r.dkim * 100) / (r.messages || 1)) },
  ], d.domains, (r) => selectDomain(r.domain));

  renderSources();

  table("#tbl-reports", [
    { label: "期間", render: (r) => `${dateStr(r.begin_ts)} – ${dateStr(r.end_ts)}` },
    { label: "レポーター", render: (r) => r.org_name },
    { label: "ドメイン", render: (r) => r.domain },
    { label: "p", render: (r) => r.p },
    { label: "メッセージ", num: 1, render: (r) => fmt(r.messages) },
    { label: "合格率", num: 1, render: (r) => pct(((r.pass || 0) * 100) / (r.messages || 1)) },
    { label: "レポート ID", cls: "mono dim", render: (r) => r.report_id },
    { label: "エラー", cls: "wrap", render: (r) => r.errors.join(" / ") },
  ], d.reports);
}

function renderSources() {
  const f = state.srcFilter;
  const rows = data.sources.filter((s) => !f || (f === "fail" ? s.fail > 0 : s.status === f));
  table("#tbl-sources", [
    { label: "状態", render: (r) => badge(STATUS[r.status]) },
    { label: "送信元 IP", cls: "mono", render: (r) => r.ip },
    { label: "ホスト名 (PTR)", render: (r) => el("span", {}, r.provider ? el("span", { class: "pill" }, r.provider) : null, r.provider ? " " : null, el("span", { class: "dim" }, r.ptr || "(逆引きなし)")) },
    { label: "From ドメイン", render: (r) => r.header_from.join(", ") },
    { label: "メッセージ", num: 1, render: (r) => fmt(r.messages) },
    { label: "失敗", num: 1, render: (r) => fmt(r.fail) },
    { label: "主な失敗理由", render: (r) => failSummary(r) },
    { label: "合格率", render: (r) => meter(r.pass_rate) },
    { label: "SPF 整合", num: 1, render: (r) => pct((r.spf_aligned * 100) / r.messages) },
    { label: "DKIM 整合", num: 1, render: (r) => pct((r.dkim_aligned * 100) / r.messages) },
    { label: "SPF ドメイン", cls: "dim", render: (r) => r.spf_domains.join(", ") },
    { label: "DKIM 署名", cls: "dim", render: (r) => r.dkim_domains.join(", ") },
  ], rows, openDetail);
}

// 送信元一覧: 失敗の多い理由から最大 2 つ (残りはツールチップ)
function failSummary(r) {
  const fr = r.fail_reasons || [];
  if (!fr.length) return el("span", { class: "dim" }, "–");
  const title = fr.map((f) => `${f.label}: ${fmt(f.messages)} 通`).join("\n");
  return el("span", { title }, fr.slice(0, 2).map((f) => f.label).join(" · "), fr.length > 2 ? el("span", { class: "dim" }, ` 他${fr.length - 2}`) : null);
}
// 詳細: 1 レコードの失敗理由と、受信側による判定の上書き
function failDetail(r) {
  const items = [];
  if (!r.failures.length) items.push(el("div", { class: "res-pass" }, "DMARC 合格"));
  for (const f of r.failures) items.push(el("div", {}, el("b", {}, f.label), el("span", { class: "dim" }, ` ${f.detail}`)));
  for (const o of r.overrides) items.push(el("div", {}, el("b", {}, "受信側の判断"), el("span", { class: "dim" }, ` ${o}`)));
  return el("div", { class: "reason-list" }, items);
}

async function openDetail(src) {
  $("#detail-title").textContent = `${src.ip}  ${src.ptr || ""}`;
  const rows = await api(`api/source?${params({ ip: src.ip })}`);
  const res = (v) => el("span", { class: v === "pass" ? "res-pass" : v === "none" ? "dim" : "res-fail" }, v);
  table("#tbl-detail", [
    { label: "期間", render: (r) => `${dateStr(r.begin_ts)}` },
    { label: "レポーター", render: (r) => r.org_name },
    { label: "From", render: (r) => r.header_from },
    { label: "Envelope From", render: (r) => r.envelope_from || "–" },
    { label: "件数", num: 1, render: (r) => fmt(r.count) },
    { label: "処置", render: (r) => r.disposition },
    { label: "SPF (整合)", render: (r) => res(r.spf_eval) },
    { label: "DKIM (整合)", render: (r) => res(r.dkim_eval) },
    { label: "失敗理由", cls: "wrap reasons", render: (r) => failDetail(r) },
    { label: "認証結果 (生)", cls: "wrap", render: (r) => el("span", {}, r.auth.map((a, i) => el("span", {},
      i ? " · " : "", `${a.kind.toUpperCase()} ${a.domain}${a.selector ? ` (${a.selector})` : ""}: `, res(a.result)))) },
  ], rows);
  $("#detail").showModal();
}

// ---------- data loading ----------
function params(extra = {}) {
  const p = new URLSearchParams();
  if (state.domain) p.set("domain", state.domain);
  if (state.from) p.set("from", state.from);
  if (state.to) p.set("to", state.to);
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  return p.toString();
}
async function api(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}
// 絞り込み状態を URL (?domain=...&range=30 / &from=...&to=...) に反映し、ブックマーク・共有できるようにする
function saveUrl() {
  const p = new URLSearchParams();
  if (state.domain) p.set("domain", state.domain);
  if (state.days > 0) p.set("range", state.days);
  else if (state.days === 0) p.set("range", "all");
  else {
    if (state.from) p.set("from", state.from);
    if (state.to) p.set("to", state.to);
  }
  const q = p.toString();
  history.replaceState(null, "", q ? `?${q}` : location.pathname);
}
function restoreUrl() {
  const p = new URLSearchParams(location.search);
  state.domain = p.get("domain") || "";
  const range = p.get("range");
  const valid = /^\d{4}-\d{2}-\d{2}$/;
  if (range === "all") applyPreset(0);
  else if (range && /^\d+$/.test(range)) applyPreset(Math.min(+range, 3650));
  else if (valid.test(p.get("from") || "") || valid.test(p.get("to") || "")) {
    applyPreset(-1);
    state.from = valid.test(p.get("from") || "") ? p.get("from") : "";
    state.to = valid.test(p.get("to") || "") ? p.get("to") : "";
    $("#from").value = state.from; $("#to").value = state.to;
  } else applyPreset(30);
}
function selectDomain(dom) {
  state.domain = dom;
  load();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
async function load() {
  saveUrl();
  $("#main").classList.add("loading");
  try {
    data = await api(`api/dashboard?${params()}`);
    render();
  } catch (e) {
    toast(`読み込みに失敗しました: ${e.message}`);
  } finally {
    $("#main").classList.remove("loading");
  }
}
function applyPreset(days) {
  state.days = days;
  document.querySelectorAll("#range-presets button").forEach((b) => b.classList.toggle("on", +b.dataset.days === days));
  if (days < 0) return;  // 日付の直接指定
  if (days) {
    const to = new Date(), from = new Date();
    from.setDate(from.getDate() - days + 1);
    state.from = isoDay(from); state.to = isoDay(to);
  } else {
    state.from = ""; state.to = "";
  }
  $("#from").value = state.from; $("#to").value = state.to;
}
let toastTimer;
function toast(msg) {
  $("#toast").textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("#toast").textContent = ""; }, 8000);
}

async function uploadFiles(files) {
  let imp = 0, dup = 0; const errs = [];
  for (const f of files) {
    try {
      const r = await api("api/upload", {
        method: "POST", body: f,
        headers: { "X-Filename": encodeURIComponent(f.name), "X-Requested-With": "dmarc-dashboard" },
      });
      imp += r.imported; dup += r.duplicates; errs.push(...r.errors);
    } catch (e) { errs.push(`${f.name}: ${e.message}`); }
  }
  toast(`取り込み ${imp} 件 / 重複 ${dup} 件${errs.length ? ` / エラー ${errs.length} 件: ${errs[0]}` : ""}`);
  load();
}

// ---------- events ----------
document.querySelectorAll("#range-presets button").forEach((b) =>
  b.addEventListener("click", () => { applyPreset(+b.dataset.days); load(); }));
["from", "to"].forEach((id) => $(`#${id}`).addEventListener("change", (e) => {
  state[id] = e.target.value; state.days = -1;
  document.querySelectorAll("#range-presets button").forEach((b) => b.classList.remove("on"));
  load();
}));
$("#domain").addEventListener("change", (e) => { state.domain = e.target.value; load(); });
document.querySelectorAll("#src-filter button").forEach((b) => b.addEventListener("click", () => {
  state.srcFilter = b.dataset.f;
  document.querySelectorAll("#src-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderSources();
}));
$("#upload").addEventListener("change", (e) => { uploadFiles([...e.target.files]); e.target.value = ""; });
$("#fetch-btn").addEventListener("click", async () => {
  const b = $("#fetch-btn"); b.disabled = true; toast("メールを取得中…");
  try {
    const r = await api("api/fetch", { method: "POST", headers: { "X-Requested-With": "dmarc-dashboard" } });
    toast(r.message); load();
  } catch (e) { toast(`取得に失敗しました: ${e.message}`); } finally { b.disabled = false; }
});
$("#detail-close").addEventListener("click", () => $("#detail").close());

let dragDepth = 0;
window.addEventListener("dragenter", (e) => { e.preventDefault(); dragDepth++; $("#drop").classList.add("show"); });
window.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; $("#drop").classList.remove("show"); } });
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => {
  e.preventDefault(); dragDepth = 0; $("#drop").classList.remove("show");
  if (e.dataTransfer.files.length) uploadFiles([...e.dataTransfer.files]);
});

const THEMES = ["", "light", "dark"];
function setTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  try { localStorage.setItem("dmarc-theme", t); } catch (_) { /* ignore */ }
}
try { setTheme(localStorage.getItem("dmarc-theme") || ""); } catch (_) { /* ignore */ }
$("#theme-btn").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme || "";
  setTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
});

let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { if (data) { columnChart($("#chart-daily"), data.daily); lineChart($("#chart-rate"), data.daily); } }, 150);
});

restoreUrl();
load();
