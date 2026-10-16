/**
 * The dashboard's stylesheet and its one script, served from the dashboard itself (the CSP allows
 * 'self' only, and nothing inline). The look is the LaunchSafe product's: Onest at 400 and 500, ink on
 * a plain canvas, hairline rows rather than boxes, a 960px column, spacing on 4/8/12/16/24/32/40/48;
 * light and dark follow the OS. The accent marks only something held or found.
 */

export const CSS = `
@font-face{font-family:"Onest";font-style:normal;font-weight:400 500;font-display:swap;src:url("onest.woff2") format("woff2")}
:root{color-scheme:light dark;
--background:#fff;--ink:#171717;--muted:#525252;--faint:#8f8f8f;--line:rgb(0 0 0 / .1);--line-strong:rgb(0 0 0 / .15);
--hover:rgb(0 0 0 / .04);--surface:#f5f5f5;--accent:#4a64fe;--danger:#ce2930;--warning:#9a5c00;--positive:#018048;--solid:#000;--solid-ink:#fff;--solid-hover:#262626;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{
--background:#000;--ink:#ededed;--muted:#a1a1a1;--faint:#6f6f72;--line:rgb(255 255 255 / .12);--line-strong:rgb(255 255 255 / .22);
--hover:rgb(255 255 255 / .07);--surface:#0a0a0a;--accent:#667efe;--danger:#fa686a;--warning:#eebc4a;--positive:#52cd86;--solid:#ededed;--solid-ink:#000;--solid-hover:#fff}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--background);color:var(--ink);font:400 14px/20px "Onest",ui-sans-serif,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:underline;text-decoration-color:var(--line-strong);text-underline-offset:3px}
a:hover{text-decoration-color:var(--ink)}
:focus-visible{outline:2px solid var(--ink);outline-offset:2px;border-radius:4px}
code,pre,.mono{font-family:var(--mono);font-size:12.5px}
.skip{position:absolute;left:-9999px}.skip:focus{left:16px;top:8px;background:var(--solid);color:var(--solid-ink);padding:4px 8px;z-index:2}
.muted{color:var(--muted)}.strong{font-weight:500}.nowrap{white-space:nowrap}.break{overflow-wrap:anywhere}.num{font-variant-numeric:tabular-nums}
.trunc{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* frame */
header.top{border-bottom:1px solid var(--line)}
.bar{max-width:1008px;margin:0 auto;padding:0 24px;display:flex;align-items:center;gap:24px;min-height:56px}
.brand{font-weight:500;text-decoration:none;white-space:nowrap}.brand span{color:var(--muted);font-weight:400}
nav.tabs{display:flex;gap:4px;min-width:0;overflow-x:auto}
nav.tabs a{text-decoration:none;color:var(--muted);padding:6px 8px;border-radius:8px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
nav.tabs a:hover{color:var(--ink)}
nav.tabs a[aria-current=page]{color:var(--ink);background:var(--hover)}
.ro{margin-left:auto;color:var(--muted);font-size:12px;white-space:nowrap}
main{max-width:1008px;margin:0 auto;padding:40px 24px 64px}
footer.foot{max-width:1008px;margin:0 auto;padding:0 24px 32px;color:var(--muted);font-size:12px}

/* type */
h1{font-size:24px;line-height:32px;font-weight:500;letter-spacing:-.03em;margin:0;display:flex;align-items:center;gap:8px;min-width:0;overflow-wrap:anywhere}
h1 .mono{font-size:20px;letter-spacing:0}
h2{font-size:16px;line-height:24px;font-weight:500;letter-spacing:-.02em;margin:0 0 12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
h2 .h-meta{font-size:13px;font-weight:400;letter-spacing:0;color:var(--muted)}
h3{font-size:13px;line-height:20px;font-weight:500;margin:16px 0 4px}
h3:first-child{margin-top:0}
p{margin:0}
.back{font-size:13px;margin:0 0 8px}.back a{color:var(--muted);text-decoration:none}.back a:hover{color:var(--ink);text-decoration:underline}
.ph{margin-bottom:32px}
.meta{color:var(--muted);font-size:13px;margin-top:4px;display:flex;flex-wrap:wrap;align-items:center;column-gap:0;row-gap:2px}
.sep{margin:0 8px;color:var(--faint)}
.why{margin-top:-8px;max-width:640px}
.hint{color:var(--muted);font-size:13px;margin-top:8px}
section{margin-top:48px}
.ph+section{margin-top:0}
.empty{color:var(--muted);padding:12px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.error{color:var(--danger);margin:16px 0}
.error ul{margin-top:8px}

/* status */
.status{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--faint);flex:none}
.status.ok .dot{background:var(--positive)}
.status.warn{color:var(--warning)}.status.warn .dot{background:var(--warning)}
.status.fail{color:var(--danger)}.status.fail .dot{background:var(--danger)}
.status.held .dot,.dot.held{background:var(--accent)}
.count{display:inline-block;min-width:18px;padding:0 5px;border-radius:999px;font-size:11px;line-height:16px;text-align:center;background:var(--accent);color:#fff;font-weight:500}
.tag{font-size:12px;color:var(--muted);border:1px solid var(--line-strong);border-radius:4px;padding:0 4px;margin-left:4px}
.vref{font-family:var(--mono);font-size:12.5px;border-bottom:1px dashed var(--line-strong)}

/* overview focal point */
.focus{padding:32px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px 24px;flex-wrap:wrap}
.focus-title{font-size:20px;line-height:28px;font-weight:500;letter-spacing:-.02em;display:flex;align-items:center;gap:10px;flex:1 1 auto}
.focus .muted{flex-basis:100%;margin-top:-12px}
.button{display:inline-flex;align-items:center;height:32px;padding:0 12px;border-radius:8px;background:var(--solid);color:var(--solid-ink);text-decoration:none;font-weight:500;white-space:nowrap}
.button:hover{background:var(--solid-hover)}
dl.glance{margin:0}
dl.glance>div{display:grid;grid-template-columns:200px 1fr;gap:16px;padding:12px 0;border-bottom:1px solid var(--line)}
dl.glance dt{color:var(--muted)}
dl.glance dd{margin:0;display:flex;flex-wrap:wrap;align-items:center}
dl.glance a{text-decoration-color:transparent}dl.glance a:hover{text-decoration-color:var(--ink)}
dl.glance .num{font-weight:500}

/* hairline rows */
ul.rows,ul.plain{list-style:none;margin:0;padding:0}
ul.rows{border-top:1px solid var(--line)}
.row{display:flex;align-items:center;gap:16px;min-height:44px;padding:10px 0;border-bottom:1px solid var(--line)}
ul.rows>li>details>summary.row{border-bottom:0}
ul.rows>li:has(details){border-bottom:1px solid var(--line)}
.row .name{font-weight:500;text-decoration-color:transparent;min-width:0;flex:none;max-width:45%}
.row a.name:hover{text-decoration-color:var(--ink)}
.row .c-status{flex:none;width:128px}
.row .c-tag{flex:none;min-width:0;max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .c-grow{flex:1 1 auto;min-width:0}
.row .c-time{flex:none;text-align:right;white-space:nowrap}
.row .c-act{flex:none;font-weight:500;text-decoration-color:var(--line-strong)}
.row.item .name{max-width:50%}
ul.plain li{padding:4px 0}
details>summary{cursor:pointer;list-style:none}
details>summary::-webkit-details-marker{display:none}
.checks summary .name::after{content:"";display:inline-block;width:6px;height:6px;margin-left:8px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:rotate(-45deg) translateY(-2px)}
.checks details[open] summary .name::after{transform:rotate(45deg) translateY(-3px)}
.detail{color:var(--muted);padding:0 0 12px 144px;max-width:780px;overflow-wrap:anywhere}
.rows+details.more,.empty+details.more{margin-top:0;border-top:0}
details.more{margin-top:48px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
details.more>summary{padding:12px 0;font-weight:500;display:flex;align-items:center;gap:8px}
details.more>summary::before{content:"";width:6px;height:6px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:rotate(-45deg)}
details.more[open]>summary::before{transform:rotate(45deg)}
.more-body{padding:0 0 16px}

/* commands */
.cmds{display:grid;grid-template-columns:minmax(0,1fr);gap:8px;margin-top:24px;max-width:640px}
.after{margin-top:16px;max-width:640px;display:grid;grid-template-columns:minmax(0,1fr);gap:8px}
.after .hint{margin-top:0}
.cmd{display:flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:8px;padding:4px 4px 4px 12px;min-height:40px}
.cmd code{flex:1;min-width:0;overflow-x:auto;white-space:nowrap}
button.copy{font:inherit;font-size:12px;font-weight:500;color:var(--ink);background:transparent;border:1px solid var(--line-strong);border-radius:6px;height:28px;padding:0 10px;cursor:pointer;flex:none}
button.copy:hover{background:var(--hover)}

/* tables */
.table{overflow-x:auto;border-top:1px solid var(--line)}
table{border-collapse:collapse;width:100%}
th{font-weight:500;color:var(--muted);font-size:12px;line-height:16px;text-align:left;padding:8px 12px 8px 0;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px 12px 8px 0;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
th:last-child,td:last-child{padding-right:0}
td.n,th.n{width:40px;color:var(--muted)}td.n a{text-decoration-color:transparent}td.n a:hover{text-decoration-color:var(--ink)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}

td.what{max-width:0;width:100%}
pre.block{background:var(--surface);border-radius:8px;padding:16px;margin:0;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;line-height:20px}
.more-body pre.block{margin-top:0}

/* log filter */
nav.seg{display:inline-flex;flex-wrap:wrap;gap:2px;padding:2px;border:1px solid var(--line);border-radius:8px;margin:0 0 16px}
nav.seg a{text-decoration:none;color:var(--muted);font-size:13px;padding:2px 10px;border-radius:6px}
nav.seg a:hover{color:var(--ink)}
nav.seg a[aria-current=true]{background:var(--hover);color:var(--ink);font-weight:500}
.pager{margin-top:16px}

/* diff */
.diff{border:1px solid var(--line);border-radius:8px;overflow-x:auto;margin-top:4px}
.diff table{table-layout:fixed;min-width:720px}
.diff col.c-ln{width:44px}.diff col.c-mark{width:16px}
.diff th{padding:8px 12px;font-weight:500}
.diff td{font-family:var(--mono);font-size:12.5px;line-height:20px;padding:0 10px 0 0;border:0;white-space:pre-wrap;overflow-wrap:anywhere}
.diff td.ln{color:var(--muted);text-align:right;user-select:none;padding-right:8px}
.diff td.mark{color:var(--muted);user-select:none;padding:0 2px}
.diff .del{background:rgb(206 41 48 / .08)}.diff .add{background:rgb(1 128 72 / .09)}
@media (prefers-color-scheme:dark){.diff .del{background:rgb(250 104 106 / .12)}.diff .add{background:rgb(82 205 134 / .11)}}
.diff td.gap{background:var(--surface)}
.diff-unified{display:none}
.diff-unified table{min-width:0}
.diff tbody tr:first-child td{padding-top:8px}.diff tbody tr:last-child td{padding-bottom:8px}

@media (max-width:720px){
.bar{padding:12px 16px 8px;gap:4px 12px;flex-wrap:wrap}.ro{order:2}nav.tabs{order:3;flex-basis:100%;margin:0 -8px}
main{padding:24px 16px 48px}footer.foot{padding:0 16px 24px}
section{margin-top:40px}
.hide-sm{display:none}
.row{flex-wrap:wrap;gap:4px 12px}
.row .c-status{width:auto}
.row .name,.row.item .name{max-width:100%}
.row .c-grow{flex-basis:100%;order:5}
.row .c-time{margin-left:auto}
dl.glance>div{grid-template-columns:1fr;gap:2px}
.detail{padding-left:0}
.focus{padding:24px 0}
.cmd code{white-space:normal;overflow-wrap:anywhere}
nav.seg{display:flex;flex-wrap:nowrap;overflow-x:auto;max-width:100%}nav.seg a{white-space:nowrap}
.diff:not(.diff-unified){display:none}.diff-unified{display:block}}
@media (forced-colors:active){.dot,.count{forced-color-adjust:none;background:CanvasText;color:Canvas}.dot.held,.status.held .dot,.count{background:Highlight;color:HighlightText}}
`;

/** Copy buttons only: the text comes from the button's own data attribute (rendered escaped). */
export const JS = `
document.addEventListener("click", function (ev) {
  var b = ev.target && ev.target.closest ? ev.target.closest("button[data-copy]") : null;
  if (!b) return;
  var text = b.getAttribute("data-copy") || "";
  var done = function () { var t = b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = t; }, 1200); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () {});
});
`;
