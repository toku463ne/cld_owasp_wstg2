// WSTG Runner: small progressive enhancements. Every action also works without JS
// except copying to the clipboard.
"use strict";

function copyText(text) {
  // navigator.clipboard needs a secure context (HTTPS or localhost). The tool is
  // served over plain HTTP on the LAN for now, so fall back to execCommand.
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise(function (resolve, reject) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    ok ? resolve() : reject(new Error("copy failed"));
  });
}

document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("select[data-nav]").forEach(function (sel) {
    sel.addEventListener("change", function () { if (sel.value) window.location = sel.value; });
  });
  document.querySelectorAll("select[data-autosubmit]").forEach(function (sel) {
    sel.addEventListener("change", function () { sel.form.submit(); });
  });
  document.querySelectorAll("button[data-confirm]").forEach(function (btn) {
    btn.addEventListener("click", function (ev) { if (!confirm(btn.getAttribute("data-confirm"))) ev.preventDefault(); });
  });
  document.querySelectorAll("button[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var src = document.querySelector(btn.getAttribute("data-copy"));
      if (!src) return;
      var label = btn.textContent;
      copyText(src.value !== undefined ? src.value : src.textContent).then(
        function () { btn.textContent = "Copied"; },
        function () { btn.textContent = "Copy failed"; }
      ).then(function () { setTimeout(function () { btn.textContent = label; }, 1500); });
    });
  });
});

// CVSS: the metric selects build the vector; the score comes from the server
// (/api/cvss), so the formula exists only once.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".cvss[data-api]").forEach(function (box) {
    var input = box.querySelector("input[name=cvss_vector]"), out = box.querySelector(".cvss-score");
    var selects = box.querySelectorAll("select[data-metric]");
    function fromVector() {
      var parts = {};
      (input.value || "").split("/").forEach(function (p) { var kv = p.split(":"); if (kv.length === 2) parts[kv[0]] = kv[1]; });
      selects.forEach(function (s) { s.value = parts[s.dataset.metric] || ""; });
    }
    function show() {
      if (!input.value) { out.textContent = ""; return; }
      var set = 0;
      selects.forEach(function (x) { if (x.value) set++; });
      if (set < selects.length) { out.innerHTML = '<span class="muted">choose all 8 metrics</span>'; return; }
      fetch(box.dataset.api + "?vector=" + encodeURIComponent(input.value), {credentials: "same-origin"})
        .then(function (r) { return r.json(); })
        .then(function (j) {
          out.innerHTML = "";
          var span = document.createElement("span");
          if (j.error) { span.className = "muted"; span.textContent = j.error; }
          else { span.className = "sev sev-" + j.severity.toLowerCase(); span.textContent = j.score + " " + j.severity; }
          out.appendChild(span);
        });
    }
    selects.forEach(function (s) {
      s.addEventListener("change", function () {
        var v = "CVSS:3.1";
        selects.forEach(function (x) { if (x.value) v += "/" + x.dataset.metric + ":" + x.value; });
        input.value = v; show();
      });
    });
    input.addEventListener("change", function () { fromVector(); show(); });
    fromVector();
  });
});
