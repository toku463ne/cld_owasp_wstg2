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
