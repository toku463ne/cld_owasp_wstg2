// Screenshot capture (the mine.wstg method): every ".capture[data-url]" box
// accepts pasted images (Ctrl+V anywhere in the box), dropped files, or chosen
// files. Each image waits in a pending list with a caption; "Save images"
// posts them, in order, in one request (one new evidence version).
"use strict";
(function () {
  var csrf = (document.querySelector('meta[name="csrf"]') || {}).content || "";
  var MAX = 20;
  function toImage(blob) {  // PNG and JPEG as they are; anything else redrawn as PNG
    if (blob.type === "image/png" || blob.type === "image/jpeg") return Promise.resolve(blob);
    return new Promise(function (resolve, reject) {
      var im = new Image();
      im.onload = function () {
        var c = document.createElement("canvas"); c.width = im.naturalWidth; c.height = im.naturalHeight;
        c.getContext("2d").drawImage(im, 0, 0); c.toBlob(resolve, "image/png");
      };
      im.onerror = reject; im.src = URL.createObjectURL(blob);
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".capture[data-url]").forEach(function (box) {
      var drop = box.querySelector(".drop"), file = box.querySelector("input[type=file]");
      var preview = box.querySelector(".preview"), list = box.querySelector(".pending");
      var msg = box.querySelector(".msg"), pending = [];
      function render() {
        list.innerHTML = "";
        pending.forEach(function (p, i) {
          var fig = document.createElement("figure"); fig.className = "pending-shot";
          var n = document.createElement("div"); n.className = "muted"; n.textContent = "Image " + (i + 1);
          var img = document.createElement("img"); img.src = p.url; img.className = "shot";
          var cap = document.createElement("input"); cap.type = "text"; cap.size = 50;
          cap.placeholder = "Caption (for example: the query or the screen)";
          cap.value = p.caption; cap.addEventListener("input", function () { p.caption = cap.value; });
          var rm = document.createElement("button"); rm.type = "button"; rm.textContent = "Remove";
          rm.addEventListener("click", function () { pending.splice(i, 1); render(); });
          fig.append(n, img, cap, rm); list.appendChild(fig);
        });
        preview.hidden = pending.length === 0;
      }
      function add(blobs) {
        blobs = Array.prototype.filter.call(blobs, function (b) { return b && b.type.indexOf("image/") === 0; });
        if (!blobs.length) { msg.textContent = "No image found."; return; }
        Promise.all(blobs.map(toImage)).then(function (imgs) {
          imgs.forEach(function (b) {
            if (pending.length >= MAX) { msg.textContent = "At most " + MAX + " images at a time."; return; }
            pending.push({blob: b, url: URL.createObjectURL(b), caption: ""});
          });
          render(); drop.focus();
        });
      }
      box.addEventListener("paste", function (ev) {
        var items = (ev.clipboardData || {}).items || [], found = [];
        for (var i = 0; i < items.length; i++) { if (items[i].type.indexOf("image/") === 0) found.push(items[i].getAsFile()); }
        if (found.length) { ev.preventDefault(); add(found); return; }
        if (ev.target.tagName !== "INPUT" && ev.target.tagName !== "TEXTAREA") msg.textContent = "The clipboard holds no image.";
      });
      drop.addEventListener("dragover", function (ev) { ev.preventDefault(); drop.classList.add("over"); });
      drop.addEventListener("dragleave", function () { drop.classList.remove("over"); });
      drop.addEventListener("drop", function (ev) { ev.preventDefault(); drop.classList.remove("over"); add(ev.dataTransfer.files); });
      box.querySelector(".pick").addEventListener("click", function (ev) { ev.preventDefault(); file.click(); });
      file.addEventListener("change", function () { add(file.files); file.value = ""; });
      box.querySelector(".cancel").addEventListener("click", function () {
        if (pending.length && !confirm("Discard " + pending.length + " image(s)?")) return;
        pending = []; render();
      });
      box.querySelector(".save").addEventListener("click", function () {
        if (!pending.length) return;
        var fd = new FormData();
        fd.append("csrf", csrf);
        pending.forEach(function (p, i) {
          fd.append("image", p.blob, "shot-" + (i + 1) + (p.blob.type === "image/jpeg" ? ".jpg" : ".png"));
          fd.append("caption", p.caption);
        });
        msg.textContent = "Saving...";
        fetch(box.dataset.url, {method: "POST", body: fd, credentials: "same-origin"})
          .then(function (r) { return r.json().catch(function () { return {error: "HTTP " + r.status}; }).then(function (j) { return [r.ok, j]; }); })
          .then(function (res) {
            if (res[0]) { pending = []; location.reload(); }
            else { msg.textContent = res[1].error || "Saving failed."; }
          })
          .catch(function (e) { msg.textContent = "Saving failed: " + e; });
      });
    });
  });
})();
