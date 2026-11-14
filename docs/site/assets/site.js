(function () {
  "use strict";
  var root = document.documentElement;
  var savedTheme = null;
  try {
    savedTheme = localStorage.getItem("padam-docs-theme");
  } catch (e) {}

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      var darkLabel = btn.getAttribute("data-dark-label") || "Dark";
      var lightLabel = btn.getAttribute("data-light-label") || "Light";
      btn.textContent = theme === "light" ? darkLabel : lightLabel;
      btn.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
    }
  }

  var initial = savedTheme || "dark";
  applyTheme(initial);

  var themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      try { localStorage.setItem("padam-docs-theme", next); } catch (e) {}
      applyTheme(next);
    });
  }

  var menuBtn = document.getElementById("menu-toggle");
  var sidebar = document.getElementById("docs-sidebar");
  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", function () {
      var open = sidebar.classList.toggle("open");
      menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  var langLinks = document.querySelectorAll("[data-set-lang]");
  for (var i = 0; i < langLinks.length; i++) {
    langLinks[i].addEventListener("click", function (ev) {
      var lang = ev.currentTarget.getAttribute("data-set-lang");
      try { localStorage.setItem("padam-docs-lang", lang); } catch (e) {}
    });
  }

  var blocks = document.querySelectorAll("pre");
  var copyLabel = root.getAttribute("data-copy-label") || "Copy";
  var copiedLabel = root.getAttribute("data-copied-label") || "Copied";
  for (var j = 0; j < blocks.length; j++) {
    (function (pre) {
      var code = pre.querySelector("code");
      if (!code) return;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = copyLabel;
      btn.addEventListener("click", function () {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(code.textContent || "").then(function () {
            btn.textContent = copiedLabel;
            setTimeout(function () { btn.textContent = copyLabel; }, 1400);
          });
        }
      });
      pre.appendChild(btn);
    })(blocks[j]);
  }

  var filterInput = document.getElementById("ref-filter");
  if (filterInput) {
    filterInput.addEventListener("input", function () {
      var q = filterInput.value.trim().toLowerCase();
      var rows = document.querySelectorAll("tbody tr");
      for (var k = 0; k < rows.length; k++) {
        var txt = (rows[k].textContent || "").toLowerCase();
        rows[k].hidden = Boolean(q && txt.indexOf(q) === -1);
      }
    });
  }
})();
