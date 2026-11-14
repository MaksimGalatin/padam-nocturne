(function () {
  "use strict";
  if (window.location.search.indexOf("stay=1") !== -1) return;
  var lang = null;
  try { lang = localStorage.getItem("padam-docs-lang"); } catch (e) {}
  if (!lang) {
    var nav = (navigator.language || "en").slice(0, 2).toLowerCase();
    lang = ["ru", "en", "es", "zh"].indexOf(nav) !== -1 ? nav : "en";
  }
  if (["ru", "en", "es", "zh"].indexOf(lang) !== -1) {
    window.location.replace("./" + lang + "/index.html");
  }
})();
