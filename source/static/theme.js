(function () {
    if (window.__themeInit) return; window.__themeInit = true;
    var KEY = "ip-theme", root = document.documentElement, t = "dark";
    try { t = localStorage.getItem(KEY) || "dark"; } catch (e) {}
    root.setAttribute("data-theme", t);
    window.setTheme = function (v) {
        root.setAttribute("data-theme", v);
        try { localStorage.setItem(KEY, v); } catch (e) {}
        window.dispatchEvent(new CustomEvent("themechange", { detail: v }));
    };
    document.addEventListener("click", function (e) {
        if (e.target.closest("#themeToggle")) window.setTheme(root.getAttribute("data-theme") === "light" ? "dark" : "light");
    });
})();
