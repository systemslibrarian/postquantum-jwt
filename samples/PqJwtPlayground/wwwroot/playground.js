// PqJwtPlayground — tiny client helpers: clipboard copy + light/dark theme.
// No framework, no interop required; the theme button is wired by id so the
// layout can stay statically rendered.
// To God be the glory — 1 Corinthians 10:31.
(function () {
    "use strict";
    var KEY = "pqjwt-theme";

    function current() {
        return document.documentElement.getAttribute("data-theme") ||
            (function () { try { return localStorage.getItem(KEY); } catch (e) { return null; } })() ||
            "dark";
    }

    function apply(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        var btn = document.getElementById("theme-toggle");
        if (btn) {
            var dark = theme !== "light";
            btn.textContent = dark ? "☀" : "☾"; // ☀ / ☾
            var label = dark ? "Switch to light theme" : "Switch to dark theme";
            btn.setAttribute("aria-label", label);
            btn.title = label;
        }
    }

    function wire() {
        apply(current());
        var btn = document.getElementById("theme-toggle");
        if (btn && !btn.dataset.wired) {
            btn.dataset.wired = "1";
            btn.addEventListener("click", function () {
                var next = current() === "light" ? "dark" : "light";
                try { localStorage.setItem(KEY, next); } catch (e) { /* private mode */ }
                apply(next);
            });
        }
    }

    // Copy arbitrary text; falls back to a hidden textarea where clipboard API is blocked.
    window.pqCopy = async function (text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (e) {
            try {
                var ta = document.createElement("textarea");
                ta.value = text;
                ta.style.position = "fixed";
                ta.style.opacity = "0";
                document.body.appendChild(ta);
                ta.select();
                var ok = document.execCommand("copy");
                document.body.removeChild(ta);
                return ok;
            } catch (e2) {
                return false;
            }
        }
    };

    document.addEventListener("DOMContentLoaded", wire);
    // Blazor enhanced navigation re-runs page content; re-wire to be safe.
    document.addEventListener("enhancedload", wire);
})();
