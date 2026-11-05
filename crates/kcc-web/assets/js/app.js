// kcc Web UI behaviour. Loaded with `defer` after htmx; no inline script exists anywhere
// (CSP script-src 'self'), and nothing here evaluates strings as code.
(() => {
  "use strict";

  const root = document.documentElement;
  const YEAR_SECONDS = 31536000;
  const THEMES = ["system", "light", "dark"];

  // Preference cookies: readable by the server on the next request, never sent cross-site.
  const writeCookie = (name, value, maxAge) => {
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${name}=${value}; Path=/; Max-Age=${maxAge}; SameSite=Strict${secure}`;
  };

  // Theme: "system" follows prefers-color-scheme; "light" and "dark" override it.
  const applyTheme = (theme) => {
    if (!THEMES.includes(theme)) {
      return;
    }
    root.classList.remove("theme-light", "theme-dark");
    if (theme === "system") {
      writeCookie("kcc_theme", "", 0);
    } else {
      root.classList.add(`theme-${theme}`);
      writeCookie("kcc_theme", theme, YEAR_SECONDS);
    }
    const scheme = document.querySelector('meta[name="color-scheme"]');
    if (scheme) {
      scheme.setAttribute("content", theme === "system" ? "light dark" : theme);
    }
    for (const item of document.querySelectorAll("[data-kcc-theme]")) {
      if (item.getAttribute("data-kcc-theme") === theme) {
        item.setAttribute("aria-current", "true");
      } else {
        item.removeAttribute("aria-current");
      }
    }
  };

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) {
      return;
    }
    const theme = target.closest("[data-kcc-theme]");
    if (theme) {
      applyTheme(theme.getAttribute("data-kcc-theme"));
      theme.closest("[popover]")?.hidePopover();
      return;
    }
    const locale = target.closest("[data-kcc-locale]");
    if (locale) {
      const tag = locale.getAttribute("data-kcc-locale");
      if (tag && /^[a-z]{2}$/.test(tag)) {
        writeCookie("kcc_lang", tag, YEAR_SECONDS);
        window.location.reload();
      }
      return;
    }
    const close = target.closest("[data-kcc-toast-close]");
    if (close) {
      close.closest(".toast")?.remove();
    }
  });

  // Header menus open under their button; without this they sit at the stylesheet's
  // top-right fallback position.
  document.addEventListener(
    "beforetoggle",
    (event) => {
      const menu = event.target;
      if (!(menu instanceof HTMLElement) || !menu.classList.contains("menu") || event.newState !== "open") {
        return;
      }
      const invoker = document.querySelector(`[popovertarget="${CSS.escape(menu.id)}"]`);
      if (!invoker) {
        return;
      }
      const rect = invoker.getBoundingClientRect();
      menu.style.insetBlockStart = `${Math.round(rect.bottom + 4)}px`;
      menu.style.insetInlineEnd = `${Math.max(8, Math.round(root.clientWidth - rect.right))}px`;
    },
    true,
  );

  // The navigation sheet becomes the permanent side column at wide widths.
  const wide = window.matchMedia("(min-width: 80rem)");
  wide.addEventListener("change", (event) => {
    const nav = document.getElementById("site-nav");
    if (event.matches && nav?.matches(":popover-open")) {
      nav.hidePopover();
    }
  });

  // Shared dialog: htmx loads content into #dialog-content, then the dialog opens modally.
  // A response header `HX-Trigger: kcc:dialog-close` closes it.
  const dialog = document.getElementById("dialog");
  const content = document.getElementById("dialog-content");
  if (dialog instanceof HTMLDialogElement && content) {
    document.addEventListener("htmx:afterSwap", (event) => {
      if (event.detail?.target !== content) {
        return;
      }
      if (content.querySelector("#dialog-title")) {
        dialog.setAttribute("aria-labelledby", "dialog-title");
      } else {
        dialog.removeAttribute("aria-labelledby");
      }
      if (!dialog.open) {
        dialog.showModal();
      }
    });
    dialog.addEventListener("close", () => {
      content.replaceChildren();
      dialog.removeAttribute("aria-labelledby");
    });
    document.addEventListener("kcc:dialog-close", () => {
      if (dialog.open) {
        dialog.close();
      }
    });
  }
})();
