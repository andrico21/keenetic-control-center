// kcc Web UI behaviour. Loaded with `defer` after htmx; no inline script exists anywhere
// (CSP script-src 'self'), and nothing here evaluates strings as code.
(() => {
  "use strict";

  const root = document.documentElement;
  const YEAR_SECONDS = 31536000;
  const THEMES = ["system", "light", "dark"];

  // htmx's settle step copies old `style` attributes onto swapped elements with
  // setAttribute, which the CSP (style-src 'self') blocks; styles live in app.css only.
  if (window.htmx) {
    window.htmx.config.attributesToSettle = ["class", "width", "height"];
  }

  document.addEventListener("htmx:configRequest", (event) => {
    if (event.detail?.verb === "get") {
      return;
    }
    const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
    if (token) {
      event.detail.headers["X-CSRF-Token"] = token;
    }
  });

  // A form answered with 422 carries its field errors: swap it like a success.
  document.addEventListener("htmx:beforeSwap", (event) => {
    if (event.detail?.xhr?.status === 422) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });

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
    document.dispatchEvent(new CustomEvent("kcc:theme"));
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

  // Traffic chart. The dashboard stream, and the stream of an interface drawer on the
  // network pages, send `traffic` events with uPlot columns (unix seconds, received and
  // sent bits per second) and the newest rates as text; htmx must not swap them, so this
  // handler takes the data and cancels the swap. The browser only listens to kcc and never
  // contacts a router. A drawer arrives after the page loaded, so charts mount as htmx
  // loads them, and a chart that left the page stops listening.
  const mountTraffic = (chartBox) => {
    if (chartBox.dataset.kccChart || typeof uPlot !== "function") {
      return;
    }
    chartBox.dataset.kccChart = "mounted";
    const WINDOW_SECONDS = 1800;
    const GAP_SECONDS = 45;
    const HEIGHT = 224;
    const columns = [[], [], []];
    const lang = root.getAttribute("lang") || "en";
    const units = JSON.parse(chartBox.dataset.units || "[]");
    const decimal = new Intl.NumberFormat(lang, { maximumFractionDigits: 1 });
    const clock = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit" });
    const rate = (bits) => {
      let value = bits;
      let unit = 0;
      while (value >= 1000 && unit < units.length - 1) {
        value /= 1000;
        unit += 1;
      }
      return (units[unit] || "{}").replace("{}", decimal.format(value));
    };
    const ink = (selector) => {
      const element = document.querySelector(selector);
      return element ? getComputedStyle(element).color : "currentColor";
    };
    const faint = (color) => {
      const [red, green, blue] = color.match(/\d+(\.\d+)?/g) || ["0", "0", "0"];
      return `rgba(${red}, ${green}, ${blue}, 0.25)`;
    };
    const seconds = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    let chart = null;
    const build = () => {
      chart?.destroy();
      chart = null;
      if (columns[0].length === 0) {
        return;
      }
      const axisInk = getComputedStyle(chartBox).color;
      const axis = {
        stroke: axisInk,
        grid: { stroke: faint(axisInk), width: 1 },
        ticks: { stroke: faint(axisInk), width: 1 },
      };
      chart = new uPlot(
        {
          width: chartBox.clientWidth,
          height: HEIGHT,
          legend: { show: false },
          cursor: { drag: { x: false, y: false } },
          scales: { y: { range: (_plot, _min, max) => [0, Math.max(max, 1000)] } },
          axes: [
            {
              ...axis,
              space: 72,
              incrs: [15, 30, 60, 120, 300, 600, 900, 1800],
              values: (_plot, ticks, _axis, _space, step) =>
                ticks.map((tick) => (step < 60 ? seconds : clock).format(new Date(tick * 1000))),
            },
            { ...axis, size: 88, values: (_plot, ticks) => ticks.map(rate) },
          ],
          series: [
            {},
            { stroke: ink('.traffic__swatch[data-series="rx"]'), width: 2 },
            { stroke: ink('.traffic__swatch[data-series="tx"]'), width: 2, dash: [6, 4] },
          ],
        },
        columns,
        chartBox,
      );
    };
    const show = (payload) => {
      if (payload.replace) {
        for (const column of columns) {
          column.length = 0;
        }
      }
      payload.t.forEach((at, index) => {
        const last = columns[0][columns[0].length - 1];
        if (last === undefined || at > last) {
          if (last !== undefined && at - last > GAP_SECONDS) {
            columns[0].push(last + 1);
            columns[1].push(null);
            columns[2].push(null);
          }
          columns[0].push(at);
          columns[1].push(payload.rx[index]);
          columns[2].push(payload.tx[index]);
        }
      });
      const newest = columns[0][columns[0].length - 1];
      while (columns[0].length > 0 && columns[0][0] <= newest - WINDOW_SECONDS) {
        for (const column of columns) {
          column.shift();
        }
      }
      for (const [series, text] of [["rx", payload.rx_text], ["tx", payload.tx_text]]) {
        const value = document.getElementById(`traffic-${series}`);
        if (value && typeof text === "string") {
          value.textContent = text;
        }
      }
      const empty = document.getElementById("traffic-empty");
      if (empty) {
        empty.hidden = columns[0].length > 0;
      }
      if (chart) {
        chart.setData(columns);
      } else {
        build();
      }
    };
    chartBox.addEventListener("htmx:sseBeforeMessage", (event) => {
      event.preventDefault();
      try {
        show(JSON.parse(event.detail.data));
      } catch {
        // A malformed event leaves the chart as it was.
      }
    });
    const listening = new AbortController();
    const resizing = new ResizeObserver(() => chart?.setSize({ width: chartBox.clientWidth, height: HEIGHT }));
    resizing.observe(chartBox);
    const rebuild = () => {
      if (chartBox.isConnected) {
        build();
        return;
      }
      listening.abort();
      resizing.disconnect();
      chart?.destroy();
      chart = null;
    };
    document.addEventListener("kcc:theme", rebuild, { signal: listening.signal });
    window
      .matchMedia("(prefers-color-scheme: dark)")
      .addEventListener("change", rebuild, { signal: listening.signal });
  };
  const initialChart = document.getElementById("traffic-chart");
  if (initialChart) {
    mountTraffic(initialChart);
  }
  window.htmx?.onLoad((element) => {
    const box = element.id === "traffic-chart" ? element : element.querySelector?.("#traffic-chart");
    if (box) {
      mountTraffic(box);
    }
  });
})();

// todo 44: admin pages. The Copy button beside a new API key, and <time data-kcc-time>
// shown in the reader's time zone and page language.
(() => {
  "use strict";

  document.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-kcc-copy]") : null;
    if (!button) {
      return;
    }
    const input = document.getElementById(button.getAttribute("data-kcc-copy") || "");
    if (!(input instanceof HTMLInputElement)) {
      return;
    }
    // Selected text stays copyable by hand when the clipboard is unavailable.
    input.select();
    navigator.clipboard?.writeText(input.value).then(
      () => {
        const note = document.getElementById(input.getAttribute("aria-describedby") || "");
        if (note) {
          note.hidden = false;
        }
      },
      () => {},
    );
  });

  const lang = document.documentElement.getAttribute("lang") || "en";
  const local = new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" });
  const localize = () => {
    for (const time of document.querySelectorAll("time[data-kcc-time]")) {
      const value = new Date(time.getAttribute("datetime") || "");
      if (!Number.isNaN(value.getTime())) {
        time.textContent = local.format(value);
        time.removeAttribute("data-kcc-time");
      }
    }
  };
  localize();
  document.addEventListener("htmx:afterSettle", localize);
})();

// todo 36: a table row's action menu opens above its button when it would leave the
// viewport at the bottom.
(() => {
  "use strict";

  document.addEventListener(
    "toggle",
    (event) => {
      const menu = event.target;
      if (!(menu instanceof HTMLElement) || !menu.classList.contains("lan-menu") || event.newState !== "open") {
        return;
      }
      const invoker = document.querySelector(`[popovertarget="${CSS.escape(menu.id)}"]`);
      const box = menu.getBoundingClientRect();
      if (!invoker || box.bottom <= window.innerHeight) {
        return;
      }
      const anchor = invoker.getBoundingClientRect();
      menu.style.insetBlockStart = `${Math.max(8, Math.round(anchor.top - box.height - 4))}px`;
    },
    true,
  );
})();

// todo 37: network pages. A dialog input's data-kcc-invalid holds the localized rule: the
// browser shows it instead of its own message when the input's constraints fail, so an
// invalid value is never sent. Typing clears it until the next check.
(() => {
  "use strict";

  document.addEventListener(
    "invalid",
    (event) => {
      const input = event.target;
      if (input instanceof HTMLInputElement && input.dataset.kccInvalid) {
        input.setCustomValidity(input.dataset.kccInvalid);
      }
    },
    true,
  );
  document.addEventListener("input", (event) => {
    const input = event.target;
    if (input instanceof HTMLInputElement && input.dataset.kccInvalid) {
      input.setCustomValidity("");
    }
  });
})();

// todo 39: an upload over its size limit is answered with 413 and the dialog showing the
// localized size error (HX-Retarget set by the server): swap it like a 422. A 413 without
// that header (no dialog to show) keeps htmx's default.
(() => {
  "use strict";

  document.addEventListener("htmx:beforeSwap", (event) => {
    const xhr = event.detail?.xhr;
    if (xhr?.status === 413 && xhr.getResponseHeader("HX-Retarget")) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });
})();
