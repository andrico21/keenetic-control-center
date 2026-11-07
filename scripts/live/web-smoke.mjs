// Web UI smoke: login, dashboard, clients page, one interface-description write with
// read-back from a fresh page load, then the original restored and read back.
import { chromium } from "playwright";

const { BASE, ROUTER, INTERFACE, WEB_USER, WEB_PASSWORD, OUT } = process.env;
const PROBE = "kcc-live-51-web";
const csp = [];

function check(condition, message) {
  if (!condition) throw new Error(message);
}

// The serial number on the dashboard is masked: screenshots of a live router are evidence.
async function shot(page, name) {
  const serial = page.locator(".identity__item .mono");
  await page.screenshot({ path: `${OUT}-${name}.png`, fullPage: true, mask: [serial] });
  console.log(`screenshot ${OUT}-${name}.png`);
}

async function description(page) {
  const url = `${BASE}/ui/r/${ROUTER}/network/description?name=${encodeURIComponent(INTERFACE)}`;
  await page.evaluate((target) => window.htmx.ajax("GET", target, { target: "#dialog-content" }), url);
  const input = page.locator('#dialog[open] input[name="value"]');
  await input.waitFor();
  return input;
}

async function write(page, value) {
  const input = await description(page);
  const before = await input.inputValue();
  await input.fill(value);
  await page.click("#dialog[open] .dialog__actions button[type=submit]");
  await page.waitForSelector("#dialog[open]", { state: "detached" });
  await page.goto(`${BASE}/ui/r/${ROUTER}/network`);
  const fresh = await (await description(page)).inputValue();
  await page.keyboard.press("Escape");
  check(fresh === value, `read-back: expected "${value}", got "${fresh}"`);
  console.log(`description of ${INTERFACE} set and read back`);
  return before;
}

const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      console.error(`csp ${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  const page = await context.newPage();
  page.on("console", (message) => {
    if (message.type() === "error") csp.push(message.text());
  });
  page.on("pageerror", (error) => csp.push(error.message));

  await page.goto(`${BASE}/ui/login`);
  await page.fill("#login-username", WEB_USER);
  await page.fill("#login-password", WEB_PASSWORD);
  await Promise.all([page.waitForURL(`${BASE}/ui/`), page.click("main button[type=submit]")]);
  console.log("logged in");

  await page.goto(`${BASE}/ui/r/${ROUTER}`);
  await page.waitForLoadState("networkidle");
  await shot(page, "dashboard");

  await page.goto(`${BASE}/ui/r/${ROUTER}/clients`);
  await page.waitForLoadState("networkidle");
  await shot(page, "clients");

  await page.goto(`${BASE}/ui/r/${ROUTER}/network`);
  const original = await write(page, PROBE);
  await shot(page, "write-read-back");
  const probe = await write(page, original);
  check(probe === PROBE, `restore started from "${probe}", not the probe value`);
  await shot(page, "restored");

  check(csp.length === 0, `browser errors: ${csp.join("; ")}`);
  console.log("web smoke: pass");
} finally {
  await browser.close();
}
