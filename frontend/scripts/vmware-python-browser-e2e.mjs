/**
 * Cross-stack acceptance: original Python CLI/writer -> UTF-8 file -> Chromium.
 * The "completed" trace is a NETWORK-FREE MOCK, NOT physical VMware evidence.
 * Both the dry-run and consent-refusal cases are actual Python CLI outcomes.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { chromium } from "playwright-core";

const dir = process.env.DA005_BROWSER_E2E_CASES;
if (!dir) throw new Error("Set DA005_BROWSER_E2E_CASES to private Python QA case folder");
const load = (filename) => {
  const path = resolve(dir, filename);
  if (!existsSync(path)) throw new Error("Missing real Python JSONL case: " + filename);
  return readFileSync(path);
};
const executablePath = [
  process.env.CHROME_BIN,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
].find((s) => s && existsSync(s));
if (!executablePath) throw new Error("Installed Chrome/Chromium is required");

const url = "http://127.0.0.1:3000/vmware-progress";
let ready = false;
for (let i = 0; i < 75; i += 1) {
  try {
    if ((await fetch(url, { signal: AbortSignal.timeout(1500) })).ok) {
      ready = true;
      break;
    }
  } catch { /* server not up yet */ }
  await new Promise((r) => setTimeout(r, 400));
}
if (!ready) throw new Error("Next.js production frontend did not start");

const browser = await chromium.launch({
  executablePath, headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage({ viewport: { width: 1300, height: 900 } });
  const pageErrors = [];
  const unsafeRequests = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("request", (request) => {
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method())) {
      unsafeRequests.push(request.url());
    }
  });
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Quy trình kiểm thử từng giai đoạn" }).waitFor();
  const input = page.getByLabel("Mở tệp JSONL VMware");
  const log = page.locator('section[aria-labelledby="vmware-events"]');
  const open = (name, buffer) => input.setInputFiles({
    name, mimeType: "application/x-ndjson", buffer,
  });

  const dry = load("python_dryrun.jsonl");
  assert.equal(dry.toString("utf8").split("\n").filter(Boolean).length, 2);
  await open("python_dryrun.jsonl", dry);
  await page.getByText("Dry-run", { exact: true }).first().waitFor();
  await log.getByText(/1 sự kiện/).waitFor();
  assert.equal(await log.locator("li").count(), 1);
  assert.match(await log.innerText(), /Preflight/);
  assert.doesNotMatch(await log.innerText(), /Red · Lưu lượng/);
  assert.doesNotMatch(await log.innerText(), /Zeek · Thu thập/);

  const completed = load("python_mock_completed.jsonl");
  assert.equal(completed.toString("utf8").split("\n").filter(Boolean).length, 10);
  await open("python_mock_completed.jsonl", completed);
  await page.getByText("Phần mềm kết thúc", { exact: true }).first().waitFor();
  await log.getByText(/9 sự kiện/).waitFor();
  assert.equal(await log.locator("li").count(), 9);
  assert.match(await log.innerText(), /Red · Lưu lượng lành tính/);
  assert.match(await log.innerText(), /Zeek · Thu thập snapshot/);
  assert.match(await log.innerText(), /Blue · Chấm điểm nghiên cứu/);
  assert.match(await log.innerText(), /SOC · Không tự động tạo cảnh báo/);
  assert.match(await page.locator("body").innerText(), /CHƯA XÁC MINH LIVE AI/);
  assert.match(await page.locator("body").innerText(), /Chỉ xem tiến độ cục bộ/);
  assert.equal(unsafeRequests.length, 0, "No evidence bytes may be uploaded to API");

  // A previously successful real-CLI shape must not allow a forged
  // vmware_isolation_verified flag to be treated as physical proof.
  const forged = completed.toString("utf8").split("\n").filter(Boolean).map(JSON.parse);
  forged[2].vmware_isolation_verified = true;
  await open("forged-live.jsonl", Buffer.from(forged.map(JSON.stringify).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "Từ chối sự kiện tuyên bố" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  const refused = load("python_no_consent.jsonl");
  await open("python_no_consent.jsonl", refused);
  await page.getByText("Đã từ chối / gặp lỗi", { exact: true }).first().waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);
  assert.equal(unsafeRequests.length, 0);
  assert.deepEqual(pageErrors, [], "No uncaught browser errors");
  console.log(
    "PASS Python CLI and private UTF-8 writer -> actual Chromium import: " +
    "dry-run, network-free mocked nine-phase sequence, refusal, provenance denial, no uploads"
  );
} finally {
  await browser.close();
}
