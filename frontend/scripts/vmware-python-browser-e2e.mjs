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

  // Genuine Python profile-v2 UCB1 planning decision, *not* a hand-written
  // JavaScript mock. Python emits the planning receipt + dry-run JSONL from
  // pinned private configuration and explicitly forbids all networking.
  const ucb1Progress = load("python_ucb1.jsonl");
  const ucb1Receipt = load("python_ucb1.red-plan.json");
  await open("python_ucb1.jsonl", ucb1Progress);
  await page.getByText("Dry-run", { exact: true }).first().waitFor();
  const redInput = page.getByLabel("Mở biên nhận Red Team");
  const redPanel = page.locator('section[aria-labelledby="vmware-red-policy"]');
  await redInput.setInputFiles({
    name: "python_ucb1.red-plan.json", mimeType: "application/json", buffer: ucb1Receipt,
  });
  await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).waitFor();
  const text = await redPanel.innerText();
  assert.match(text, /UCB1/);
  assert.match(text, /Số phản hồi nhập tay:\s*3/);
  assert.match(text, /SHA-256 profile tự khai/);
  assert.match(text, /không xác nhận nó đã được thực thi/);
  assert.equal(unsafeRequests.length, 0, "Python Red plan cannot be uploaded to API");

  // One picker can load both genuine Python artifacts without an extra
  // manual receipt selection. Invalid pairs must clear both panels atomically.
  const pairInput = page.getByLabel("Mở cặp JSONL và biên nhận Red");
  const validPair = [
    { name: "python_ucb1.jsonl", mimeType: "application/x-ndjson", buffer: ucb1Progress },
    { name: "python_ucb1.red-plan.json", mimeType: "application/json", buffer: ucb1Receipt },
  ];
  await pairInput.setInputFiles(validPair);
  await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).waitFor();
  await log.getByText(/1 sự kiện/).waitFor();
  assert.equal(unsafeRequests.length, 0, "Paired local import must make zero API writes");

  await pairInput.setInputFiles([
    validPair[0],
    { name: "other-session.red-plan.json", mimeType: "application/json", buffer: ucb1Receipt },
  ]);
  await page.getByRole("alert").filter({ hasText: "không khớp tên phiên" }).waitFor();
  assert.equal(await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).count(), 0);
  await log.getByText(/0 sự kiện/).waitFor();

  const invalidPairedPlan = JSON.parse(ucb1Receipt.toString("utf8"));
  invalidPairedPlan.attack_executed = true;
  await pairInput.setInputFiles([
    validPair[0],
    { name: "python_ucb1.red-plan.json", mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(invalidPairedPlan)) },
  ]);
  await page.getByRole("alert").filter({ hasText: "sai provenance" }).waitFor();
  await log.getByText(/0 sự kiện/).waitFor();
  assert.equal(await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).count(), 0);

  await pairInput.setInputFiles(validPair);
  await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).waitFor();

  const forgedPlan = JSON.parse(ucb1Receipt.toString("utf8"));
  forgedPlan.attack_executed = true;
  await redInput.setInputFiles({
    name: "python_ucb1.red-plan.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(forgedPlan)),
  });
  await redPanel.getByRole("alert").filter({ hasText: "sai provenance" }).waitFor();
  assert.equal(await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).count(), 0);

  await redInput.setInputFiles({
    name: "python_ucb1.red-plan.json", mimeType: "application/json", buffer: ucb1Receipt,
  });
  await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).waitFor();

  const completed = load("python_mock_completed.jsonl");
  assert.equal(completed.toString("utf8").split("\n").filter(Boolean).length, 10);
  await open("python_mock_completed.jsonl", completed);
  await page.getByText("Phần mềm kết thúc", { exact: true }).first().waitFor();
  assert.equal(await redPanel.getByText("DNS .invalid (UDP/53)", { exact: true }).count(), 0,
    "Changing JSONL sessions must remove the previous Python UCB1 selection");
  await log.getByText(/9 sự kiện/).waitFor();
  assert.equal(await log.locator("li").count(), 9);
  assert.match(await log.innerText(), /Red · Lưu lượng lành tính/);
  assert.match(await log.innerText(), /Zeek · Thu thập snapshot/);
  assert.match(await log.innerText(), /Blue · Chấm điểm nghiên cứu/);
  assert.match(await log.innerText(), /SOC · Không tự động tạo cảnh báo/);
  assert.match(await page.locator("body").innerText(), /CHƯA XÁC MINH LIVE AI/);
  assert.match(await page.locator("body").innerText(), /Chỉ xem tiến độ cục bộ/);
  assert.equal(unsafeRequests.length, 0, "No evidence bytes may be uploaded to API");

  // Internal proof of consistency: a syntactically valid terminal is
  // rejected if it reports a different packet count than the Red event.
  const contradictory = completed.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  contradictory[contradictory.length - 1].result.network_attempts = 3;
  await open("contradictory.jsonl", Buffer.from(contradictory.map((row) => JSON.stringify(row)).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "không khớp bộ đếm giai đoạn" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  // The strict timeline rejects records whose stage sequence is valid
  // but whose timestamps move backwards. No live VM clock is implied.
  const reverseTime = completed.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  reverseTime[3].observed_at_utc = "2001-01-01T00:00:00+00:00";
  await open("reverse-time.jsonl", Buffer.from(reverseTime.map(JSON.stringify).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "Thời gian UTC của sự kiện đi ngược" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  const microsecondBacktrack = completed.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  microsecondBacktrack[0].observed_at_utc = "2026-11-19T09:00:00.123456+00:00";
  microsecondBacktrack[1].observed_at_utc = "2026-11-19T09:00:00.123455+00:00";
  await open("microsecond-reverse.jsonl", Buffer.from(microsecondBacktrack.map(JSON.stringify).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "Thời gian UTC của sự kiện đi ngược" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  const invalidCalendar = completed.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  invalidCalendar[0].observed_at_utc = "2026-02-30T05:00:00.000001+00:00";
  await open("invalid-calendar.jsonl", Buffer.from(invalidCalendar.map(JSON.stringify).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "Thứ tự hoặc provenance" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  const noncanonicalTime = completed.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  noncanonicalTime[1].observed_at_utc = "2026-11-19 05:00:00+00:00";
  await open("noncanonical-time.jsonl", Buffer.from(noncanonicalTime.map(JSON.stringify).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "Thứ tự hoặc provenance" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  // A previously successful real-CLI shape must not allow a forged
  // vmware_isolation_verified flag to be treated as physical proof.
  const forged = completed.toString("utf8").split("\n").filter(Boolean).map(JSON.parse);
  forged[2].vmware_isolation_verified = true;
  await open("forged-live.jsonl", Buffer.from(forged.map(JSON.stringify).join("\n") + "\n"));
  await page.getByRole("alert").filter({ hasText: "Từ chối sự kiện tuyên bố" }).waitFor();
  assert.match(await log.innerText(), /0 sự kiện/);

  // Validate actual real-time UI polling without granting any filesystem
  // path to the CI browser: fake FileSystemAccess only; Python bytes are real.
  // The UI must clear stale "completed" status when a later update is invalid.
  await page.evaluate((startingText) => {
    let contents = startingText;
    let version = 1;
    window.__da005UpdateMockJsonl = (nextText) => {
      contents = nextText;
      version += 1;
    };
    Object.defineProperty(window, "showOpenFilePicker", {
      configurable: true,
      value: async () => [{
        getFile: async () => new File([contents], "mock-follow.jsonl", {
          type: "application/x-ndjson", lastModified: version,
        }),
      }],
    });
  }, dry.toString("utf8"));
  await page.getByRole("button", { name: "Theo dõi tệp đang ghi" }).click();
  await page.getByRole("button", { name: "Đang theo dõi tệp" }).waitFor();
  await page.getByText("Dry-run", { exact: true }).first().waitFor({ timeout: 9000 });
  await page.evaluate((data) => window.__da005UpdateMockJsonl(data), completed.toString("utf8"));
  await page.getByText("Phần mềm kết thúc", { exact: true }).first().waitFor({ timeout: 9000 });
  await log.getByText(/9 sự kiện/).waitFor({ timeout: 9000 });
  const corruptFollow = completed.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  corruptFollow[1].vmware_isolation_verified = true;
  await page.evaluate((data) => window.__da005UpdateMockJsonl(data),
    corruptFollow.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  await page.getByRole("alert").filter({ hasText: "Đã xóa toàn bộ tiến độ cũ" }).waitFor({ timeout: 9000 });
  await log.getByText(/0 sự kiện/).waitFor();
  assert.equal(await page.getByRole("button", { name: "Theo dõi tệp đang ghi" }).count(), 1);
  assert.equal(unsafeRequests.length, 0);

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
