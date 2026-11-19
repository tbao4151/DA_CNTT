/**
 * Network-free Chromium regression of local STOP-file user authorization.
 * Uses mock File System Access API: no physical VMware, shell or filesystem writes.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { chromium } from "playwright-core";

const url = "http://127.0.0.1:3000/vmware-progress";
const executablePath = [
  process.env.CHROME_BIN, "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable", "/usr/bin/chromium",
].find((path) => path && existsSync(path));
if (!executablePath) throw new Error("Chrome/Chromium required");

for (let i = 0; i < 80; i += 1) {
  try {
    if ((await fetch(url, { signal: AbortSignal.timeout(1500) })).ok) break;
  } catch { /* waiting for local Next.js */ }
  if (i === 79) throw new Error("Local Next.js production server not ready");
  await new Promise((resolve) => setTimeout(resolve, 400));
}

const sample = {
  kind: "da005_vmware_stepwise_progress_v1", seq: 1,
  observed_at_utc: "2026-11-19T09:00:00+00:00",
  stage: "preflight", status: "completed",
  mode: "operator_assisted_benign_hostonly_experiment",
  stage_evidence: "program_execution_only_not_independently_verified",
  vmware_isolation_verified: false, attack_executed: false,
  ai_attack_planning_executed: false, operational_ai_detection_verified: false,
  soc_alerts_created: false,
};
const payload = JSON.stringify(sample) + "\n";
const browser = await chromium.launch({
  executablePath, headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage({ viewport: { width: 1320, height: 900 } });
  const errors = [], mutations = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => {
    if (["POST", "PUT", "PATCH", "DELETE"].includes(r.method())) mutations.push(r.url());
  });
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Quy trình kiểm thử từng giai đoạn" }).waitFor();
  const stop = page.getByRole("button", { name: "Yêu cầu STOP qua tệp" });
  assert.equal(await stop.isDisabled(), true, "No STOP before reading an active file");

  await page.evaluate((jsonl) => {
    let filesWritten = 0, markerCreated = false, useWrongDirectory = true, lastMarkerName = "";
    let currentText = jsonl;
    const watched = {
      getFile: async () => new File([currentText], "phase-001.jsonl", {
        type: "application/x-ndjson", lastModified: 100,
      }),
    };
    const directory = {
      name: "captures",
      getFileHandle: async (name, options = {}) => {
        if (name === "phase-001.jsonl") {
          return { isSameEntry: async (other) => !useWrongDirectory && other === watched };
        }
        if (name !== "DA005_STOP.flag") throw new Error("Unexpected filename");
        lastMarkerName = name;
        if (!options.create && !markerCreated) {
          throw Object.assign(new Error("No such file"), { name: "NotFoundError" });
        }
        if (options.create) markerCreated = true;
        return {
          createWritable: async () => ({
            write: async (bytes) => {
              assertBrowser(typeof bytes === "string" && bytes === "");
              filesWritten += 1;
            },
            close: async () => {},
          }),
        };
      },
    };
    function assertBrowser(ok) {
      if (!ok) throw new Error("Unexpected stop marker content");
    }
    window.__da005StopTest = {
      wrong: (flag) => { useWrongDirectory = flag; },
      counts: () => ({ filesWritten, markerCreated, lastMarkerName }),
    };
    window.showOpenFilePicker = async () => [watched];
    window.showDirectoryPicker = async () => directory;
  }, payload);

  await page.getByRole("button", { name: "Theo dõi tệp đang ghi" }).click();
  await page.getByRole("button", { name: "Đang theo dõi tệp" }).waitFor();
  await page.locator('section[aria-labelledby="vmware-events"]').getByText(/1 sự kiện/).waitFor();
  assert.equal(await stop.isEnabled(), true);

  await stop.click();
  await page.getByRole("alert").filter({ hasText: "không chứa chính tệp JSONL" }).waitFor();
  assert.deepEqual(await page.evaluate(() => window.__da005StopTest.counts()),
    { filesWritten: 0, markerCreated: false, lastMarkerName: "" });
  assert.equal(await page.getByRole("button", { name: "Xác nhận gửi STOP" }).count(), 0);

  await page.evaluate(() => window.__da005StopTest.wrong(false));
  await stop.click();
  await page.getByRole("group", { name: "Xác nhận yêu cầu STOP" }).waitFor();
  assert.deepEqual(await page.evaluate(() => window.__da005StopTest.counts()),
    { filesWritten: 0, markerCreated: false, lastMarkerName: "" },
    "Picking directory MUST NOT create STOP marker without second user click");

  await page.getByRole("button", { name: "Hủy yêu cầu STOP" }).click();
  assert.equal(await page.getByRole("group", { name: "Xác nhận yêu cầu STOP" }).count(), 0);
  assert.equal((await page.evaluate(() => window.__da005StopTest.counts())).filesWritten, 0);
  await stop.click();
  await page.getByRole("button", { name: "Xác nhận gửi STOP" }).click();
  await page.getByRole("status").filter({ hasText: "Đã tạo DA005_STOP.flag" }).waitFor();
  assert.deepEqual(await page.evaluate(() => window.__da005StopTest.counts()),
    { filesWritten: 1, markerCreated: true, lastMarkerName: "DA005_STOP.flag" });
  assert.equal(await stop.isDisabled(), true, "Duplicate STOP creation not offered");
  assert.deepEqual(mutations, [], "No network mutation for local stop");
  assert.deepEqual(errors, [], "Uncaught browser errors");

  await page.getByRole("button", { name: "Đóng phiên" }).click();
  assert.equal(await stop.isDisabled(), true);
  assert.equal(await page.getByRole("status").filter({ hasText: "DA005_STOP.flag" }).count(), 0);
  console.log("PASS: browser STOP marker requires watched JSONL, same-directory handle, explicit second click; never makes network mutations");
} finally {
  await browser.close();
}
