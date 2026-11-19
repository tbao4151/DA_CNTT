# DA005 — VMware Local Progress Viewer

Route: http://127.0.0.1:3000/vmware-progress (Next.js frontend).

This is a separate local-file reader for operator-assisted VMware stage JSONL. The file is read in the browser and not sent to FastAPI. The viewer has no attack or SSH execution endpoint. It is strictly separate from the synthetic SSE Automated Lab page.

## Create JSONL locally

The CLI --progress-jsonl option belongs to PR #405 and must be integrated first. Use **PowerShell 7+** (pwsh) for a UTF-8 JSONL pipeline; old Windows PowerShell may encode pipeline output as UTF-16, which is not JSONL UTF-8.

Example DRY-RUN from the project root (IP addresses below are historic examples; first check actual adapter and guest addresses):

    New-Item -ItemType Directory -Force E:\DA005_Private\captures | Out-Null
    py -3.12 -u scripts/run_vmware_stepwise.py --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario connection_shift --user YOUR_UBUNTU_USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir 'E:\DA005_Private\captures' --progress-jsonl | Tee-Object -FilePath 'E:\DA005_Private\captures\vmware-stage-progress.jsonl' -Encoding utf8

Dry-run sends NO packets and performs NO SSH. It should only show preflight/dry_run followed by a dry_run terminal status.

For the **bounded, benign** real lab test, only after verifying VMware Host-only isolation, Windows and Ubuntu adapters/routes, Zeek capture interface, pinned SSH host key and private evidence directory, add --execute --operator-confirmed-hostonly to this CLI. Never do so on an Internet-exposed network. Without a separately SHA-pinned Zeek v1 model, Blue remains skipped. Candidate research scores are not verified attacks.

## Browser viewing

Start the Next.js frontend on the local machine and open /vmware-progress.

- Click Mở tệp JSONL to import a saved file once.
- On Chrome or Edge at localhost, click Theo dõi tệp đang ghi and select the private JSONL being written by PowerShell. The browser requests explicit file read permission and checks it every 1.5 seconds. It shows only complete records.
- Click Đóng phiên to clear the view and stop watching.

The viewer never opens raw PCAP, conn.log or private model files. Every event must have the exact JSONL kind/mode, a monotonic sequence, allowed stage/status, a bounded aggregate count and explicit false flags for isolation, AI attack execution, verified detection and SOC alert creation. A forged, out-of-order or malformed complete record invalidates the whole session. A final incomplete line is ignored until completed. Input is capped at 1 MiB.

This screen verifies JSON structure, NOT VM Host-only isolation, Zeek capture provenance, packet-to-flow causality, model accuracy, verified attacks, precision/recall/F1, SOC live alerts, or complete autonomous dual-AI One-Click. Maintain the original evidence privately and separately use scripts/verify_vmware_snapshot_bundle.py to cross-check the Zeek capture receipts and model research reports.

## Bảng thông số tiến độ phần mềm

Trang VMware có một thanh tiến độ 0–6 giai đoạn, chỉ tính các giai đoạn đã có kết quả từ JSONL (completed, skipped, dry_run). Bốn thông số tổng hợp được suy ra duy nhất từ bản ghi đã qua bộ kiểm tra cấu trúc: lượt thử Red lành tính, flow Zeek trong snapshot, ứng viên nghiên cứu Blue và số UID khớp ứng viên ở bước audit.

Số liệu chưa có sự kiện được thể hiện bằng dấu “—”; Blue bị bỏ qua được ghi “Không chạy” thay vì đánh đồng với 0 ca phát hiện. Khi một tệp JSONL bị từ chối, bảng số liệu và thanh tiến độ được xóa theo sự kiện, không giữ giá trị của phiên cũ. Đây KHÔNG phải số vụ tấn công, xác nhận dương tính, mô hình detection live, độ trễ cảnh báo hay SOC thật. Việc cập nhật theo tệp đòi quyền File System Access trên localhost và không tự chạy máy ảo.

## CI

The new workflow .github/workflows/vmware-viewer-browser.yml runs typecheck, lint, production build, and real Chromium smoke using synthetic local JSONL. It checks stage changes, forged provenance rejection, partially written lines, and absence of POST/PUT file uploads. Tests are network-free except serving the local frontend.
