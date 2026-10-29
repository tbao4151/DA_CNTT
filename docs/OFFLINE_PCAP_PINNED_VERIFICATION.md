# DA005 — Xác minh độc lập báo cáo import PCAP → Zeek (offline)

Đây là bước **chỉ đọc** sau `scripts/import_offline_pcap.py` (PR #131). Không bắt gói tin, không chạy Zeek, không truy cập mạng, không tạo alert/case và không dùng model UNSW-NB15 để chấm Zeek. Chỉ kiểm tra tính nhất quán của **ba tệp riêng tư**: PCAP gốc, `conn.log` do Zeek tạo và `offline_import_report.json`.

## Quy trình thực tế

1. Nhóm xác nhận quyền sử dụng PCAP, kiểm tra mạng VMware Host-only bằng chứng độc lập và import offline trong Linux VM theo `docs/OFFLINE_PCAP_ZEEK_IMPORT.md`.
2. **Ngay khi import thành công**, ghi nhận SHA-256 của `offline_import_report.json` vào sổ thực nghiệm độc lập (không sao chép lại giá trị từ report khi xác minh). Ví dụ trên Linux: `sha256sum /home/student/da005-private/capture-001/zeek-run-001/offline_import_report.json`. Lưu giá trị và thời điểm ghi nhận bên ngoài repository.
3. Chạy trình xác minh từ repository đã cập nhật, dùng đường dẫn tuyệt đối bên ngoài Git:

```bash
python3 scripts/verify_offline_pcap_import.py \
  --report /home/student/da005-private/capture-001/zeek-run-001/offline_import_report.json \
  --expected-report-sha256 <SHA256_GHI_NHAN_DOC_LAP> \
  --pcap /home/student/da005-private/capture-001/input.pcap \
  --log /home/student/da005-private/capture-001/zeek-run-001/conn.log \
  --cidr 192.168.56.0/24
```

Thay CIDR bằng subnet Host-only **thực tế**, không mở rộng CIDR chỉ để ép qua kiểm tra. Có thể lặp lại `--cidr` (tối đa bốn RFC1918 IPv4 subnet). Trên Windows Python 3.12.9 có thể chạy cùng script với đường dẫn tuyệt đối Windows, nếu đã chuyển nguyên vẹn ba tệp sang thư mục riêng ngoài Git; **không** diễn giải việc chạy trên Windows là đã chạy Zeek hoặc kiểm tra VMware.

Verifier so sánh checksum báo cáo với pin độc lập, kiểm tra schema/safety flags, đọc và băm lại PCAP gốc (tối đa 64 MiB), kiểm tra magic classic PCAP, đọc và băm lại Zeek `conn.log` (tối đa 15 MiB), tính lại số flow và digest CIDR bằng parser Zeek hiện có. Từ chối tệp thiếu, sai checksum, sai phạm vi, report có khóa JSON trùng, các cờ tự nhận đã xác thực lab, hoặc đường dẫn nằm trong repository. Báo cáo và `conn.log` phải cùng thư mục output, các đường dẫn phải khác nhau. Không ghi đè bất kỳ tệp nào.

**Lưu ý khoa học:** Một checksum được ghi lại từ chính báo cáo đã bị thay đổi không có giá trị độc lập. Ngay cả khi verifier thành công, nó **không** chứng minh PCAP do VMware Host-only tạo ra, Zeek executable đáng tin cậy, Zeek đã chuyển đổi đúng về ngữ nghĩa, nhãn tấn công đúng, hay AI phát hiện được tấn công. Cần lưu bản gốc, ảnh adapter/routes, Zeek version, nhật ký kịch bản và biên bản gán nhãn riêng. Không đẩy các tệp riêng tư lên GitHub.

## Kiểm thử tự động

```bash
python3 -m pytest -q tests/test_offline_pcap_verify.py
```

Fixture PCAP và Zeek tổng hợp; Zeek import trong fixture dùng **mock subprocess**, không chạy Zeek thật. Kết quả GitHub CI chỉ chứng minh đường đi kiểm tra checksum/schema/scope và điều kiện từ chối trên runner, không thay thế nghiệm thu laptop/VMware.


## Optional strict classic-PCAP record framing (30/10/2026)

For a stronger **structural** check, append `--require-pcap-framing` to
`scripts/verify_offline_pcap_import.py`. This opt-in mode re-reads the same
bounded, SHA-256-pinned PCAP bytes and validates classic-PCAP v2.4 global
header, four byte-order/timestamp-resolution magic variants, nonzero
snapshot length, packet-record headers, timestamp fractions, captured
versus original/snapshot lengths, and exact record boundaries. At least
one nonempty packet record is required. A successful run reports the
number of framed records; without the flag the CLI explicitly states
that packet framing was **not** checked. Existing import/verification
calls remain backward compatible.

Example (append to the existing private command):

```bash
  --require-pcap-framing
```

This does **not** decode Ethernet/IP/TCP, compare individual PCAP packets
to Zeek flows, validate Zeek's semantic correctness, or establish
capture authenticity, isolation, authorization, independent attack labels,
AI alerts or live detection latency. A valid packet count is not expected
to equal Zeek flow count. The existing offline importer still accepts
header-only synthetic test fixtures; the stricter check is a separate
opt-in research acceptance gate, not a retrospective claim about old data.

Synthetic regression: `python -m pytest -q tests/test_pcap_structure.py tests/test_offline_pcap_verify.py`.
Student acceptance requires a genuine privately stored classic PCAP
from an authorized Host-only lab, separately pinned original SHA-256,
a Zeek `conn.log` and the import report. Do not publish private captures.
