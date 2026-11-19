# DA005 — Audit độc lập bộ bằng chứng Zeek VMware (chỉ đọc)

Công cụ `scripts/verify_vmware_snapshot_bundle.py` đối chiếu lại byte gốc của `conn.log`, SHA-256, số flow, giới hạn thời gian và mạng CIDR với receipt từ `fetch_zeek_hostonly.py`. Nếu có file `.research.json`, nó kiểm tra từng UID, thời gian, IP/port, xác suất và nhãn *research candidate* so với chính log gốc.

**Không cần kết nối VMware để chạy audit**; công cụ không phát gói tin, không gọi SSH, không dùng mô hình AI, không tạo cảnh báo SOC. Chỉ dùng tệp tư liệu cá nhân của chính nhóm trong thư mục ngoài repository.

Từ PowerShell, tại thư mục gốc dự án:

```powershell
py -3.12 scripts/verify_vmware_snapshot_bundle.py --receipt "E:\DA005_Private\captures\zeek_conn_YYYYMMDDTHHMMSSZ_aaaaaaaaaaaa.receipt.json"
```

Nếu đã chạy chấm điểm Blue Team với mô hình Zeek v1 được chốt SHA-256:

```powershell
py -3.12 scripts/verify_vmware_snapshot_bundle.py --receipt "E:\DA005_Private\captures\zeek_conn_YYYYMMDDTHHMMSSZ_aaaaaaaaaaaa.receipt.json" --research-report "E:\DA005_Private\captures\zeek_conn_YYYYMMDDTHHMMSSZ_aaaaaaaaaaaa.research.json"
```

Có thể bổ sung `--expected-receipt-sha256` và `--expected-research-sha256` nếu đã ghi nhận các mã băm từ nguồn độc lập trước lúc kiểm tra. Thay tên file mẫu bằng tên thật do công cụ SCP tạo. Không đổi tên file để làm khớp.

Kết quả trả JSON không công bố đường dẫn, IP, UID, hay dự đoán theo từng flow. Nếu bất kỳ kiểm tra nào không đạt, lệnh trả mã thoát 1 và không tạo báo cáo có thể gây hiểu lầm.

**Giới hạn học thuật:** tự khớp hash không chứng minh rằng tệp được thu từ máy ảo thật; nằm trong CIDR không chứng minh cấu hình Host-only; một *research candidate* không phải tấn công được xác thực; không có Precision/Recall/F1 nếu chưa có ground truth và tập kiểm thử độc lập. Không mô tả audit này là One-Click dual-AI, kiểm thử tấn công thật hoặc phát hiện theo thời gian thực.

Kiểm thử hồi quy không cần mạng:

```powershell
py -3.12 -m pytest -q tests/test_vmware_snapshot_bundle_audit.py
```
