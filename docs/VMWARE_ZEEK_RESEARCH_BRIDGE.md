# DA005 — Một lệnh lấy Zeek thật và suy luận offline có kiểm chứng

**Trạng thái:** Chuỗi tích hợp CLI cho ảnh chụp Zeek `conn.log` từ VMware. Không phải One-Click Red/Blue, không tạo cảnh báo/case vận hành, không tuyên bố đã kiểm thử máy thật.

## Điều kiện bắt buộc

1. Ubuntu Zeek trong VMware Host-only đã được kiểm tra cấu hình mạng và được phép hoạt động; xác nhận IP guest/subnet thực tế. Ví dụ trước đây 192.168.77.20 và 192.168.77.0/24 chỉ là cấu hình tham khảo.
2. Zeek đã tạo `conn.log` ASCII tại `/opt/zeek/logs/current/conn.log` hoặc `/usr/local/zeek/logs/current/conn.log` và tài khoản Ubuntu có quyền đọc.
3. Windows có `ssh`, `scp`, Python 3.12.9, thông tin `known_hosts` đối chiếu fingerprint trên **console của Ubuntu** (không lấy thẳng từ lần kết nối chưa xác minh) và SSH key không cần nhập mật khẩu.
4. Có mô hình **Zeek v1 research JSON của chính nhóm** nằm ngoài Git, SHA-256 đã ghi độc lập; không dùng `unsw_binary_rf.joblib` thay thế. Nếu chưa có model/manifest, chỉ kiểm thử lấy log bằng `scripts/fetch_zeek_hostonly.py` trước.
5. Có thư mục riêng bên ngoài repository, ví dụ `E:\DA005_Private\captures`; không commit log và model.

## Cách chạy khi có private model đã được kiểm chứng

Chạy PowerShell từ thư mục gốc repository đã checkout đúng nhánh:

```powershell
py -3.12 scripts/run_vmware_zeek_research.py --host 192.168.77.20 --cidr 192.168.77.0/24 --user YOUR_UBUNTU_USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir "E:\DA005_Private\captures" --model "E:\DA005_Private\models\zeek_research.json" --expected-model-sha256 YOUR_INDEPENDENT_SHA256
```

Nếu có manifest phân vùng TRAIN/VALIDATION/TEST đã ghi hash độc lập, thêm:

```powershell
--manifest "E:\DA005_Private\experiment_manifest.json" --expected-manifest-sha256 YOUR_INDEPENDENT_MANIFEST_SHA256
```

**Không tự thêm các cờ này nếu chưa có model/manifest thật.** Không tự sinh hoặc điền đại SHA-256; một model chưa được huấn luyện bằng dữ liệu phù hợp không tạo ra kết quả khoa học có giá trị.

## Kết quả

- `zeek_conn_*.log`: bản sao byte Zeek mới được lấy qua SCP.
- `zeek_conn_*.receipt.json`: biên nhận với SHA-256 nguồn, phạm vi IP và thời điểm lấy.
- `zeek_conn_*.research.json`: dự đoán nghiên cứu từ mô hình Zeek được ghim SHA-256, chỉ sinh nếu các kiểm tra đầu vào và model thành công.
- Chuỗi này KHÔNG xác nhận log thật sự sinh từ kịch bản Red Team, không xác thực ground truth hoặc hoạt động live, không tạo SOC case và không cung cấp độ chính xác/độ trễ mạng.

## Nghiệm thu kỹ thuật từng bước trên máy Windows

```powershell
py -3.12 -m pytest -q tests/test_fetch_zeek_hostonly.py tests/test_vmware_zeek_research_bridge.py tests/test_zeek_new_log_inference.py
```

Sau đó xác minh ảnh VMnet Host-only, route/SSH, phiên Zeek, `conn.log` nguyên bản, SHA-256 và file JSON. Chỉ khi đã có chứng cứ gốc mới kết nối vào điều phối One-Click. Nếu log thu được quá lớn, trống, có endpoint ngoài CIDR, không tương thích model hoặc SCP lỗi thì dừng và điều tra; không đổi nhãn synthetic thành live.

## Phần còn thiếu

- Chưa có tự thực thi Red Team trên VMware từ UI.
- Chưa có streaming log liên tục từ Ubuntu đến FastAPI và dự đoán tự động qua trang One-Click.
- Chưa có SOC alerts/cases phát sinh tự động dựa trên Zeek lab thực.
- Chưa có thử nghiệm có nhãn độc lập để tính Precision/Recall/F1, chưa có bằng chứng G1–G8 trên laptop.

**Chưa viết báo cáo học thuật trước khi chạy nghiệm thu end-to-end trên VMware.**
