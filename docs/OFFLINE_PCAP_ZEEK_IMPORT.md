# DA005 — Import PCAP offline bằng Zeek (Cyber Lab Mode)

Đây là một **bước thu thập dữ liệu ngoại tuyến**, không phải công cụ bắt gói tin trực tiếp, không tạo lưu lượng kiểm thử, không thực thi kịch bản Red Team, không tự phát AI Alert và không tạo SOC Case. Chỉ dùng PCAP **đã có sẵn**, do nhóm sở hữu hoặc được phép phân tích. Dataset Mode UNSW-NB15 không bị thay đổi.

## Môi trường và ranh giới an toàn

Chạy bên trong máy ảo **Linux có Zeek đã cài**, sau khi nhóm tự kiểm tra cấu hình VMware Host-only và quyền sử dụng PCAP. Công cụ gọi đúng `zeek -r <đường dẫn PCAP>` bằng subprocess không qua shell; **không gọi `zeek -i`** và không sử dụng giao diện mạng. Đường dẫn PCAP và thư mục đầu ra phải tuyệt đối, nằm **ngoài repository**. Thư mục đầu ra chưa được tồn tại; công cụ không ghi đè và không xóa dữ liệu, kể cả khi Zeek lỗi. Giới hạn PCAP 64 MiB, `conn.log` 15 MiB/10.000 flow và thời gian Zeek tối đa 120 giây. Phiên bản đầu chỉ hỗ trợ **classic PCAP**, không hỗ trợ PCAPNG.

Đặt PCAP gốc tại một thư mục riêng tư trong VM (ví dụ `/home/student/da005-private/capture-001/input.pcap`), tạo sẵn thư mục cha đầu ra `/home/student/da005-private/capture-001`, nhưng **không tạo** thư mục `zeek-run-001` trước khi chạy. Cần cài Python 3.12.x, Zeek và dependencies dự án. Trên Linux, `zeek --version` và `python3 --version` giúp kiểm tra môi trường; trên Windows host không giả định đã có Zeek.

```bash
python3 scripts/import_offline_pcap.py \
  --pcap /home/student/da005-private/capture-001/input.pcap \
  --output-dir /home/student/da005-private/capture-001/zeek-run-001 \
  --cidr 192.168.56.0/24 \
  --confirm-offline-only
```

Thay CIDR bằng mạng **RFC1918 thực tế** của lab, đã được nhóm xác nhận. Có thể lặp lại `--cidr` (tối đa bốn mạng). Chương trình từ chối bất kỳ địa chỉ nguồn/đích nào ngoài phạm vi đã khai báo, kể cả traffic tới DNS/gateway bên ngoài. **Không mở rộng CIDR để ép dữ liệu lỗi vượt qua kiểm tra.** Hãy kiểm tra cấu hình cô lập hoặc nguồn PCAP.

## Bằng chứng và hạn chế

Khi thành công, thư mục riêng chứa `conn.log`, các log Zeek phụ nếu Zeek tạo ra, và `offline_import_report.json`. Báo cáo chứa SHA-256 PCAP gốc, SHA-256 `conn.log`, số flow và checksum phạm vi CIDR, **không chứa IP, UID, đường dẫn riêng hay nhãn tấn công**. Giữ PCAP, Zeek logs và báo cáo bên ngoài Git; ghi thêm ảnh cấu hình adapter, routes, Zeek version, thời điểm bắt gói, người vận hành, mã phiên và nhật ký kịch bản. Công cụ không tự chứng minh dữ liệu là lab capture thật, VMware cô lập, nhãn đúng hay phát hiện tấn công chính xác.

Khi lỗi, thư mục đầu ra có thể chứa tệp Zeek chưa hoàn chỉnh; **không dùng làm bằng chứng thành công**. Dùng tên thư mục mới khi chạy lại. Không đẩy PCAP hoặc log nhạy cảm lên GitHub.

Sau import, có thể đưa `conn.log` qua pipeline Zeek offline đã có: kiểm tra phạm vi, tạo hồ sơ bằng chứng, chuẩn hóa feature, đánh giá với nhãn độc lập và Blue Team research review. Không dùng Random Forest UNSW-NB15 trực tiếp với Zeek.

## Kiểm thử

```bash
python3 -m pytest -q tests/test_offline_pcap_import.py
```

Các bài kiểm thử **mock subprocess**, tạo PCAP và Zeek log tổng hợp; chúng chỉ kiểm tra hợp đồng chương trình và điều kiện từ chối. Chúng **không chạy Zeek thật**, không kiểm tra VMware thật, không đo hiệu năng hoặc độ chính xác AI. Bước nghiệm thu cần sinh viên chạy lệnh trên một máy ảo Linux thực, lưu checksum và xác minh độc lập log sinh ra.
