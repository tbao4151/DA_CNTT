# DA005 — Audit độc lập tệp tiến độ VMware JSONL

Công cụ scripts/verify_vmware_progress_jsonl.py chỉ đọc một tệp JSONL riêng tư và kiểm tra SHA-256 do người vận hành lưu độc lập trước đó. Công cụ từ chối tệp thiếu dòng kết thúc, sự kiện sai thứ tự, số lượt thử / flow / Blue không khớp giữa các giai đoạn và bản tổng kết, dữ liệu không hợp lệ, trường chứa đường dẫn cá nhân hoặc cờ tuyên bố đã xác minh VMware/AI/SOC.

Đây KHÔNG phải công cụ chứng thực nguồn gốc máy ảo. Một tệp JSONL giả mạo hoàn toàn vẫn có thể qua kiểm tra nếu người tạo đồng thời cung cấp đúng SHA-256 của chính tệp giả. PASS chỉ xác nhận tính nhất quán nội bộ của tệp đã được pin, không chứng minh PCAP được thu trên Host-only, không có bằng chứng ground truth và không phải chỉ số đánh giá mô hình.

## Quy trình trên Windows 11

1. Dùng mã nguồn đã tích hợp PR #405–#408, tại thư mục gốc dự án. Tệp được tạo bằng scripts/run_vmware_progress_file.py trong thư mục riêng tư ngoài Git; mặc định dry-run, không mở socket.
2. Sau khi chương trình kết thúc, lưu SHA-256 từ hệ điều hành và ghi vào sổ kiểm thử riêng trước khi chạy verifier:

    Get-FileHash 'E:\DA005_Private\captures\phase-001.jsonl' -Algorithm SHA256

3. Truyền giá trị băm 64 ký tự chữ thường vừa ghi:

    py -3.12 scripts/verify_vmware_progress_jsonl.py --jsonl-file 'E:\DA005_Private\captures\phase-001.jsonl' --expected-sha256 <SHA256_64_KY_TU_CHU_THUONG>

Khi thành công, kết quả chỉ có các trường an toàn: hash đầu vào, số sự kiện, trạng thái dry_run/completed/refused và các cờ false. Không in IP, tên người dùng, đường dẫn, UID, mô hình hay nội dung conn.log. Lỗi trả exit code 1 và thông báo ngắn không tiết lộ bằng chứng cá nhân.

Chạy kiểm thử phần mềm không kết nối mạng:

    py -3.12 -m pytest -q tests/test_vmware_progress_jsonl_audit.py

## Phạm vi nghiệm thu khoa học

Dùng các công cụ RIÊNG BIỆT sau trong buổi thực nghiệm thực tế:

- scripts/check_paired_network_preflight.py: so sánh snapshot mạng host/guest được pin
- scripts/check_linux_guest_combined_preflight.py: sàng lọc route/policy Linux trong snapshot
- scripts/verify_vmware_snapshot_bundle.py: đối chiếu tệp Zeek conn.log và receipt từ SCP
- scripts/verify_vmware_progress_jsonl.py: đối chiếu tiến độ phần mềm
- scripts/verify_vmware_session_record.py: kiểm toán hồ sơ phiên và các chứng cứ bổ sung, nếu có

Không được dùng một công cụ thay thế kết quả của công cụ khác. Phải kiểm tra cấu hình VMware Virtual Network Editor, NIC thực tế, Zeek interface, PCAP và nhật ký thời gian bằng quan sát độc lập. Kết quả bắt buộc từ VMware chỉ được ghi vào báo cáo sau khi chạy và lưu bằng chứng thực tế; không biến fixture của GitHub Actions thành số liệu thí nghiệm.
