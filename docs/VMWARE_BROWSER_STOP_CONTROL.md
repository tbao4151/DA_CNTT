# DA005 — Gửi yêu cầu STOP từ giao diện VMware localhost

Giao diện /vmware-progress có thể gửi yêu cầu dừng hợp tác cho CLI operator-assisted **chỉ khi** PR #411 được tích hợp. Đây KHÔNG phải một nút kill-switch tức thời và KHÔNG chạy Red Team/Blue Team, SSH, mô hình AI hay bất kỳ API network nào.

## Luồng sử dụng trong Chrome/Edge localhost

1. Trên Windows, mở phiên VMware stepwise bằng scripts/run_vmware_progress_file.py, có bổ sung tùy chọn --stop-file với đường dẫn cố định trong chính thư mục bằng chứng. Ví dụ:
   
       --stop-file 'E:\DA005_Private\captures\DA005_STOP.flag'

2. Mở http://127.0.0.1:3000/vmware-progress trên Chrome hoặc Edge. Chọn Theo dõi tệp đang ghi và chọn đúng tệp JSONL mà CLI đang xuất.
3. Khi muốn dừng, nhấn Yêu cầu STOP qua tệp. Trình duyệt sẽ yêu cầu quyền ghi vào THƯ MỤC chứa tệp JSONL vừa chọn. Phải chọn đúng thư mục; hệ thống dùng File System Access API để so sánh file handle, không dựa riêng vào tên.
4. Đọc cảnh báo và nhấn Xác nhận gửi STOP. Trình duyệt tạo đúng tên DA005_STOP.flag trong thư mục đã xác minh; không ghi vào tệp log.
5. Quan sát dòng kết thúc của Python; trạng thái từ chối/lỗi mới xác nhận phần mềm đã thoát. Việc tạo marker mới là YÊU CẦU dừng, không khẳng định lệnh đã ngừng.

Nếu trình duyệt không hỗ trợ quyền ghi thư mục, tạo marker thủ công bằng PowerShell:

    New-Item -ItemType File -Path 'E:\DA005_Private\captures\DA005_STOP.flag' -Force

Nếu marker đã tồn tại, không ghi đè. Giữ và kiểm toán bằng chứng phiên trước khi xóa marker cho một lần chạy mới. Việc hủy thao tác chọn thư mục không tạo marker. Trang sẽ không ghi tệp nếu chưa có một phiên được theo dõi hoặc phiên đã có terminal.

## Giới hạn

- Cooperative STOP chỉ được kiểm tra ở ranh giới trước các probe tiếp theo và trước các giai đoạn hậu xử lý. Một socket hoặc SCP đã bắt đầu có thể vẫn đang chặn; không có bảo đảm thời gian dừng tức thời.
- Trang không tự biết PID của Python hay trạng thái mạng vật lý, và không thể xác minh việc tạo STOP đã được chương trình nhận.
- Việc chọn thư mục cần quyền đọc/ghi rõ ràng, một lần chọn và một lần xác nhận. Giao diện không đọc PCAP, conn.log, mô hình hay thông tin bí mật khác, không gọi POST/PUT/PATCH/DELETE để gửi marker.
- Trạng thái trong trang vẫn chỉ là tiến độ chương trình chưa xác minh. Chưa có phát hiện tấn công hay One-Click hai AI.

## QA không có hoạt động mạng

    cd frontend
    node scripts/vmware-stop-browser-smoke.mjs

Test headless Chromium mô phỏng File System Access API, xác minh không thể tạo marker trước xác nhận, từ chối sai thư mục, ngăn ghi trùng và không có HTTP mutation. Workflow CI chuyên biệt: .github/workflows/vmware-stop-browser.yml.
