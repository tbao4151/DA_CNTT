# DA005 VMware — Cooperative STOP cho phiên thử nghiệm Host-only

Chức năng dừng này áp dụng cho CLI operator-assisted stepwise ở Python, không phải nút STOP trong giao diện web synthetic replay. Chỉ dùng với VMware Host-only thuộc quyền quản lý của nhóm sau khi xác minh cấu hình mạng, máy ảo, quyền và Zeek interface. Các kịch bản vẫn là kết nối lành tính, không phải exploit hoặc AI tự tạo tấn công.

## Kích hoạt STOP

Trước một phiên thực sự, Windows PowerShell phải có thư mục bằng chứng riêng tư nằm NGOÀI Git:

    New-Item -ItemType Directory -Force 'E:\DA005_Private\captures' | Out-Null

Dùng đường dẫn cố định của marker, chưa tạo trước lúc bắt đầu:

    E:\DA005_Private\captures\DA005_STOP.flag

Trước khi cấp quyền thực thi, kiểm tra marker không tồn tại. Nếu tồn tại, phiên mới bị từ chối trước khi thực hiện thao tác mạng. Không tự xóa marker khi một phiên còn đang chạy.

Ví dụ dry-run (không phát gói tin và không SCP):

    py -3.12 scripts/run_vmware_progress_file.py --jsonl-file 'E:\DA005_Private\captures\phase-001.jsonl' --source-ip 192.168.77.1 --target-ip 192.168.77.20 --cidr 192.168.77.0/24 --scenario connection_shift --user YOUR_UBUNTU_USER --known-hosts "$HOME\.ssh\known_hosts" --output-dir 'E:\DA005_Private\captures' --stop-file 'E:\DA005_Private\captures\DA005_STOP.flag'

Địa chỉ IP là ví dụ lịch sử, cần xác minh thực tế. Nếu và chỉ nếu các xác minh độc lập về mạng Host-only, scope, SSH và bằng chứng hoàn tất, người vận hành có thể chạy cùng lệnh với --execute --operator-confirmed-hostonly.

Để đề nghị DỪNG trong lúc CLI đang chạy, mở PowerShell khác và tạo marker:

    New-Item -ItemType File -Path 'E:\DA005_Private\captures\DA005_STOP.flag' -Force

Hệ thống kiểm tra marker trước gói tin đầu tiên, trước từng lượt kết nối tiếp theo (tối đa bốn), sau Red, sau thời gian chờ Zeek flush và trước SCP, sau Zeek/Blue bridge, trước audit và trước khi phát kết quả hoàn tất.

Nếu thấy STOP, chương trình thoát với mã lỗi. Terminal JSONL là trạng thái refused, với cờ xác minh AI/SOC/tấn công vẫn false. Sự kiện trước đó (nếu có) được giữ lại, nhưng không có terminal completed. Giao diện hiển thị trạng thái từ chối hoặc lỗi.

GIỚI HẠN: Đây là dừng HỢP TÁC tại ranh giới các bước, KHÔNG phải kill switch thời gian thực. Không bảo đảm ngắt socket hoặc SCP đang thực hiện. Trong trường hợp khẩn cấp, dừng phiên bằng terminal hoặc cô lập VM theo đúng quy trình.

Có thể nhấn Ctrl+C trên terminal CLI; chương trình cố gắng phát refused khi nhận KeyboardInterrupt. Nếu process bị kill tức thời, dòng terminal có thể không xuất hiện; JSONL lúc đó là DỞ DANG. Không bao giờ sửa bằng chứng để tạo kết quả completed giả.

Chỉ sau khi chắc chắn không còn phiên chạy, nhóm mới có thể lưu marker cùng dấu thời gian vào hồ sơ riêng rồi xóa marker có chủ đích trước phiên kế tiếp.

Chức năng này không biến dự án thành One-Click dual-AI, không xác minh nguồn gốc capture, không tạo SOC case live, và không chứng minh khả năng phát hiện tấn công. Xem docs/VMWARE_PROGRESS_FILE_AUDIT.md và docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md.

## Kiểm thử network-free

    py -3.12 -m pytest -q tests/test_vmware_cooperative_stop.py

Các bài kiểm thử dùng mock để xác nhận STOP trước probe, sau Red, sau Zeek và Ctrl+C đều không gây tuyên bố thành công giả.
