# DA005 — Kết nối bộ chọn kịch bản UCB1 của Red Team với VMware (profile v2)

## Phạm vi

Profile v1 của scripts/run_vmware_session_profile.py vẫn hoạt động như trước: chọn trực tiếp đúng một trong ba kết nối mạng lành tính đã định nghĩa. Profile v2 bổ sung bộ chọn UCB1 hoặc seeded-random của src/red_team_ai/scenario_policy.py, nhưng **không cấp quyền tự ý tạo hoặc chọn mục tiêu/kịch bản mới**.

Red Team ở đây chỉ dùng thuật toán multi-armed bandit trên các nhãn kịch bản cố định, dựa trên phản hồi người vận hành nhập thủ công. Không có LLM, không sinh exploit, không quét mạng, không đánh cắp thông tin, không xác minh AI tấn công. Đầu vào "blue_flagged" là quan sát chủ quan/chưa xác minh, KHÔNG được xem là ground truth, nhãn tấn công hay kết quả phát hiện mô hình.

## Cấu hình riêng tư có SHA-256

Tạo hồ sơ JSON mới trong thư mục nằm ngoài Git, theo mẫu docs/VMWARE_PINNED_ONE_COMMAND_SESSION.md. Giữ nguyên toàn bộ các trường v1, nhưng đổi:

    "version": 2,
    "scenario_id": "dns_variation",
    "red_policy": {
      "strategy": "ucb1",
      "seed": 42,
      "feedback": [
        {"scenario_id": "baseline_web", "blue_flagged": true},
        {"scenario_id": "dns_variation", "blue_flagged": false},
        {"scenario_id": "connection_shift", "blue_flagged": true}
      ],
      "expected_scenario_id": "dns_variation"
    }

Trong ví dụ, UCB1 chọn dns_variation vì cả ba lựa chọn đều đã có một lần ghi nhận và kịch bản này có tỉ lệ "chưa bị người vận hành đánh dấu" cao nhất. Đây chỉ là kết quả chọn kịch bản nghiên cứu theo feedback nhập tay. Không có nguồn dữ liệu mạng thực tế trong cấu hình ví dụ.

Bộ kiểm tra chỉ cho phép 0–128 dòng phản hồi có đúng hai trường scenario_id/blue_flagged, strategy thuộc ucb1 hoặc random, seed nguyên từ 0–1.000.000. Kịch bản do thuật toán chọn phải khớp đồng thời với scenario_id ở profile và expected_scenario_id của chính red_policy. Không khớp thì toàn bộ phiên bị từ chối trước khi gửi lưu lượng và trước khi tạo tệp tiến độ.

Việc ghim SHA-256 phải được thực hiện lại độc lập sau MỌI sửa đổi. Hồ sơ phải nằm ngoài Git, không symlink, không chứa mật khẩu/SSH private key, IP và CIDR phải là Host-only đã được xác minh. Không lưu profile thật hoặc raw conn.log lên GitHub.

## Khởi chạy

Lệnh giống hệt profile v1; không cần tăng quyền:

    py -3.12 scripts/run_vmware_session_profile.py --config-file "E:\DA005_Private\captures\operator-profile-v2.json" --expected-config-sha256 YOUR_INDEPENDENT_SHA256 --jsonl-file "E:\DA005_Private\captures\ucb1-dryrun-001.jsonl"

Mặc định DRY-RUN: không phát gói tin, không SCP, không chạy Blue Team. Chỉ chạy kết nối lành tính trên VM của nhóm sau khi đã kiểm tra mạng vật lý Host-only và có đồng thời --execute --operator-confirmed-hostonly. Chỉ có ba kịch bản đã khóa trong bộ tạo lưu lượng, tối đa bốn lượt thử mỗi phiên.

Khi hồ sơ v2 hợp lệ, chương trình ghi thêm tệp duy nhất trong chính thư mục riêng tư, có tên tương ứng:

    ucb1-dryrun-001.red-plan.json

Tệp này chứa chiến lược, seed, scenario_id đã duyệt, số lượng phản hồi, nguồn phản hồi operator_entered_unverified và SHA-256 hồ sơ. Nó không chứa IP, đường dẫn, phản hồi gốc, UID hoặc dự đoán mô hình. Các trường planning_only=true, attack_executed=false, verified_ai_detection=false, soc_alerts_created=false vẫn giữ nguyên kể cả khi lệnh mạng lành tính được thực thi sau đó. Đây là **biên nhận quyết định chọn kịch bản, không phải biên nhận lưu lượng**.

Tệp tiến độ JSONL chính tiếp tục đi qua công cụ SHA-audit và giao diện /vmware-progress. Red probe, Zeek snapshot, tùy chọn mô hình Blue research và audit UID liên quan nằm trong pipeline hiện hữu, không phải kết quả từ UCB1. Khi không có model Zeek v1 được ghim riêng, Blue hiển thị "Không chạy". Không được diễn giải "candidate UID" là true positive.

Nếu biên nhận kế hoạch đã tồn tại, chương trình từ chối ghi đè. Nếu có một lần khởi chạy thất bại sau khi biên nhận được tạo, biên nhận đó vẫn chỉ chứng minh đã chọn nhãn kịch bản (không phải đã chạy mạng); giữ nguyên tệp gốc, chọn tên phiên mới để thử lại.

## Kiểm thử và giới hạn

    py -3.12 -m pytest -q tests/test_vmware_session_profile.py

CI Ubuntu và Windows kiểm tra tính xác định của UCB1/random, từ chối cấu hình giả, giữ tương thích profile v1 và chạy thử pipeline Red → Zeek với toàn bộ socket/SSH được mock. Không sử dụng VM thật, không tạo bằng chứng detection, không tính precision/recall/F1. Thu thập bằng chứng thật, đồng bộ đồng hồ, PCAP, chính sách mạng và mô hình có kiểm thử giữ lại là các công việc riêng cần hoàn thành trước khi viết báo cáo.
