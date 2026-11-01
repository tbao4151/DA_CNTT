# DA005 — Sentinel Lab: trạng thái triển khai có kiểm chứng

**Mốc đối chiếu:** `main` tại `aafec3c233dc3dcd2dd9940ea23e070155f5e2a2` (01/11/2026), sau khi PR #330 được hợp nhất và main quality CI thành công. Đây là bản kiểm kê **mã nguồn**, không phải biên bản chạy trên laptop. Xem `PROGRESS.md` và `ROADMAP.md` để biết thay đổi sau mốc này. Tên đề tài khoa ấn định vẫn là **“Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công” (DA005)**.

## Sơ đồ luồng dữ liệu và ranh giới

```text
Dataset Mode (historical, offline)
UNSW-NB15 train/test -> src/siem_ai/model.py -> Random Forest -> app.py
                                              -> Dataset SOC SQLite (`runtime/soc_cases.sqlite3`)

Cyber Lab Mode (offline research, NOT live)
Private authorized PCAP --offline import/Zeek--> original conn.log + SHA-256
  -> blue_team_ai/zeek.py -> typed Zeek-only features
  -> independently annotated TRAIN / VALIDATION / held-out TEST
  -> blue_team_ai/offline_baseline.py (separate Logistic Regression research)
  -> pinned JSON-only model + NEW conn.log (offline scoring/review)
  -> research candidate / verified queue
  -> explicit analyst confirmation -> Unclassified SOC case + audit in private SQLite (`runtime/cyber_lab_cases.sqlite3`)

Red Team (non-executing)
Fixed safe scenario labels -> UCB1 or seeded random -> manual planning audit
  -> optional read-only evidence binding/handoff -> Blue research evidence
```

Không có đường nối từ `conn.log` vào Random Forest 42 đặc trưng UNSW-NB15. Không có packet capture trực tiếp, exploit, active traffic replay, autonomous attack, operational AI alert hoặc xác minh cô lập mạng vật lý trong các luồng trên. Mọi trường `timestamp`/`IP` của Zeek chỉ phản ánh nội dung tệp đầu vào; UNSW-NB15 train/test không có IP/timestamp gốc.

## Kiểm chứng mới nhất trên main (01/11/2026)

- [PR #327](https://github.com/tbao4151/DA_CNTT/pull/327): mô tả TP/FP/TN/FN theo bốn nhóm giao thức Zeek cố định, **không** suy diễn độ chính xác triển khai.
- [PR #328](https://github.com/tbao4151/DA_CNTT/pull/328): khoảng Wilson 95% mô tả theo giao thức, **không** điều chỉnh tương quan host/session.
- [PR #329](https://github.com/tbao4151/DA_CNTT/pull/329): Brier Score và tỷ lệ Attack theo nhãn người vận hành, **không** xác thực hiệu chỉnh xác suất hoặc nhãn.
- [PR #330](https://github.com/tbao4151/DA_CNTT/pull/330): dùng chung một lần parse Zeek cho hai phép tổng hợp protocol; **chưa đo** cải thiện runtime trên laptop.
- PR #330 có [Ubuntu CI thành công](https://github.com/tbao4151/DA_CNTT/actions/runs/41294345318) và [Windows offline CI thành công](https://github.com/tbao4151/DA_CNTT/actions/runs/41294345303) trên head `53adff917ee13ce10d489700b02a14110bcea17d`; [main quality CI](https://github.com/tbao4151/DA_CNTT/actions/runs/41295852825) thành công trên merge commit `aafec3c233dc3dcd2dd9940ea23e070155f5e2a2`. Đây chỉ là kiểm thử phần mềm bằng fixture/synthetic, không phải thực nghiệm VMware của sinh viên.

**Cổng nghiệm thu chưa đạt:** chưa có bằng chứng thu PCAP/Zeek gốc từ VMware Host-only đã kiểm tra độc lập, nhãn Attack/Normal độc lập, holdout host/session thực nghiệm, độ trễ packet-to-alert, hoặc SOC case từ phiên thu thật. Nút Red Team chỉ lập kế hoạch offline; không thực thi lưu lượng. Các báo cáo protocol/Brier thuộc **NEW-log nghiên cứu offline**, không thay thế benchmark UNSW-NB15 chính thức.

## Những thành phần đã có trong repository

| Thành phần | Entry point / module | Phạm vi đã triển khai |
| --- | --- | --- |
| Dataset Mode | `app.py`, `src/siem_ai/model.py`, `src/siem_ai/core.py` | Benchmark lịch sử, dự đoán khi có model đáng tin cậy, case/evidence/audit SQLite riêng; không phải SIEM live. |
| Blue telemetry | `pages/1_Cyber_Lab.py`, `src/blue_team_ai/zeek.py`, `src/blue_team_ai/features.py` | Preview Zeek ASCII offline, provenance, schema Zeek 9 đặc trưng; có manual Unclassified triage và kiểm tra trace nghiên cứu. Trang preview **không tự chạy inference**. |
| Blue research model | `src/blue_team_ai/labeled_dataset.py`, `src/blue_team_ai/offline_baseline.py`, `scripts/evaluate_zeek_lab.py` | Hợp đồng nhãn do người vận hành khai báo, host-disjoint split, train-only preprocessing, validation threshold và held-out test. CI synthetic không xác thực nhãn thật. |
| Blue NEW-log review | `pages/3_New_Log_Review.py`, `src/blue_team_ai/new_log_inference.py`, `src/blue_team_ai/new_log_triage.py` | Offline score từ Zeek-schema model đã ghim hash, xác minh declared partition và nguồn, chọn ứng viên thủ công để tạo/reuse **Unclassified** SOC case. Không có tự động mở case. |
| Blue protocol diagnostics | `src/blue_team_ai/protocol_error_analysis.py`, `src/blue_team_ai/new_log_evaluation.py` | Tổng hợp protocol TP/FP/TN/FN, Wilson và Brier từ nhãn do người vận hành cung cấp; không xác thực nhãn, không đo live. |\n| Research queue | `src/blue_team_ai/research_alerts.py` | Xuất/xác minh danh sách **research candidates** đã ghim, không phải alert production hoặc nhãn tấn công xác nhận. |
| Red Team | `pages/2_Red_Team_Lab.py`, `src/red_team_ai/scenario_policy.py`, `src/red_team_ai/planning_audit.py` | Danh mục nhãn kịch bản cố định, UCB1/seeded random, feedback thủ công và audit. **Execution OFF**; không có quyền điều khiển mạng/VMware. |
| Shared handoff | `src/shared/offline_handoff.py`, `scripts/verify_red_blue_offline_handoff.py` | Đối chiếu read-only Red proposal, PCAP/Zeek và Blue report đã ghim; không chứng minh kịch bản gây ra packet hay AI phát hiện thật. |
| Offline capture checks | `scripts/import_offline_pcap.py`, `scripts/verify_pcap_zeek_tuple.py`, `scripts/check_paired_network_preflight.py` | Import/đối chiếu dữ liệu offline, kiểm tra cấu hình mạng do operator cung cấp; **không chứng minh cô lập Host-only**. |

Các trang Streamlit nằm trong `pages/`, **không** phải `apps/blue_team/` hay `apps/red_team/`. Việc chia thành các thư mục `apps/` là phương án tái cấu trúc trong tương lai, không được báo cáo như đã hoàn thành. Một số module có compatibility entrypoint trong `src/siem_ai/`; không xóa hoặc đổi giao diện cũ khi chưa có regression tests.

## Bằng chứng phần mềm so với nghiệm thu khoa học

Tại mốc đối chiếu 01/11, PR #330 đã merge; workflow `Mini-SIEM quality gates` trên `main` ([run #41295852825](https://github.com/tbao4151/DA_CNTT/actions/runs/41295852825)) thành công. Đây là **CI**, không phải phiên thực nghiệm Windows 11/VMware của nhóm. Các workflow Zeek sử dụng fixtures hoặc PCAP tổng hợp; không chứng minh đã thu lưu lượng thật trong lab. Chỉ số UNSW-NB15 thuộc **Dataset Mode**, không chuyển thành chỉ số phát hiện của Cyber Lab.

Chưa có bằng chứng nghiệm thu tại máy sinh viên cho chuỗi **VMware Host-only được kiểm tra độc lập -> PCAP/Zeek thực tế -> nhãn độc lập -> mô hình Zeek đánh giá trên held-out host/session -> research alert -> SOC case -> thời gian end-to-end**. Các báo cáo Precision/Recall/FPR của dữ liệu synthetic hoặc operator-supplied không phải độ chính xác thực tế nếu chưa xác thực nguồn và nhãn. Các phép đo runtime offline không phải độ trễ live từ packet đến alert.

## Các bước nghiệm thu trên Windows (chưa được thực hiện bởi CI)

1. Đọc `docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md` và `docs/WINDOWS_PAIRED_NETWORK_PREFLIGHT.md`; kiểm tra host **và từng guest**, IPv4/IPv6, NAT/bridged/route, VMnet, quyền kiểm thử. Giữ Red execution OFF.
2. Thu một PCAP và Zeek `conn.log` từ mạng do nhóm sở hữu/được phép; lưu bản gốc, SHA-256, phiên bản Zeek, ảnh cấu hình và sổ tay kịch bản **ngoài GitHub**.
3. Thực hiện quy trình `docs/ZEEK_OFFLINE_EXPERIMENT.md` với nhãn độc lập, host/session-disjoint TRAIN/VALIDATION/TEST và untouched TEST; không dùng kết quả TEST để chọn model/ngưỡng.
4. Theo `docs/ZEEK_NEW_LOG_BLUE_TEAM_UI.md`, ghim model, manifest, log và report; chạy read-only review rồi chọn một ứng viên để tạo **Unclassified** case bằng xác nhận thủ công. Lưu audit JSON và đối chiếu hash.
5. Ghi rõ thời điểm phát sinh traffic, hoàn tất Zeek, bắt đầu/kết thúc inference và tạo case bằng đồng hồ nhất quán; báo cáo độ trễ theo định nghĩa đo, không gọi offline processing là real-time detection.

**Giới hạn an toàn:** Không tự động tạo traffic, không quét/exploit ngoài lab, không chạy brute force/DoS/persistence/stealth; không triển khai công khai, không commit PCAP/Zeek riêng tư, model không tin cậy, SQLite hoặc secrets.
