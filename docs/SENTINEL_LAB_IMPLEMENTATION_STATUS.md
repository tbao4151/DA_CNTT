# DA005 — Sentinel Lab: trạng thái triển khai có kiểm chứng

**Mốc lịch sử (01/11/2026):** `main` tại `aafec3c233dc3dcd2dd9940ea23e070155f5e2a2` (01/11/2026), sau khi PR #330 được hợp nhất và main quality CI thành công. Đây là bản kiểm kê **mã nguồn**, không phải biên bản chạy trên laptop. Xem `PROGRESS.md` và `ROADMAP.md` để biết thay đổi sau mốc này. Tên đề tài khoa ấn định vẫn là **“Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công” (DA005)**.

## Trạng thái kiểm chứng hiện tại trên GitHub (02/11/2026)

Mốc mã nguồn đối chiếu mới: `main` tại `329e3243945b752ddbdc3ffa5ce6f246bea0798c` sau khi [PR #347](https://github.com/tbao4151/DA_CNTT/pull/347) được hợp nhất. Ubuntu quality [#41389724529](https://github.com/tbao4151/DA_CNTT/actions/runs/41389724529) và Windows offline [#41389724552](https://github.com/tbao4151/DA_CNTT/actions/runs/41389724552) đều **SUCCESS** trên đúng feature head `d5bf02d4394f0e0c345f707d1cd21ed9f5470321`; post-merge main quality [#41392752250](https://github.com/tbao4151/DA_CNTT/actions/runs/41392752250) **SUCCESS**. Đây là bằng chứng CI phần mềm, **không** phải phiên thử nghiệm VMware/Windows của sinh viên.

Các thay đổi sau mốc lịch sử PR #330 bao gồm bộ kiểm tra cấu hình Linux guest ngoại tuyến, PCAP framing, kiểm chứng read-only tuple/timestamp và tùy chọn yêu cầu packet riêng biệt khi đối chiếu SOC case. Chúng **không** biến dữ liệu replay/synthetic thành live, không xác thực nguồn PCAP, không chứng minh Zeek sinh đúng flow từ packet (packet-to-flow identity), không tự động tạo operational alert. Tài liệu dưới đây phân biệt rõ chức năng phần mềm đã có với bằng chứng khoa học còn thiếu.

## Ma trận cổng nghiệm thu khoa học (trạng thái tại 02/11/2026)

Quy ước: **CODE_PRESENT** chỉ xác nhận có entrypoint/kiểm thử phần mềm trong repository; **PENDING_STUDENT_EVIDENCE** nghĩa là chưa có bằng chứng thực nghiệm độc lập của nhóm trong GitHub. Không được suy diễn CODE_PRESENT thành PASS nghiệm thu. Tệp riêng tư, nhãn và ảnh cấu hình không đưa vào Git.

| Gate | Code/contract đã có | Trạng thái bằng chứng | Việc cần làm trên Windows/VMware |
| --- | --- | --- | --- |
| G1 — cô lập và quyền | `scripts/check_paired_network_preflight.py`, `scripts/check_linux_guest_combined_preflight.py` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Kiểm tra thủ công VMnet/NIC, NAT/bridged, IPv4/IPv6, route, firewall, DNS, forwarding và văn bản cho phép; lưu ảnh/snapshot riêng tư. |
| G2 — thu thập nguyên bản | `scripts/import_offline_pcap.py`, `docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Thu PCAP benign từ Host-only được phép, tạo `conn.log` bằng Zeek offline, ghi phiên bản, thời gian và SHA-256 gốc. |
| G3 — tính nhất quán bằng chứng | `scripts/verify_lab_evidence_chain.py`, `scripts/verify_zeek_soc_case_link.py` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Ghim riêng PCAP/Zeek/import report; đối chiếu tuple/timestamp khi tương thích, lưu kết quả từ chối/PASS; không nhận là packet-to-flow identity. |
| G4 — nhãn và phân hoạch | `scripts/evaluate_zeek_lab.py`, `src/blue_team_ai/labeled_dataset.py` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Hai người đánh nhãn độc lập, đối chiếu bất đồng, tách host/session TRAIN/VALIDATION/TEST và giữ TEST chưa dùng để chọn ngưỡng. |
| G5 — đánh giá Blue AI | `src/blue_team_ai/offline_baseline.py`, `src/blue_team_ai/new_log_evaluation.py` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Đánh giá mô hình Zeek riêng trên holdout với Precision/Recall/FPR, FP/FN, nhãn/provenance; không chuyển benchmark UNSW-NB15 thành metric live. |
| G6 — alert và SOC case | `src/blue_team_ai/research_alerts.py`, `src/blue_team_ai/new_log_triage.py` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Dùng NEW log chưa thấy, kiểm tra research candidate, analyst xác nhận tạo Unclassified case và xuất audit/evidence riêng tư. |
| G7 — độ trễ và tái lập | `scripts/benchmark_zeek_new_log_runtime.py`, `docs/FIRST_VMWARE_HOSTONLY_EVIDENCE_SESSION.md` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Ghi clock nguồn, mốc packet/Zeek/inference/alert/case thực đo; phân biệt offline processing time với event-to-case latency. |
| G8 — Red Team an toàn | `src/red_team_ai/scenario_policy.py`, `src/shared/offline_handoff.py` | CODE_PRESENT; PENDING_STUDENT_EVIDENCE | Giữ Execution OFF; chỉ so sánh UCB1 với seeded random bằng phản hồi có nguồn; không phát sinh attack/scan/DoS. |

**Kết luận nghiệm thu:** Chưa đạt end-to-end Cyber Lab thực nghiệm. Dataset Mode vẫn là benchmark lịch sử riêng. Mọi dòng CODE_PRESENT chỉ phản ánh mã nguồn đã tồn tại và CI synthetic, không phải xác nhận chức năng đã chạy trên laptop hay có độ chính xác thực tế.

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

## Kiểm chứng lịch sử trên main (01/11/2026, đến PR #330)

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
| Blue protocol diagnostics | `src/blue_team_ai/protocol_error_analysis.py`, `src/blue_team_ai/new_log_evaluation.py` | Tổng hợp protocol TP/FP/TN/FN, Wilson và Brier từ nhãn do người vận hành cung cấp; không xác thực nhãn, không đo live. |
| Research queue | `src/blue_team_ai/research_alerts.py` | Xuất/xác minh danh sách **research candidates** đã ghim, không phải alert production hoặc nhãn tấn công xác nhận. |
| Red Team | `pages/2_Red_Team_Lab.py`, `src/red_team_ai/scenario_policy.py`, `src/red_team_ai/planning_audit.py` | Danh mục nhãn kịch bản cố định, UCB1/seeded random, feedback thủ công và audit. **Execution OFF**; không có quyền điều khiển mạng/VMware. |
| Shared handoff | `src/shared/offline_handoff.py`, `scripts/verify_red_blue_offline_handoff.py` | Đối chiếu read-only Red proposal, PCAP/Zeek và Blue report đã ghim; không chứng minh kịch bản gây ra packet hay AI phát hiện thật. |
| Offline capture checks | `scripts/import_offline_pcap.py`, `scripts/verify_pcap_zeek_tuple.py`, `scripts/check_paired_network_preflight.py`, `scripts/verify_lab_evidence_chain.py` | Import/đối chiếu dữ liệu offline, kiểm tra cấu hình mạng do operator cung cấp; **không chứng minh cô lập Host-only**. |

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
