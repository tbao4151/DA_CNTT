# DA005 – Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công

Môn **Dự án CNTT**, Khoa CNTT, Đại học Tôn Đức Thắng (TDTU).

- GVHD: Trương Đình Tú
- Nguyễn Văn Thiên Bảo – 52300179
- Đặng Triệu Vỹ – 52300274
- Phạm vi: Network Logs / network intrusion detection
- **Dataset chính: UNSW-NB15 (standard train/test split)**
- Dataset CTU-13 Scenario 7 trước đây được giữ lại tại `data/raw/ctu13_scenario_07/` để tham khảo, không dùng làm tập huấn luyện chính.

## UNSW-NB15

[Nguồn học thuật chính thức](https://research.unsw.edu.au/projects/unsw-nb15-dataset). Sử dụng 2 CSV với tổng 257.673 dòng, gồm train (175.341) và test (82.332). Nhãn `label`: 0=Normal, 1=Attack; `attack_cat`: loại tấn công. Bản train/test có 45 cột (gồm `id`, `label`, `attack_cat`), khác với bản raw đầy đủ 49 đặc trưng.

Hai tệp được lấy từ [bản sao Nir-J/ML-Projects](https://github.com/Nir-J/ML-Projects/tree/master/UNSW-Network_Packet_Classification) và **đối chiếu SHA-256** theo [tài liệu kiểm tra bản sao](https://github.com/ausyeah/intrusion-detection-imbalance/blob/main/data/README.md). Không tuyên bố đã xác minh byte-by-byte trực tiếp với SharePoint chính thức.

### Tải và xác minh

```bash
python scripts/download_unsw_nb15.py
```

### Huấn luyện baseline

```bash
pip install -r requirements.txt
python scripts/evaluate_unsw_nb15.py
```

Kết quả sinh tại `reports/baseline_metrics.json`. Không báo cáo điểm số khi chưa thực thi huấn luyện và kiểm tra. Mọi tiền xử lý được fit chỉ trên train; test chính thức giữ nguyên. Không đưa `id`, `attack_cat` hay `label` vào đặc trưng. Chỉ số chính: precision, recall, F1 cho Attack, macro-F1, confusion matrix, average precision. Không chỉ dùng accuracy.

### Hạn chế

Đây là dữ liệu lưu lượng mạng có gán nhãn (flow features), không phải syslog nguyên bản hoặc nhật ký hệ điều hành. Dataset được tạo trong môi trường thử nghiệm; tỷ lệ Normal/Attack và giữa các loại tấn công chưa cân bằng, đặc biệt Worms và Shellcode có ít mẫu. Không suy luận trực tiếp hiệu quả thực tế khi triển khai trên hạ tầng mới.

### Trích dẫn

Moustafa, N. & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems*. MilCIS. Xem yêu cầu trích dẫn và phạm vi sử dụng học thuật tại trang UNSW chính thức.
