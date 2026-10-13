# DA005 – Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công

Môn **Dự án CNTT** – Khoa Công nghệ Thông tin, Trường Đại học Tôn Đức Thắng (TDTU).

- Giảng viên hướng dẫn: Trương Đình Tú
- Nguyễn Văn Thiên Bảo – 52300179
- Đặng Triệu Vỹ – 52300274
- Phạm vi triển khai: Network Logs (Network Flow Logs)
- Bộ dữ liệu lựa chọn: CTU-13 Dataset – Scenario 7 (Sogou Botnet)

## Bộ dữ liệu

- **Nguồn chính thức:** https://www.stratosphereips.org/datasets-ctu13
- **Tệp gốc:** `capture20110816-2.binetflow` (khoảng 15 MB)
- **Thư mục lưu:** `data/raw/ctu13_scenario_07/`
- **Cấu trúc:** 15 cột: StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label.
- **Bản quyền dữ liệu:** Creative Commons Attribution (CC BY). Tác giả dataset giữ bản quyền; nhóm chỉ sử dụng cho học tập và trích dẫn nguồn.

Tải lại dữ liệu từ nguồn học thuật chính thức:

```bash
python scripts/download_ctu13.py
```

> Lưu ý: Background là lưu lượng chưa được xác nhận là an toàn; không nên gộp Background thành Normal mà không giải thích. Sự có mặt của từ "Botnet" trong nhãn cũng cần được xử lý cẩn thận theo quy tắc gán nhãn gốc.

## Tài liệu tham khảo

García, S., Grill, M., Stiborek, J., & Zunino, A. (2014). *An empirical comparison of botnet detection methods*. Computers & Security, 45, 100–123. https://doi.org/10.1016/j.cose.2014.05.011
