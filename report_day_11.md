# Báo cáo Assignment 11 - Production Defense-in-Depth Pipeline

## 1. Tổng quan hệ thống
Hệ thống được triển khai theo hướng Pure Python + OpenAI, gồm các lớp:
1. Rate Limiter
2. Input Guardrails
3. LLM Response Generation
4. Output Guardrails
5. LLM-as-Judge
6. Audit Log + Monitoring
7. Bonus: Session Anomaly Detector

Kết quả test:
- Safe queries: 5/5 pass.
- Attack queries: 7/7 bị chặn tại Input Guard.
- Rate limit: 10 pass, 5 block.
- Edge cases: 5/5 bị chặn đúng logic.

## 2. Phân tích theo từng lớp bảo vệ
Trong bộ ATTACK_QUERIES, cả 7 prompt tấn công đều bị chặn ngay ở Input Guard trước khi tới mô hình chính.
Các pattern khớp gồm: `ignore_previous_instructions`, `dan_roleplay`, `credential_request`, `system_prompt_exfiltration`, `json_prompt_exfiltration`, `vietnamese_override`, `fill_in_secret`.

## 3. Phân tích false positive
Không ghi nhận false positive trong bộ test chuẩn (5/5 safe queries pass).
Tuy nhiên, nếu siết rule quá chặt (whitelist hẹp hoặc regex quá rộng), hệ thống có thể chặn nhầm truy vấn hợp lệ.
Trade-off chính: security cao hơn thường đi kèm usability thấp hơn.

## 4. Gap analysis (3 điểm chưa bắt tốt)
1. Many-shot jailbreak: ý đồ nguy hiểm ẩn trong ngữ cảnh dài.
2. Unicode/homoglyph attack: regex thường bỏ sót ký tự confusable.
3. Indirect prompt injection từ tài liệu/tool output: chưa tách trust boundary cho dữ liệu external.

Đề xuất bổ sung:
- Semantic risk classifier theo hội thoại.
- Unicode normalization + confusable mapping.
- Document sanitization + retrieval/tool-output guardrails.

## 5. Đánh giá production readiness
Hệ thống đã minh họa defense-in-depth tốt cho assignment.
Để production-ready cần nâng cấp:
- Tối ưu latency do mỗi request có thể gọọi >=2 LLM calls.
- Kiểm soát chi phí judge theo risk thay vì judge toàn bộ.
- Chuyển rate limiter sang Redis/distributed store.
- Tích hợp monitoring và alert vào dashboard/incident pipeline.
- Tách policy/rules ra config để cập nhật không cần redeploy full.

## 6. Suy ngẫm đạo đức
Không thể có hệ thống AI an toàn tuyệt đối.
Guardrails giảm rủi ro, nhưng không loại bỏ hoàn toàn sai sót.
Nguyên tắc thực tế:
- Từ chối dứt khoát yêu cầu exfiltration (password, API key, connection string).
- Với truy vấn hợp lệ nhưng dữ liệu biến động, trả lời an toàn kèm disclaimer.

## Kết luận
Bản triển khai hiện tại đáp ứng tốt mục tiêu assignment:
- Chặn tấn công ở input layer
- Giảm rò rỉ ở output layer
- Có judge hậu kiểm
- Có monitoring/alerts và audit log
- Có bonus session anomaly detector
