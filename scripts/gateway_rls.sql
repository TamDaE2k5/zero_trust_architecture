-- =============================================================================
-- Kịch bản Kích hoạt Bảo vệ Mức Dòng (Row-Level Security - RLS)
-- Tệp: scripts/gateway_rls.sql
-- =============================================================================

-- 1. Kích hoạt RLS (ENABLE) và Cưỡng chế RLS (FORCE) trên cả 3 bảng
-- - ENABLE: Bật tính năng kiểm soát truy cập từng dòng.
-- - FORCE: Cực kỳ quan trọng! Ép buộc RLS áp dụng ngay cả với chủ sở hữu bảng (table owner).
ALTER TABLE customer_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_data FORCE ROW LEVEL SECURITY;

ALTER TABLE financial_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_records FORCE ROW LEVEL SECURITY;

ALTER TABLE production_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_logs FORCE ROW LEVEL SECURITY;

-- 2. Chính sách RLS trên bảng customer_data
-- - Áp dụng riêng cho tài khoản: gateway_reader
-- - Đọc biến phiên: current_setting('gateway.scope', true)
--   (tham số thứ 2 là 'true' nghĩa là nếu biến chưa được gán thì trả về NULL thay vì văng lỗi)
-- - Quy tắc lọc:
--   + Nếu scope = 'all' (Admin) => Cho phép đọc toàn bộ dòng.
--   + Nếu scope = 'department' => Chỉ cho phép đọc các dòng có department khớp với phòng ban người dùng.
--   + Nếu chưa gán biến phiên (NULL) => Điều kiện trả về FALSE => Trả về đúng 0 dòng (Mặc định Fail-Closed)!
DROP POLICY IF EXISTS gateway_scope ON customer_data;
CREATE POLICY gateway_scope ON customer_data FOR SELECT TO gateway_reader
 USING (current_setting('gateway.scope', true) = 'all' OR
        (current_setting('gateway.scope', true) = 'department' AND
         department = current_setting('gateway.department', true)));

-- 3. Chính sách RLS trên bảng financial_records
DROP POLICY IF EXISTS gateway_scope ON financial_records;
CREATE POLICY gateway_scope ON financial_records FOR SELECT TO gateway_reader
 USING (current_setting('gateway.scope', true) = 'all' OR
        (current_setting('gateway.scope', true) = 'department' AND
         department = current_setting('gateway.department', true)));

-- 4. Chính sách RLS trên bảng production_logs
DROP POLICY IF EXISTS gateway_scope ON production_logs;
CREATE POLICY gateway_scope ON production_logs FOR SELECT TO gateway_reader
 USING (current_setting('gateway.scope', true) = 'all' OR
        (current_setting('gateway.scope', true) = 'department' AND
         department = current_setting('gateway.department', true)));
