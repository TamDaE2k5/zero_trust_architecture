-- =============================================================================
-- Kịch bản SQL Khởi tạo Bảng Dữ liệu & Dữ liệu Mẫu Ban đầu (Database Schema)
-- Tệp: scripts/init_gateway_db.sql
-- Tự động chạy khi Docker PostgreSQL khởi tạo container lần đầu tiên
-- =============================================================================

-- 1. Bảng Dữ liệu Khách hàng (Chứa các thông tin nhạy cảm cần che mờ DDM)
CREATE TABLE customer_data (
    id integer PRIMARY KEY,
    department text NOT NULL,
    name text NOT NULL,
    email text NOT NULL,         -- Nhạy cảm: Bị che mờ với non-admin (analyst, intern)
    salary integer NOT NULL,      -- Nhạy cảm: Bị che mờ với non-admin
    national_id text NOT NULL    -- Nhạy cảm: Bị che mờ với non-admin
);

-- 2. Bảng Hồ sơ Tài chính Doanh nghiệp (Phân loại Restricted - Chỉ Finance/Admin được xem)
CREATE TABLE financial_records (
    id integer PRIMARY KEY,
    department text NOT NULL,
    period text NOT NULL,
    revenue integer NOT NULL
);

-- 3. Bảng Nhật ký Vận hành Hệ thống (Chỉ Data Engineer/Admin được xem)
CREATE TABLE production_logs (
    id integer PRIMARY KEY,
    department text NOT NULL,
    event text NOT NULL,
    severity text NOT NULL
);

-- Nạp dữ liệu mẫu thử nghiệm:
INSERT INTO customer_data VALUES
 (1, 'marketing', 'Synthetic Customer A', 'customer-a@example.test', 100000, 'DEMO-0001'),
 (2, 'marketing', 'Synthetic Customer B', 'customer-b@example.test', 120000, 'DEMO-0002'),
 (3, 'risk',      'Synthetic Customer C', 'customer-c@example.test', 150000, 'DEMO-0003');

INSERT INTO financial_records VALUES 
 (1, 'finance', '2026-Q3', 300000),
 (2, 'data',    '2026-Q3', 200000);

INSERT INTO production_logs VALUES 
 (1, 'data', 'Deployment completed', 'info'),
 (2, 'risk', 'Risk batch completed', 'info');
