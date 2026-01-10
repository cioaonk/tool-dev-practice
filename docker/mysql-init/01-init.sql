-- =============================================================================
-- MySQL Initialization Script for CPTC11 Test Environment
-- =============================================================================
-- This script creates test data for the webapp database.
-- =============================================================================

USE webapp;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users (passwords are intentionally weak for testing)
INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'admin123', 'admin@testlab.local', 'admin'),
    ('user1', 'password1', 'user1@testlab.local', 'user'),
    ('user2', 'password2', 'user2@testlab.local', 'user'),
    ('testuser', 'testpass', 'test@testlab.local', 'user'),
    ('developer', 'dev2024', 'dev@testlab.local', 'developer'),
    ('dbadmin', 'dbadmin123', 'dbadmin@testlab.local', 'admin');

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Products table (for demo app)
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(50)
);

INSERT INTO products (name, description, price, category) VALUES
    ('Widget A', 'A basic widget', 19.99, 'widgets'),
    ('Widget B', 'An advanced widget', 49.99, 'widgets'),
    ('Gadget X', 'A cool gadget', 99.99, 'gadgets'),
    ('Tool Y', 'A useful tool', 29.99, 'tools');

-- Configuration table (contains sensitive data for testing)
CREATE TABLE IF NOT EXISTS config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(50) NOT NULL UNIQUE,
    config_value TEXT,
    is_secret BOOLEAN DEFAULT FALSE
);

INSERT INTO config (config_key, config_value, is_secret) VALUES
    ('site_name', 'CPTC11 Test Application', FALSE),
    ('admin_email', 'admin@testlab.local', FALSE),
    ('api_key', 'sk_test_1234567890abcdef', TRUE),
    ('encryption_key', 'MySuperSecretKey123!', TRUE),
    ('backup_password', 'BackupPass2024', TRUE);

-- Logs table
CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    log_type VARCHAR(20),
    message TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant permissions
GRANT ALL PRIVILEGES ON webapp.* TO 'webuser'@'%';
FLUSH PRIVILEGES;
