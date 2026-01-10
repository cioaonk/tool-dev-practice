#!/bin/bash
# MySQL Service Script for CORE Network Emulator
# Usage: mysql-service.sh [port]
# Simulates a MySQL database server for penetration testing

PORT=${1:-3306}
DATADIR="/var/lib/mysql"

# Create data directory
mkdir -p "$DATADIR"

# Create version info
echo "MySQL 5.7.32 - Community Edition" > "$DATADIR/version.txt"

# Create fake database structure info
cat > "$DATADIR/databases.txt" << 'EOF'
information_schema
mysql
performance_schema
sys
webapp_db
customer_data
employee_records
EOF

cat > "$DATADIR/users.txt" << 'EOF'
# MySQL Users (for enumeration practice)
root@localhost - GRANT ALL
webapp@% - GRANT SELECT,INSERT,UPDATE on webapp_db.*
backup@localhost - GRANT SELECT, LOCK TABLES on *.*
readonly@10.100.2.% - GRANT SELECT on webapp_db.*
admin@% - GRANT ALL (weak password: admin123)
EOF

echo "[+] Starting MySQL service on port $PORT"

# Check if MySQL/MariaDB is available
if command -v mysqld &> /dev/null; then
    # Initialize MySQL if needed
    if [ ! -d "$DATADIR/mysql" ]; then
        mysqld --initialize-insecure --datadir="$DATADIR" 2>/dev/null || true
    fi

    # Start MySQL
    mysqld --datadir="$DATADIR" --port="$PORT" --bind-address=0.0.0.0 &
    sleep 3

    # Create test databases and users
    mysql -u root << 'EOSQL'
CREATE DATABASE IF NOT EXISTS webapp_db;
CREATE DATABASE IF NOT EXISTS customer_data;

USE webapp_db;
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(255),
    email VARCHAR(100),
    role VARCHAR(20)
);

INSERT INTO users (username, password, email, role) VALUES
('admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@company.local', 'admin'),
('user1', '482c811da5d5b4bc6d497ffa98491e38', 'user1@company.local', 'user'),
('backup', '5d41402abc4b2a76b9719d911017c592', 'backup@company.local', 'backup');

CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

USE customer_data;
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    ssn VARCHAR(11),
    credit_card VARCHAR(20)
);

INSERT INTO customers (name, email, phone, ssn, credit_card) VALUES
('John Doe', 'jdoe@email.com', '555-0101', '123-45-6789', '4111111111111111'),
('Jane Smith', 'jsmith@email.com', '555-0102', '987-65-4321', '5500000000000004');

-- Create vulnerable user with weak password
CREATE USER IF NOT EXISTS 'webapp'@'%' IDENTIFIED BY 'webapp123';
GRANT SELECT, INSERT, UPDATE ON webapp_db.* TO 'webapp'@'%';

CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED BY 'admin123';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%';

FLUSH PRIVILEGES;
EOSQL

    echo "[+] MySQL server started with test databases"
else
    # Fallback: Simple MySQL banner
    echo "[*] MySQL not found, using banner service"
    (
        while true; do
            # MySQL 5.7.32 greeting packet
            printf '\x4a\x00\x00\x00\x0a5.7.32\x00\x01\x00\x00\x00\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x00\xff\xf7\x21\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x00mysql_native_password\x00' | nc -l -p "$PORT" -q 1
        done
    ) &
    echo "[+] MySQL banner service started"
fi

echo "[+] MySQL service configuration complete"
echo "[+] Test credentials:"
echo "    - admin / admin123 (full access)"
echo "    - webapp / webapp123 (webapp_db only)"
