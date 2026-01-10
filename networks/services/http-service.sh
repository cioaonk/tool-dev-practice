#!/bin/bash
# HTTP Service Script for CORE Network Emulator
# Usage: http-service.sh [port] [webroot]
# Starts a simple HTTP server for penetration testing

PORT=${1:-80}
WEBROOT=${2:-/var/www/html}

# Create webroot if it doesn't exist
mkdir -p "$WEBROOT"

# Create default index.html if none exists
if [ ! -f "$WEBROOT/index.html" ]; then
    cat > "$WEBROOT/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Web Server</title>
</head>
<body>
    <h1>Welcome</h1>
    <p>This is a default web page.</p>
    <form action="login.php" method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
</body>
</html>
EOF
fi

# Create a vulnerable PHP file for testing
cat > "$WEBROOT/login.php" << 'EOF'
<?php
// Intentionally vulnerable login page for pentest practice
$username = $_POST['username'];
$password = $_POST['password'];

// SQL Injection vulnerable query (for practice)
// $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";

if ($username == "admin" && $password == "admin123") {
    echo "Welcome, admin!";
    // session_start(); $_SESSION['user'] = 'admin';
} else {
    echo "Invalid credentials";
}
?>
EOF

# Create robots.txt with interesting entries
cat > "$WEBROOT/robots.txt" << 'EOF'
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /api/internal/
EOF

# Create hidden admin directory
mkdir -p "$WEBROOT/admin"
cat > "$WEBROOT/admin/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Administration Panel</h1>
<p>Restricted Access</p>
<form action="admin_login.php" method="post">
    <input type="text" name="admin_user" placeholder="Admin Username">
    <input type="password" name="admin_pass" placeholder="Admin Password">
    <button>Login</button>
</form>
</body>
</html>
EOF

# Create backup directory with sensitive files
mkdir -p "$WEBROOT/backup"
echo "database_backup_2024.sql" > "$WEBROOT/backup/index.txt"
echo "-- MySQL Backup" > "$WEBROOT/backup/db.sql"
echo "-- Users table" >> "$WEBROOT/backup/db.sql"
echo "INSERT INTO users VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99');" >> "$WEBROOT/backup/db.sql"

# Start Python HTTP server
echo "[+] Starting HTTP server on port $PORT"
echo "[+] Webroot: $WEBROOT"
cd "$WEBROOT"

# Try python3 first, fall back to python
if command -v python3 &> /dev/null; then
    python3 -m http.server "$PORT" 2>&1 &
elif command -v python &> /dev/null; then
    python -m SimpleHTTPServer "$PORT" 2>&1 &
else
    echo "[-] Python not found, using netcat"
    while true; do
        echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n$(cat index.html)" | nc -l -p "$PORT" -q 1
    done &
fi

echo "[+] HTTP service started with PID $!"
