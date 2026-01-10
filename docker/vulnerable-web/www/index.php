<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CPTC11 Test Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; color: #007bff; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CPTC11 Vulnerable Web Application</h1>

        <div class="warning">
            <strong>Warning:</strong> This is an intentionally vulnerable application for security testing purposes only.
        </div>

        <div class="nav">
            <a href="/login.php">Login</a>
            <a href="/admin/">Admin Panel</a>
            <a href="/api/">API</a>
            <a href="/search.php">Search</a>
            <a href="/upload.php">File Upload</a>
        </div>

        <h2>Application Information</h2>
        <ul>
            <li>Server: <?php echo $_SERVER['SERVER_SOFTWARE']; ?></li>
            <li>PHP Version: <?php echo phpversion(); ?></li>
            <li>Host: <?php echo gethostname(); ?></li>
            <li>IP: <?php echo $_SERVER['SERVER_ADDR']; ?></li>
        </ul>

        <h2>Test Endpoints</h2>
        <ul>
            <li><code>/admin/</code> - Basic Auth protected admin area</li>
            <li><code>/api/</code> - REST API endpoints</li>
            <li><code>/login.php</code> - Form-based login</li>
            <li><code>/search.php</code> - Search functionality (SQL injection)</li>
            <li><code>/upload.php</code> - File upload</li>
            <li><code>/config/</code> - Configuration files</li>
            <li><code>/backup/</code> - Backup files</li>
            <li><code>/.git/</code> - Exposed git directory</li>
            <li><code>/robots.txt</code> - Robots file with hints</li>
            <li><code>/server-status</code> - Apache server status</li>
        </ul>
    </div>
</body>
</html>
