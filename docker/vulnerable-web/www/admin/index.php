<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - CPTC11</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #2c3e50; color: white; }
        .container { max-width: 800px; margin: 0 auto; background: #34495e; padding: 30px; border-radius: 8px; }
        h1 { color: #ecf0f1; }
        .info { background: #3498db; padding: 15px; border-radius: 4px; margin: 15px 0; }
        ul { list-style: none; padding: 0; }
        li { padding: 10px; background: #2c3e50; margin: 5px 0; border-radius: 4px; }
        a { color: #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>

        <div class="info">
            <strong>Authenticated as:</strong> <?php echo $_SERVER['REMOTE_USER'] ?? 'Unknown'; ?>
        </div>

        <h2>Admin Functions</h2>
        <ul>
            <li><a href="/admin/users.php">User Management</a></li>
            <li><a href="/admin/config.php">System Configuration</a></li>
            <li><a href="/admin/logs.php">View Logs</a></li>
            <li><a href="/admin/backup.php">Backup Management</a></li>
            <li><a href="/admin/database.php">Database Admin</a></li>
        </ul>

        <h2>Server Information</h2>
        <ul>
            <li>PHP Version: <?php echo phpversion(); ?></li>
            <li>Server: <?php echo $_SERVER['SERVER_SOFTWARE']; ?></li>
            <li>Document Root: <?php echo $_SERVER['DOCUMENT_ROOT']; ?></li>
        </ul>

        <p><a href="/">Back to Main Site</a></p>
    </div>
</body>
</html>
