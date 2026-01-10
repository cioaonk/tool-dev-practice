<?php
session_start();

$valid_users = [
    'admin' => 'admin123',
    'user' => 'password',
    'testuser' => 'testpass',
    'webmaster' => 'webmaster1'
];

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (isset($valid_users[$username]) && $valid_users[$username] === $password) {
        $_SESSION['user'] = $username;
        $_SESSION['logged_in'] = true;
        $message = '<div class="success">Login successful! Welcome, ' . htmlspecialchars($username) . '</div>';
    } else {
        $message = '<div class="error">Invalid username or password</div>';
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - CPTC11 Test App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        form { margin-top: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .back { text-align: center; margin-top: 20px; }
        .back a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>User Login</h1>

        <?php echo $message; ?>

        <?php if (isset($_SESSION['logged_in']) && $_SESSION['logged_in']): ?>
            <p>You are logged in as <strong><?php echo htmlspecialchars($_SESSION['user']); ?></strong></p>
            <p><a href="?logout=1">Logout</a></p>
            <p><a href="/dashboard.php">Go to Dashboard</a></p>
        <?php else: ?>
            <form method="POST" action="">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>

                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>

                <button type="submit">Login</button>
            </form>
        <?php endif; ?>

        <div class="back">
            <a href="/">Back to Home</a>
        </div>
    </div>
</body>
</html>
