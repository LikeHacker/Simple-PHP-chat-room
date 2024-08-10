<?php
session_start();
$filename = 'user.json';
$chatFilename = 'chat.json';
$encryption_key = 'your-secret-encryption-key'; // 这里应该用一个安全的密钥

function getData($file) {
    return file_exists($file) ? json_decode(file_get_contents($file), true) : [];
}

function saveData($file, $data) {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
}

function userExists($username) {
    $users = getData($GLOBALS['filename']);
    return isset($users[$username]);
}

function registerUser($username, $password) {
    $users = getData($GLOBALS['filename']);
    if (userExists($username)) return false;
    $users[$username] = password_hash($password, PASSWORD_DEFAULT);
    saveData($GLOBALS['filename'], $users);
    return true;
}

function authenticateUser($username, $password) {
    $users = getData($GLOBALS['filename']);
    return isset($users[$username]) && password_verify($password, $users[$username]);
}

function encrypt($data, $key) {
    $key = substr(hash('sha256', $key, true), 0, 16); // 取密钥的前 16 字节
    $data = base64_encode($data); // 简单编码
    $encrypted = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $encrypted .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return base64_encode($encrypted);
}

function decrypt($data, $key) {
    $key = substr(hash('sha256', $key, true), 0, 16); // 取密钥的前 16 字节
    $data = base64_decode($data);
    $decrypted = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $decrypted .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return base64_decode($decrypted);
}

if (isset($_POST['register'])) {
    $success = registerUser($_POST['username'], $_POST['password']);
    if ($success) {
        $_SESSION['username'] = $_POST['username'];
        header("Location: index.php");
        exit();
    } else {
        $error = "用户名已被注册";
    }
}

if (isset($_POST['login'])) {
    $success = authenticateUser($_POST['username'], $_POST['password']);
    if ($success) {
        $_SESSION['username'] = $_POST['username'];
        header("Location: index.php");
        exit();
    } else {
        $error = "用户名或密码错误";
    }
}

if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}

if (isset($_POST['delete'])) {
    $username = $_SESSION['username'];
    $users = getData($GLOBALS['filename']);
    unset($users[$username]);
    saveData($GLOBALS['filename'], $users);
    session_destroy();
    header("Location: index.php");
    exit();
}

if (isset($_POST['send_message'])) {
    $message = $_POST['message'];
    if (!empty($message)) {
        $encrypted_message = encrypt($message, $encryption_key);
        $chats = getData($chatFilename);
        $chats[] = ['user' => $_SESSION['username'], 'message' => $encrypted_message];
        saveData($chatFilename, $chats);
    }
    header("Location: index.php");
    exit();
}

if (isset($_GET['action']) && $_GET['action'] === 'fetch_chats') {
    header('Content-Type: application/json');
    echo json_encode(array_map(function($chat) {
        return [
            'user' => htmlspecialchars($chat['user']),
            'message' => htmlspecialchars(decrypt($chat['message'], $GLOBALS['encryption_key']))
        ];
    }, getData($chatFilename)));
    exit();
}

$loggedIn = isset($_SESSION['username']);
$currentUser = $loggedIn ? $_SESSION['username'] : '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>聊天系统</title>
    <link rel="stylesheet" href="styles.css">
    <script>
        function confirmAction(action) {
            let message = '';
            if (action === 'logout') {
                message = '你确定要登出吗？';
            } else if (action === 'delete') {
                message = '你确定要删除账户吗？此操作不可恢复。';
            }
            return confirm(message);
        }

        function fetchChats() {
            fetch('index.php?action=fetch_chats')
                .then(response => response.json())
                .then(data => {
                    const chatbox = document.getElementById('chatbox');
                    chatbox.innerHTML = '';
                    data.forEach(chat => {
                        const messageElement = document.createElement('div');
                        messageElement.className = 'message';
                        if (chat.user === '<?php echo htmlspecialchars($currentUser); ?>') {
                            messageElement.classList.add('user');
                        } else {
                            messageElement.classList.add('other');
                        }
                        messageElement.innerHTML = `<div class="content"><strong>${chat.user}</strong>: ${chat.message}</div>`;
                        chatbox.appendChild(messageElement);
                    });
                });
        }

        document.addEventListener('DOMContentLoaded', function() {
            if (<?php echo $loggedIn ? 'true' : 'false'; ?>) {
                fetchChats(); // 初次加载时拉取聊天记录
                setInterval(fetchChats, 5000); // 每5秒自动拉取一次
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <?php if (!$loggedIn): ?>
            <div class="login-container">
                <div class="login-form">
                    <h2>登录</h2>
                    <form method="post">
                        <input type="text" name="username" placeholder="用户名" required>
                        <input type="password" name="password" placeholder="密码" required>
                        <input type="submit" name="login" value="登录" class="login-btn">
                        <input type="submit" name="register" value="注册" class="register-btn">
                        <?php if (isset($error)): ?><div class="error"><?php echo $error; ?></div><?php endif; ?>
                    </form>
                </div>
            </div>
        <?php else: ?>
            <div class="sidebar">
                <div class="username-display">
                    <?php echo htmlspecialchars($currentUser); ?>
                </div>
                <form method="post" onsubmit="return confirmAction('logout');">
                    <input type="submit" name="logout" value="登出" class="logout">
                </form>
                <form method="post" onsubmit="return confirmAction('delete');">
                    <input type="submit" name="delete" value="删除账户" class="delete">
                </form>
                <button id="sync-button" onclick="fetchChats()">同步消息</button>
            </div>
            <div class="chat-window">
                <div class="chatbox" id="chatbox">
                    <!-- 消息会在这里动态加载 -->
                </div>
                <div class="input-container">
                    <form method="post">
                        <textarea name="message" placeholder="输入消息..."></textarea>
                        <input type="submit" name="send_message" value="发送">
                    </form>
                </div>
            </div>
        <?php endif; ?>
    </div>
    <script src="scripts.js"></script>
</body>
</html>