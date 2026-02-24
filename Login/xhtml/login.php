<?php

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

define('DB_HOST', 'localhost');
define('DB_NAME', 'mi_app');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');


if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Método no permitido.']);
    exit;
}


$email    = trim(filter_input(INPUT_POST, 'email',    FILTER_SANITIZE_EMAIL));
$password = trim(filter_input(INPUT_POST, 'password', FILTER_DEFAULT));
$remember = filter_input(INPUT_POST, 'remember', FILTER_VALIDATE_INT) === 1;


$errors = [];

if (empty($email)) {
    $errors[] = 'El correo es requerido.';
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'El correo no tiene un formato válido.';
}

if (empty($password)) {
    $errors[] = 'La contraseña es requerida.';
} elseif (strlen($password) < 6) {
    $errors[] = 'La contraseña debe tener al menos 6 caracteres.';
}

if (!empty($errors)) {
    http_response_code(422);
    echo json_encode(['success' => false, 'message' => implode(' ', $errors)]);
    exit;
}


try {
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=%s',
        DB_HOST, DB_NAME, DB_CHARSET
    );
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor.']);
    exit;
}


try {
    $stmt = $pdo->prepare('SELECT id, name, password, active FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error al consultar la base de datos.']);
    exit;
}

if (!$user) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Credenciales incorrectas.']);
    exit;
}

if (!$user['active']) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Cuenta desactivada. Contacta al administrador.']);
    exit;
}

if (!password_verify($password, $user['password'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Credenciales incorrectas.']);
    exit;
}

session_start();
session_regenerate_id(true);          

$_SESSION['user_id']   = $user['id'];
$_SESSION['user_name'] = $user['name'];
$_SESSION['user_email'] = $email;


if ($remember) {
    $token = bin2hex(random_bytes(32));
    
    setcookie('remember_token', $token, [
        'expires'  => time() + 60 * 60 * 24 * 30,
        'path'     => '/',
        'secure'   => true,         
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

echo json_encode([
    'success'  => true,
    'message'  => '¡Bienvenido, ' . htmlspecialchars($user['name']) . '!',
    'redirect' => 'dashboard.php',
]);
exit;