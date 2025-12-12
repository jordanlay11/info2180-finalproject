<?php
declare(strict_types=1);
require_once 'db_user_management.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid request method.']);
    exit();
}

$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

$result = loginUser($email, $password);

if ($result['success']) {
    echo json_encode(['success' => true]);
} else {
    echo json_encode([
        'success' => false,
        'error' => $result['message'] ?? 'Login failed.'
    ]);
}
