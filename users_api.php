<?php
declare(strict_types=1);
require_once 'db_user_management.php';

// Only allow logged-in users
if (!validateSession()) {
    sendJsonResponse(['success' => false, 'message' => 'Unauthorized'], 401);
}

$method = $_SERVER['REQUEST_METHOD'];

// GET USERS 
if ($method === 'GET') {
    $users = getAllUsers();

    $cleanedUsers = array_map(function($u){
        return [
            'id' => $u['id'],
            'firstname' => $u['firstname'],
            'lastname' => $u['lastname'],
            'email' => $u['email'],
            'role' => $u['role'],
            'created_at' => $u['created_at']
        ];
    }, $users);

    sendJsonResponse([
        'success' => true,
        'data' => $cleanedUsers
    ]);
}

// POST CREATE USER 
if ($method === 'POST') {
    if (!isAdmin()) {
        sendJsonResponse(['success' => false, 'message' => 'Forbidden: Admins only'], 403);
    }

    $data = [
        'firstname' => $_POST['firstname'] ?? '',
        'lastname'  => $_POST['lastname'] ?? '',
        'email'     => $_POST['email'] ?? '',
        'password'  => $_POST['password'] ?? '',
        'role'      => $_POST['role'] ?? 'Member',
    ];

    $result = createUser($data);
    $status = $result['success'] ? 200 : 400;

    sendJsonResponse($result, $status);
}

sendJsonResponse(['success' => false, 'message' => 'Method not allowed'], 405);
