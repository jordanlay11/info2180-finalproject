<?php
declare(strict_types=1);
require_once 'db_user_management.php';

if (!validateSession()) {
    http_response_code(401);
    exit('Unauthorized');
}

header('Content-Type: application/json');
echo json_encode([
    'token' => generateCsrfToken()
]);
