<?php
declare(strict_types=1);

require_once 'db_user_management.php';

if (!validateSession()) {
    sendJsonResponse(['success' => false, 'message' => 'Unauthorized'], 401);
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendJsonResponse(['success' => false, 'message' => 'Method not allowed'], 405);
}

// GET list contacts
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $filter = $_GET['filter'] ?? 'all';
    $userId = $_SESSION['user_id'] ?? null;

    $contacts = getContacts($filter, $userId);

    sendJsonResponse([
        'success' => true,
        'data' => $contacts
    ]);
}

// POST create a new contact
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireValidCsrfToken();
    $data = [
        'title'       => $_POST['title']       ?? '',
        'firstname'   => $_POST['firstname']   ?? '',
        'lastname'    => $_POST['lastname']    ?? '',
        'email'       => $_POST['email']       ?? '',
        'telephone'   => $_POST['telephone']   ?? '',
        'company'     => $_POST['company']     ?? '',
        'type'        => ($_POST['type'] ?? '') === 'support' ? 'Support' : 'Sales Lead',
        'assigned_to' => $_POST['assignedTo']  ?? null,
    ];

    $result = createContact($data);

    $status = $result['success'] ? 200 : 400;
    sendJsonResponse($result, $status);
}
