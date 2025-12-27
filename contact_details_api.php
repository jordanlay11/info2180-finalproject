<?php
declare(strict_types=1);
require_once 'db_user_management.php';

if (!validateSession()) {
    sendJsonResponse(['success' => false, 'message' => 'Unauthorized'], 401);
}

$method = $_SERVER['REQUEST_METHOD'];

//  GET: Contact details + notes 
if ($method === 'GET') {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if ($id <= 0) {
        sendJsonResponse(['success' => false, 'message' => 'Invalid contact ID'], 400);
    }

    $contact = getContactById($id);
    $notes = getNotesByContactId($id);

    if (!$contact) {
        sendJsonResponse(['success' => false, 'message' => 'Contact not found'], 404);
    }

    sendJsonResponse([
        'success' => true,
        'data' => [
            'contact' => $contact,
            'notes' => $notes
        ]
    ]);
}

// POST: Update or Add Note
if ($method === 'POST') {
    requireValidCsrfToken();

    $action = $_POST['action'] ?? '';
    $contactId = isset($_POST['contact_id']) ? (int) $_POST['contact_id'] : 0;

    if ($contactId <= 0) {
        sendJsonResponse(['success' => false, 'message' => 'Invalid contact ID'], 400);
    }

    switch ($action) {
        case 'assign_me':
            // assign to currently logged-in user
            $assignedUser = $_SESSION['user_id'] ?? null;
            $result = updateContactAssignment($contactId, $assignedUser);
            break;

        case 'assign':
            $assignedTo = isset($_POST['assigned_to']) ? (int) $_POST['assigned_to'] : null;
            $result = updateContactAssignment($contactId, $assignedTo);
            break;

        case 'change_type':
            $newType = $_POST['type'] ?? '';
            $result = updateContactType($contactId, $newType);
            break;

        case 'add_note':
            $comment = $_POST['comment'] ?? '';
            $result = createNote($contactId, $comment);
            break;

        default:
            sendJsonResponse(['success' => false, 'message' => 'Invalid action'], 400);
    }

    $status = $result['success'] ? 200 : 400;
    sendJsonResponse($result, $status);
}

sendJsonResponse(['success' => false, 'message' => 'Method not allowed'], 405);
