<?php
declare(strict_types=1);

// ==================== CONFIGURATION & DATABASE ====================

// Secure session configuration - must be called before session_start()
function configureSecureSession(): void {
    ini_set('session. cookie_httponly', '1');
    ini_set('session. cookie_secure', '1');
    ini_set('session. cookie_samesite', 'Strict');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', '1800'); // 30 minutes
}

configureSecureSession();
session_start();

// Load configuration from environment variables
function getDbConfig(): array {
    return [
        'host' => getenv('DB_HOST') ?: throw new RuntimeException('DB_HOST environment variable not set'),
        'name' => getenv('DB_NAME') ?: throw new RuntimeException('DB_NAME environment variable not set'),
        'user' => getenv('DB_USER') ?: throw new RuntimeException('DB_USER environment variable not set'),
        'pass' => getenv('DB_PASS') ?: throw new RuntimeException('DB_PASS environment variable not set'),
    ];
}

// Create database connection with singleton pattern
function getDB(): PDO {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $config = getDbConfig();
            $dsn = sprintf(
                "mysql:host=%s;dbname=%s;charset=utf8mb4",
                $config['host'],
                $config['name']
            );
            
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ];
            
            $pdo = new PDO($dsn, $config['user'], $config['pass'], $options);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new RuntimeException('Database connection failed.  Please try again later.');
        }
    }
    
    return $pdo;
}

// ==================== CSRF PROTECTION ====================
function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(? string $token): bool {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function requireValidCsrfToken(): void {
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
    if (! validateCsrfToken($token)) {
        http_response_code(403);
        throw new RuntimeException('Invalid security token.  Please refresh the page and try again.');
    }
}

// ==================== RATE LIMITING ====================
function checkRateLimit(string $identifier, int $maxAttempts = 5, int $windowSeconds = 900): bool {
    $key = 'rate_limit_' . hash('sha256', $identifier);
    
    if (! isset($_SESSION[$key])) {
        $_SESSION[$key] = ['attempts' => 0, 'first_attempt' => time()];
    }
    
    $data = $_SESSION[$key];
    
    // Reset if window has passed
    if (time() - $data['first_attempt'] > $windowSeconds) {
        $_SESSION[$key] = ['attempts' => 1, 'first_attempt' => time()];
        return true;
    }
    
    // Check if max attempts exceeded
    if ($data['attempts'] >= $maxAttempts) {
        return false;
    }
    
    $_SESSION[$key]['attempts']++;
    return true;
}

function resetRateLimit(string $identifier): void {
    $key = 'rate_limit_' .  hash('sha256', $identifier);
    unset($_SESSION[$key]);
}

// ==================== SESSION & AUTHENTICATION ====================
function isLoggedIn(): bool {
    return isset($_SESSION['user_id']) && 
           isset($_SESSION['last_activity']) &&
           (time() - $_SESSION['last_activity']) < 1800; // 30 minute timeout
}

function isAdmin(): bool {
    return isLoggedIn() && isset($_SESSION['role']) && $_SESSION['role'] === 'Admin';
}

function requireLogin(): void {
    if (!isLoggedIn()) {
        $_SESSION = []; // Clear session
        header("Location: login.php");
        exit();
    }
    // Update last activity timestamp
    $_SESSION['last_activity'] = time();
}

function requireAdmin(): void {
    requireLogin();
    if (!isAdmin()) {
        http_response_code(403);
        header("Location: index.php");
        exit();
    }
}

function regenerateSession(): void {
    $oldData = $_SESSION;
    session_regenerate_id(true);
    $_SESSION = $oldData;
}

// ==================== USER FUNCTIONS ====================
function loginUser(string $email, string $password): array {
    // Validate inputs
    $email = filter_var(trim($email), FILTER_VALIDATE_EMAIL);
    if (!$email) {
        return ['success' => false, 'message' => 'Invalid email format'];
    }
    
    // Check rate limiting
    if (! checkRateLimit($email)) {
        error_log("Rate limit exceeded for login attempt: " . hash('sha256', $email));
        return ['success' => false, 'message' => 'Too many login attempts. Please try again in 15 minutes. '];
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT id, firstname, lastname, email, password, role FROM users WHERE email = ?  LIMIT 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        // Use constant-time comparison to prevent timing attacks
        if ($user && password_verify($password, $user['password'])) {
            // Regenerate session ID to prevent session fixation
            regenerateSession();
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['firstname'] = $user['firstname'];
            $_SESSION['lastname'] = $user['lastname'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['last_activity'] = time();
            $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
            
            // Reset rate limit on successful login
            resetRateLimit($email);
            
            // Regenerate CSRF token
            unset($_SESSION['csrf_token']);
            generateCsrfToken();
            
            return ['success' => true, 'message' => 'Login successful'];
        }
        
        return ['success' => false, 'message' => 'Invalid email or password'];
        
    } catch (PDOException $e) {
        error_log("Login error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred.  Please try again later.'];
    }
}

function logoutUser(): void {
    $_SESSION = [];
    
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
    
    session_destroy();
}

function createUser(array $data): array {
    // Validate required fields
    $requiredFields = ['firstname', 'lastname', 'email', 'password', 'role'];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            return ['success' => false, 'message' => "Missing required field: {$field}"];
        }
    }
    
    // Sanitize and validate inputs
    $firstname = sanitizeInput($data['firstname']);
    $lastname = sanitizeInput($data['lastname']);
    $email = filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL);
    $role = in_array($data['role'], ['Admin', 'Member']) ? $data['role'] : 'Member';
    
    if (!$email) {
        return ['success' => false, 'message' => 'Invalid email format'];
    }
    
    if (strlen($firstname) < 2 || strlen($firstname) > 50) {
        return ['success' => false, 'message' => 'First name must be between 2 and 50 characters'];
    }
    
    if (strlen($lastname) < 2 || strlen($lastname) > 50) {
        return ['success' => false, 'message' => 'Last name must be between 2 and 50 characters'];
    }
    
    // Validate password
    $passwordValidation = validatePassword($data['password']);
    if (! $passwordValidation['valid']) {
        return ['success' => false, 'message' => $passwordValidation['message']];
    }
    
    // Hash password with strong settings
    $hashedPassword = password_hash($data['password'], PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ]);
    
    try {
        $db = getDB();
        
        // Check if email already exists
        $checkStmt = $db->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
        $checkStmt->execute([$email]);
        if ($checkStmt->fetchColumn() > 0) {
            return ['success' => false, 'message' => 'An account with this email already exists'];
        }
        
        $stmt = $db->prepare("INSERT INTO users (firstname, lastname, email, password, role, created_at) 
                             VALUES (?, ?, ?, ?, ?, NOW())");
        $stmt->execute([
            $firstname,
            $lastname,
            $email,
            $hashedPassword,
            $role
        ]);
        
        return ['success' => true, 'message' => 'User created successfully', 'id' => (int)$db->lastInsertId()];
        
    } catch (PDOException $e) {
        error_log("User creation error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while creating the user. Please try again. '];
    }
}

function getAllUsers(): array {
    try {
        $db = getDB();
        $stmt = $db->query("SELECT id, firstname, lastname, email, role, created_at FROM users ORDER BY created_at DESC");
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Get all users error: " .  $e->getMessage());
        return [];
    }
}

function getUserById(int $id): ? array {
    if ($id <= 0) {
        return null;
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT id, firstname, lastname, email, role, created_at FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();
        return $user ?: null;
    } catch (PDOException $e) {
        error_log("Get user by ID error: " . $e->getMessage());
        return null;
    }
}

function getAllUsersForDropdown(): array {
    try {
        $db = getDB();
        $stmt = $db->query("SELECT id, CONCAT(firstname, ' ', lastname) as name FROM users ORDER BY firstname");
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Get users for dropdown error: " . $e->getMessage());
        return [];
    }
}

function updateUserPassword(int $userId, string $currentPassword, string $newPassword): array {
    if ($userId <= 0) {
        return ['success' => false, 'message' => 'Invalid user ID'];
    }
    
    $passwordValidation = validatePassword($newPassword);
    if (!$passwordValidation['valid']) {
        return ['success' => false, 'message' => $passwordValidation['message']];
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();
        
        if (!$user || !password_verify($currentPassword, $user['password'])) {
            return ['success' => false, 'message' => 'Current password is incorrect'];
        }
        
        $hashedPassword = password_hash($newPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
        
        $updateStmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
        $updateStmt->execute([$hashedPassword, $userId]);
        
        return ['success' => true, 'message' => 'Password updated successfully'];
        
    } catch (PDOException $e) {
        error_log("Password update error: " .  $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred.  Please try again.'];
    }
}

// ==================== CONTACT FUNCTIONS ====================
function createContact(array $data): array {
    // Validate required fields
    $requiredFields = ['firstname', 'lastname', 'email', 'type'];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            return ['success' => false, 'message' => "Missing required field: {$field}"];
        }
    }
    
    // Sanitize inputs
    $title = isset($data['title']) ? sanitizeInput($data['title']) : '';
    $firstname = sanitizeInput($data['firstname']);
    $lastname = sanitizeInput($data['lastname']);
    $email = filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL);
    $telephone = isset($data['telephone']) ? preg_replace('/[^0-9+\-\s()]/', '', $data['telephone']) : '';
    $company = isset($data['company']) ? sanitizeInput($data['company']) : '';
    $type = in_array($data['type'], ['Sales Lead', 'Support']) ? $data['type'] : 'Sales Lead';
    $assignedTo = isset($data['assigned_to']) ? (int)$data['assigned_to'] : null;
    
    if (!$email) {
        return ['success' => false, 'message' => 'Invalid email format'];
    }
    
    if (! in_array($title, ['', 'Mr', 'Mrs', 'Ms', 'Miss', 'Dr', 'Prof'])) {
        $title = '';
    }
    
    if (! isLoggedIn()) {
        return ['success' => false, 'message' => 'You must be logged in to create contacts'];
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("INSERT INTO contacts 
                             (title, firstname, lastname, email, telephone, company, type, 
                             assigned_to, created_by, created_at, updated_at) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())");
        $stmt->execute([
            $title,
            $firstname,
            $lastname,
            $email,
            $telephone,
            $company,
            $type,
            $assignedTo ?: null,
            $_SESSION['user_id']
        ]);
        
        return ['success' => true, 'message' => 'Contact created successfully', 'id' => (int)$db->lastInsertId()];
        
    } catch (PDOException $e) {
        error_log("Contact creation error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while creating the contact. Please try again.'];
    }
}

function getContacts(string $filter = 'all', ? int $userId = null): array {
    // Whitelist allowed filter values
    $allowedFilters = ['all', 'sales_leads', 'support', 'assigned_to_me'];
    if (! in_array($filter, $allowedFilters)) {
        $filter = 'all';
    }
    
    try {
        $db = getDB();
        
        $query = "SELECT c.id, c. title, c.firstname, c.lastname, c.email, c.telephone, 
                  c. company, c.type, c.assigned_to, c.created_by, c. created_at, c.updated_at,
                  CONCAT(u.firstname, ' ', u.lastname) as assigned_to_name,
                  CONCAT(uc.firstname, ' ', uc.lastname) as created_by_name
                  FROM contacts c
                  LEFT JOIN users u ON c.assigned_to = u. id
                  LEFT JOIN users uc ON c. created_by = uc.id
                  WHERE 1=1";
        
        $params = [];
        
        switch ($filter) {
            case 'sales_leads':
                $query .= " AND c.type = 'Sales Lead'";
                break;
            case 'support':
                $query .= " AND c.type = 'Support'";
                break;
            case 'assigned_to_me':
                if ($userId === null || $userId <= 0) {
                    return [];
                }
                $query .= " AND c.assigned_to = ?";
                $params[] = $userId;
                break;
        }
        
        $query .= " ORDER BY c.updated_at DESC";
        
        $stmt = $db->prepare($query);
        $stmt->execute($params);
        return $stmt->fetchAll();
        
    } catch (PDOException $e) {
        error_log("Get contacts error: " .  $e->getMessage());
        return [];
    }
}

function getContactById(int $id): ? array {
    if ($id <= 0) {
        return null;
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT c.id, c. title, c.firstname, c.lastname, c.email, c.telephone, 
                             c.company, c.type, c. assigned_to, c.created_by, c.created_at, c.updated_at,
                             CONCAT(u. firstname, ' ', u.lastname) as assigned_to_name,
                             CONCAT(uc.firstname, ' ', uc.lastname) as created_by_name
                             FROM contacts c
                             LEFT JOIN users u ON c. assigned_to = u.id
                             LEFT JOIN users uc ON c.created_by = uc. id
                             WHERE c.id = ? ");
        $stmt->execute([$id]);
        $contact = $stmt->fetch();
        return $contact ?: null;
    } catch (PDOException $e) {
        error_log("Get contact by ID error: " . $e->getMessage());
        return null;
    }
}

function updateContactAssignment(int $contactId, ? int $userId): array {
    if ($contactId <= 0) {
        return ['success' => false, 'message' => 'Invalid contact ID'];
    }
    
    if ($userId !== null && $userId <= 0) {
        return ['success' => false, 'message' => 'Invalid user ID'];
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("UPDATE contacts SET assigned_to = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$userId, $contactId]);
        
        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'Contact not found'];
        }
        
        return ['success' => true, 'message' => 'Contact assignment updated successfully'];
        
    } catch (PDOException $e) {
        error_log("Update contact assignment error: " .  $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred.  Please try again.'];
    }
}

function updateContactType(int $contactId, string $newType): array {
    if ($contactId <= 0) {
        return ['success' => false, 'message' => 'Invalid contact ID'];
    }
    
    // Whitelist allowed types
    if (!in_array($newType, ['Sales Lead', 'Support'])) {
        return ['success' => false, 'message' => 'Invalid contact type'];
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("UPDATE contacts SET type = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$newType, $contactId]);
        
        if ($stmt->rowCount() === 0) {
            return ['success' => false, 'message' => 'Contact not found'];
        }
        
        return ['success' => true, 'message' => 'Contact type updated successfully'];
        
    } catch (PDOException $e) {
        error_log("Update contact type error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred. Please try again. '];
    }
}

// ==================== NOTE FUNCTIONS ====================
function createNote(int $contactId, string $comment): array {
    if ($contactId <= 0) {
        return ['success' => false, 'message' => 'Invalid contact ID'];
    }
    
    $comment = trim($comment);
    if (empty($comment)) {
        return ['success' => false, 'message' => 'Note comment cannot be empty'];
    }
    
    if (strlen($comment) > 10000) {
        return ['success' => false, 'message' => 'Note is too long. Maximum 10,000 characters allowed. '];
    }
    
    if (!isLoggedIn()) {
        return ['success' => false, 'message' => 'You must be logged in to add notes'];
    }
    
    // Sanitize comment but preserve newlines
    $comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
    
    try {
        $db = getDB();
        $db->beginTransaction();
        
        // Verify contact exists
        $checkStmt = $db->prepare("SELECT id FROM contacts WHERE id = ?");
        $checkStmt->execute([$contactId]);
        if (! $checkStmt->fetch()) {
            $db->rollBack();
            return ['success' => false, 'message' => 'Contact not found'];
        }
        
        // Insert note
        $stmt = $db->prepare("INSERT INTO notes (contact_id, comment, created_by, created_at) 
                             VALUES (?, ?, ?, NOW())");
        $stmt->execute([$contactId, $comment, $_SESSION['user_id']]);
        $noteId = (int)$db->lastInsertId();
        
        // Update contact's updated_at timestamp
        $stmt2 = $db->prepare("UPDATE contacts SET updated_at = NOW() WHERE id = ? ");
        $stmt2->execute([$contactId]);
        
        $db->commit();
        return ['success' => true, 'message' => 'Note added successfully', 'id' => $noteId];
        
    } catch (PDOException $e) {
        if (isset($db)) {
            $db->rollBack();
        }
        error_log("Note creation error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while adding the note. Please try again.'];
    }
}

function getNotesByContactId(int $contactId): array {
    if ($contactId <= 0) {
        return [];
    }
    
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT n.id, n. contact_id, n. comment, n.created_by, n. created_at,
                             CONCAT(u.firstname, ' ', u. lastname) as created_by_name
                             FROM notes n
                             LEFT JOIN users u ON n.created_by = u. id
                             WHERE n.contact_id = ?
                             ORDER BY n.created_at DESC");
        $stmt->execute([$contactId]);
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Get notes error: " . $e->getMessage());
        return [];
    }
}

// ==================== VALIDATION FUNCTIONS ====================
function validatePassword(string $password): array {
    $errors = [];
    
    if (strlen($password) < 12) {
        $errors[] = 'Password must be at least 12 characters long';
    }
    
    if (strlen($password) > 128) {
        $errors[] = 'Password must not exceed 128 characters';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter';
    }
    
    if (! preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter';
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one number';
    }
    
    if (!preg_match('/[!@#$%^&*()\-_=+\[\]{}|;:\'",. <>?\/\\\\`~]/', $password)) {
        $errors[] = 'Password must contain at least one special character (! @#$%^&*()-_=+[]{}|;:\'",.<>?/\\`~)';
    }
    
    // Check for common passwords
    $commonPasswords = ['password123! ', 'admin123456! ', 'qwerty123456!', 'letmein12345!'];
    if (in_array(strtolower($password), $commonPasswords)) {
        $errors[] = 'Password is too common. Please choose a more secure password';
    }
    
    if (empty($errors)) {
        return ['valid' => true, 'message' => 'Password is valid'];
    }
    
    return ['valid' => false, 'message' => implode('.  ', $errors)];
}

function sanitizeInput(string $input): string {
    $input = trim($input);
    $input = strip_tags($input);
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    return $input;
}

function validateEmail(string $email): bool {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// ==================== AJAX RESPONSE HELPER ====================
function sendJsonResponse(array $data, int $statusCode = 200): void {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    echo json_encode($data, JSON_THROW_ON_ERROR);
    exit();
}

// ==================== SECURITY HEADERS ====================
function setSecurityHeaders(): void {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';");
    
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

// ==================== SESSION VALIDATION ====================
function validateSession(): bool {
    if (!isLoggedIn()) {
        return false;
    }
    
    // Check for session hijacking by validating IP and user agent
    if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
        error_log("Possible session hijacking detected: IP mismatch for user " . ($_SESSION['user_id'] ?? 'unknown'));
        logoutUser();
        return false;
    }
    
    $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $currentUserAgent) {
        error_log("Possible session hijacking detected: User-Agent mismatch for user " . ($_SESSION['user_id'] ?? 'unknown'));
        logoutUser();
        return false;
    }
    
    return true;
}

// Apply security headers on every request
setSecurityHeaders();
?>