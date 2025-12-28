# Dolphin CRM – INFO2180 Project 2

This is a simple CRM (Customer Relationship Management) system built as a group project for INFO2180. It allows admin and member users to manage contacts, assign leads, update contact types, and add internal notes via a dynamic AJAX-driven interface.

## Technologies Used
- HTML/CSS
- JavaScript (AJAX)
- PHP (with security best practices)
- MySQL (schema provided)
- Session management and CSRF protection

---

## Team Roles & Contributions

- **Jordan Laylor**
  - HTML, CSS, View Contact, Notes

- **Nyishia Robinson**
  - Developed "schema.sql" and hashed password for user safety.

- **Ravaughn Marsh**
  - Built the centralized PHP backend (db_user_management.php)
    that acts as the core logic and gateway for all API requests.

- **Tramonique Wellington**
  - Developed AJAX logic and JavaScript integration
  - Built PHP API files to support AJAX actions
  - Added CSRF token generation and validation
  - Secured API routes using session and role checks
  - Ensured dynamic content loading and real-time form submissions

---

## Developer Notes

