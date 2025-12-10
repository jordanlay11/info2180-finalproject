# Dolphin CRM – INFO2180 Project 2

This is a simple CRM (Customer Relationship Management) system built as a group project for INFO2180. It allows admin and member users to manage contacts, assign leads, update contact types, and add internal notes via a dynamic AJAX-driven interface.

## Technologies Used
- HTML/CSS
- JavaScript (AJAX)
- PHP (with security best practices)
- MySQL (schema provided)
- Session management and CSRF protection

---

## Setup Instructions

1. Clone or download the project folder
2. Import the `schema.sql` file into your MySQL database
3. Create a `.env` file or set the following environment variables in your server config:
   - `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`
4. Start the PHP server or load through XAMPP/Localhost
5. Default login:  
   - **Email:** `admin@project2.com`  
   - **Password:** `password123` *(hashed with Argon2id)*

---

## Team Roles & Contributions

- **[Member/s A Name]**
  - Designed the HTML structure and page layout
  - Created the CSS styles for the UI
  - Built form sections for users and contacts

- **[Member/s B Name]**
  - Built database interaction functions in PHP
  - Managed session handling and role logic
  - Handled user creation and login functions

- **Tramonique Wellington**
  - Developed all AJAX logic and JavaScript integration
  - Built PHP API files to support AJAX actions
  - Added CSRF token generation and validation
  - Secured API routes using session and role checks
  - Ensured dynamic content loading and real-time form submissions

---

## Developer Notes

### Tramonique Wellington

Although my assigned role was **AJAX integration**, most frontend interactions (e.g., contact filtering, user creation, viewing contact details, adding notes) could not be completed without backend support. To ensure the AJAX functionality worked correctly, I also implemented supporting PHP APIs.

**Key contributions:**
- Wrote all AJAX request handlers in `script.js` (load contacts, filter, form submissions)
- Created the following PHP API files to support AJAX actions:
  - `contacts_api.php`
  - `users_api.php`
  - `contact_details_api.php`
  - `csrf_token.php`
- Enforced **session validation**, **role-based access**, and **CSRF token checks**
- Integrated dynamic contact filtering, form submission, and real-time table updates

These additions ensured that all features could function asynchronously and securely, as required by the project.

