document.addEventListener('DOMContentLoaded', () => {

    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();

            const formData = new FormData(loginForm);

            fetch('login_api.php', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(result => {
                if (result.success) {
                    window.location.href = 'index.html';
                } else {
                    const errorDiv = document.getElementById('loginError');
                    if (errorDiv) {
                        errorDiv.textContent = result.error || 'Login failed.';
                        errorDiv.style.display = 'block';
                    } else {
                        alert(result.error || 'Login failed.');
                    }
                }
            })
            .catch(err => {
                console.error('Login error:', err);
                alert('An error occurred while logging in.');
            });
        });
    }
    
    const sections = document.querySelectorAll('section');
    
    const showSection = (hash) => {
        sections.forEach(s => s.style.display = 'none');
        const target = document.getElementById(hash.slice(1));
        if (target) target.style.display = 'block';
    };

    showSection(window.location.hash || '#home');

    document.querySelectorAll('nav li a').forEach(link =>
        link.addEventListener('click', () => {
            const hash = link.getAttribute('href');
            showSection(hash);
            window.location.hash = hash;
        })
    );

    window.addEventListener('hashchange', () => showSection(window.location.hash || '#home'));

    // ===== AJAX PART STARTS HERE =====

    const contactTableBody = document.getElementById('contactTableBody');
    const contactForm = document.getElementById('contactForm');

    fetch('csrf_token.php')
        .then(res => res.json())
        .then(data => {
            document.getElementById('contact_csrf_token').value = data.token;
        });

    function loadContacts(filter = 'all') {
        fetch(`contacts_api.php?filter=${encodeURIComponent(filter)}`)
            .then(response => response.json())
            .then(data => {
                if (!data.success) {
                    console.error(data.message);
                    contactTableBody.innerHTML = `<tr><td colspan="4">${data.message}</td></tr>`;
                    return;
                }

                const contacts = data.data;
                if (!contacts || contacts.length === 0) {
                    contactTableBody.innerHTML = `<tr><td colspan="4">No contacts found.</td></tr>`;
                    return;
                }

                contactTableBody.innerHTML = contacts.map(c => `
                    <tr>
                        <td>${c.firstname} ${c.lastname}</td>
                        <td>${c.email}</td>
                        <td>${c.company || ''}</td>
                        <td>${c.type}</td>
                    </tr>
                `).join('');
            })
            .catch(err => {
                console.error('Error loading contacts:', err);
                contactTableBody.innerHTML = `<tr><td colspan="4">Error loading contacts.</td></tr>`;
            });
    }

    // Load all contacts when the page first opens
    loadContacts('all');

    // Hook up filter links
    const filterLinks = {
        '#all': 'all',
        '#salesLead': 'sales_leads',
        '#support': 'support',
        '#assignedToMe': 'assigned_to_me'
    };

    document.querySelectorAll('#contactFilter a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const hash = link.getAttribute('href');
            const filter = filterLinks[hash] || 'all';
            loadContacts(filter);
        });
    });

    // Handle New Contact form submit via AJAX
    contactForm.addEventListener('submit', (e) => {
        e.preventDefault();

        const formData = new FormData(contactForm);

        fetch('contacts_api.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(result => {
            alert(result.message);

            if (result.success) {
                contactForm.reset();
                loadContacts('all');
                // Refresh token
                fetch('csrf_token.php')
                    .then(res => res.json())
                    .then(data => {
                        document.getElementById('contact_csrf_token').value = data.token;
                    });

            }
        })
        .catch(err => {
            console.error('Error saving contact:', err);
            alert('An error occurred while saving the contact.');
        });
    });

    const userTableBody = document.getElementById('userTableBody');
    const addUserForm = document.getElementById('addUserForm');

    fetch('csrf_token.php')
        .then(res => res.json())
        .then(data => {
            document.getElementById('csrf_token').value = data.token;
        });

    // Fetch and load users
    function loadUsers() {
        fetch('users_api.php')
            .then(res => res.json())
            .then(result => {
                if (!result.success) {
                    userTableBody.innerHTML = `<tr><td colspan="4">${result.message}</td></tr>`;
                    return;
                }

                userTableBody.innerHTML = result.data.map(user => `
                    <tr>
                        <td>${user.firstname} ${user.lastname}</td>
                        <td>${user.email}</td>
                        <td>${user.role}</td>
                        <td>${user.created_at}</td>
                    </tr>
                `).join('');
            })
            .catch(err => {
                console.error('Error loading users:', err);
                userTableBody.innerHTML = `<tr><td colspan="4">Error loading users</td></tr>`;
            });
    }

    // Handle user creation
    addUserForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(addUserForm);

        fetch('users_api.php', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(result => {
            alert(result.message);
            if (result.success) {
                addUserForm.reset();
                loadUsers();
                // Refresh token
                fetch('csrf_token.php')
                    .then(res => res.json())
                    .then(data => {
                        document.getElementById('csrf_token').value = data.token;
                    });
            }
        })
        .catch(err => {
            console.error('Error creating user:', err);
            alert('Error creating user.');
        });
    });
    loadUsers();
});