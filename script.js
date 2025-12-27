document.addEventListener('DOMContentLoaded', () => {
    //Login
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
                    window.location.href = 'dashboard.html';
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

    //Logout
    const logoutLink = document.getElementById('logoutLink');
    if (logoutLink) {
        logoutLink.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = 'logout.php';
        });
    }

    //Navigate HTML sections
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
    let currentContactId = null;
    let currentFilter = 'all';

    fetch('csrf_token.php')
        .then(res => res.json())
        .then(data => {
            document.getElementById('contact_csrf_token').value = data.token;
        });

    function loadContacts(filter = 'all') {
        currentFilter = filter;
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

                contactTableBody.innerHTML = contacts.map(c => {
                    const t = (c.type || '').toLowerCase();
                    const typeClass = t.includes('support') ? 'type-support' : (t.includes('sales') ? 'type-sales' : '');
                    const typeLabel = c.type || '';
                    return `
                    <tr>
                        <td>${c.firstname} ${c.lastname}</td>
                        <td>${c.email}</td>
                        <td>${c.company || ''}</td>
                        <td><span class="contact-type ${typeClass}">${typeLabel}</span></td>
                        <td><a href="#viewUser" class="viewContact" data-id="${c.id}">View</a></td>
                    </tr>
                `}).join('');
            })
            .catch(err => {
                console.error('Error loading contacts:', err);
                contactTableBody.innerHTML = `<tr><td colspan="4">Error loading contacts.</td></tr>`;
            });
    }

    // Load all contacts when the page first opens
    loadContacts('all');

    // Click handler for "View" links using event delegation
    contactTableBody.addEventListener('click', (e) => {
        const el = e.target;
        if (el.matches && el.matches('a.viewContact')) {
            e.preventDefault();
            const contactId = el.dataset.id;
            if (!contactId) return;
            // show the view section and load details
            showSection('#viewUser');
            window.location.hash = '#viewUser';
            loadContactDetails(contactId);
        }
    });

    // Fetch and populate contact details and notes
    function loadContactDetails(contactId) {
        fetch(`contact_details_api.php?id=${encodeURIComponent(contactId)}`)
            .then(res => res.json())
            .then(result => {
                if (!result.success) {
                    console.error('Failed to load contact details:', result.message);
                    return;
                }

                // API returns { success: true, data: { contact: ..., notes: [...] } }
                const payload = result.data || {};
                const contact = payload.contact || {};

                // store current contact id for actions like adding notes
                currentContactId = contactId;

                // Populate basic fields (use safe defaults)
                const nameEl = document.getElementById('contactName');
                const createdEl = document.getElementById('createdOn');
                const updatedEl = document.getElementById('updatedOn');
                const emailEl = document.getElementById('contactEmail');
                const companyEl = document.getElementById('contactCompany');
                const telEl = document.getElementById('contactTelephone');
                const assignedEl = document.getElementById('contactAssignedTo');

                if (nameEl) nameEl.textContent = `${contact.firstname || ''} ${contact.lastname || ''}`.trim() || '—';
                if (createdEl) createdEl.textContent = `Created on ${contact.created_at || '—'}`;
                if (updatedEl) updatedEl.textContent = `Updated on ${contact.updated_at || '—'}`;
                if (emailEl) emailEl.textContent = contact.email || '—';
                if (companyEl) companyEl.textContent = contact.company || '—';
                if (telEl) telEl.textContent = contact.telephone || '—';
                // assigned_to may be an object or string
                if (assignedEl) {
                    assignedEl.textContent = (contact.assigned_to_name || contact.assigned_to || 'Unassigned');
                }

                // Configure Assign to Me button
                const assignBtn = document.getElementById('assignToME');
                const csrfEl = document.getElementById('contact_csrf_token');
                if (assignBtn) {
                    assignBtn.onclick = (evt) => {
                        evt.preventDefault();
                        if (!currentContactId) return;
                        const fd = new FormData();
                        fd.append('action', 'assign_me');
                        fd.append('contact_id', currentContactId);
                        if (csrfEl) fd.append('csrf_token', csrfEl.value);

                        assignBtn.disabled = true;
                        fetch('contact_details_api.php', { method: 'POST', body: fd })
                            .then(r => r.json())
                            .then(res => {
                                alert(res.message || (res.success ? 'Assigned' : 'Error'));
                                if (res.success) {
                                    loadContactDetails(currentContactId);
                                    loadContacts(currentFilter);
                                }
                            })
                            .catch(err => {
                                console.error('Assign error:', err);
                                alert('Error assigning contact.');
                            })
                            .finally(() => assignBtn.disabled = false);
                    };
                }

                // Switch To button message(toggle type)
                const switchBtn = document.getElementById('switchTo');
                if (switchBtn) {
                    // Determine target type
                    const currentType = (contact.type || '').toLowerCase();
                    const targetType = currentType.includes('support') ? 'Sales Lead' : 'Support';
                    switchBtn.textContent = `⇄ Switch to ${targetType}`;
                    // set color class on the button according to what it will switch to
                    switchBtn.classList.remove('btn-sales', 'btn-support');
                    if (targetType === 'Support') switchBtn.classList.add('btn-support');
                    else switchBtn.classList.add('btn-sales');

                    switchBtn.onclick = (evt) => {
                        evt.preventDefault();
                        if (!currentContactId) return;
                        if (!confirm(`Switch contact to ${targetType}?`)) return;

                        const fd = new FormData();
                        fd.append('action', 'change_type');
                        fd.append('contact_id', currentContactId);
                        fd.append('type', targetType);
                        if (csrfEl) fd.append('csrf_token', csrfEl.value);

                        switchBtn.disabled = true;
                        fetch('contact_details_api.php', { method: 'POST', body: fd })
                            .then(r => r.json())
                            .then(res => {
                                alert(res.message || (res.success ? 'Updated' : 'Error'));
                                if (res.success) {
                                    loadContactDetails(currentContactId);
                                    loadContacts(currentFilter);
                                }
                            })
                            .catch(err => {
                                console.error('Change type error:', err);
                                alert('Error changing type.');
                            })
                            .finally(() => switchBtn.disabled = false);
                    };
                }

                // Populate notes
                const notesContainer = document.getElementById('notesList');
                if (notesContainer) {
                    notesContainer.innerHTML = '';
                    const notes = payload.notes || [];
                    if (notes.length === 0) {
                        notesContainer.innerHTML = '<p>No notes for this contact.</p>';
                    } else {
                        notes.forEach(n => {
                            const div = document.createElement('div');
                            div.className = 'noteItem';
                            const by = n.created_by_name || n.created_by || 'Unknown';
                            const when = n.created_at || '';
                            div.innerHTML = `
                                <p>${n.comment || ''}</p>
                                <p class="noteMeta">— ${by} on ${when}</p>
                            `;
                            notesContainer.appendChild(div);
                        });
                    }
                }
            })
            .catch(err => {
                console.error('Error loading contact details:', err);
            });
    }

    // Handle Add Note form submission
    const addNoteForm = document.getElementById('addNote');
    if (addNoteForm) {
        addNoteForm.addEventListener('submit', (e) => {
            e.preventDefault();

            if (!currentContactId) {
                alert('No contact selected.');
                return;
            }

            const textarea = document.getElementById('noteContent');
            const comment = textarea ? textarea.value.trim() : '';
            if (!comment) {
                alert('Please enter a note.');
                return;
            }

            const formData = new FormData();
            formData.append('action', 'add_note');
            formData.append('contact_id', currentContactId);
            formData.append('comment', comment);
            // include csrf token used for contact operations
            const csrfEl = document.getElementById('contact_csrf_token');
            if (csrfEl) formData.append('csrf_token', csrfEl.value);

            fetch('contact_details_api.php', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(result => {
                alert(result.message || (result.success ? 'Note added' : 'Error'));
                if (result.success) {
                    if (textarea) textarea.value = '';
                    // reload notes for this contact
                    loadContactDetails(currentContactId);
                    // refresh token for other forms
                    fetch('csrf_token.php')
                        .then(r => r.json())
                        .then(d => { if (d.token && csrfEl) csrfEl.value = d.token; })
                        .catch(() => {});
                }
            })
            .catch(err => {
                console.error('Error adding note:', err);
                alert('An error occurred while adding the note.');
            });
        });
    }

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
    
    function populateAssignedToDropdown() {
        fetch('users_api.php')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const dropdown = document.getElementById('assigned-to');
                    dropdown.innerHTML = '';

                    const defaultOption = document.createElement('option');
                    defaultOption.value = '';
                    defaultOption.textContent = '-- Select User --';
                    dropdown.appendChild(defaultOption);

                    data.data.forEach(user => {
                        const option = document.createElement('option');
                        option.value = user.id;
                        option.textContent = `${user.firstname} ${user.lastname}`;
                        dropdown.appendChild(option);
                    });
                } else {
                    console.error('Failed to load users:', data.message);
                }
            })
            .catch(error => {
                console.error('Error fetching users:', error);
            });
    }
    loadUsers();
    populateAssignedToDropdown();
});