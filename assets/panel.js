(function() {
    'use strict';

    const apiEndpoint = document.querySelector('meta[name="5x-api-endpoint"]').getAttribute('content');
    const token = localStorage.getItem('admin_token');
    
    let currentUser = null;

    if (!token) {
        window.location.href = '/admin';
        return;
    }

    async function verifyAuth() {
        try {
            const response = await fetch(`${apiEndpoint}/verify`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                localStorage.removeItem('admin_token');
                window.location.href = '/admin';
                return;
            }
            
            const data = await response.json();
            currentUser = data;
            
            document.getElementById('username-display').textContent = data.username;
            
            if (data.user_id === 1) {
                document.getElementById('users-tab').style.display = 'flex';
            }
        } catch (err) {
            localStorage.removeItem('admin_token');
            window.location.href = '/admin';
        }
    }

    document.getElementById('logout-btn').addEventListener('click', async () => {
        try {
            await fetch(`${apiEndpoint}/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        } catch (err) {}
        
        localStorage.removeItem('admin_token');
        window.location.href = '/admin';
    });

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(`${tabId}-tab${tabId === 'users' ? '-content' : ''}`).classList.add('active');
            
            if (tabId === 'files') {
                loadFiles();
            } else if (tabId === 'users') {
                loadUsers();
            }
        });
    });

    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const privateCheckbox = document.getElementById('private-checkbox');

    uploadArea.addEventListener('click', () => fileInput.click());

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragging');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragging');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragging');
        
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    async function handleFileUpload(file) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('is_private', privateCheckbox.checked ? 'true' : 'false');
        
        try {
            const response = await fetch(`${apiEndpoint}/upload`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });
            
            if (!response.ok) {
                alert('Upload failed');
                return;
            }
            
            const data = await response.json();
            
            showUrlModal(window.location.origin + '/' + data.download_url);
            
            loadFiles();
            
            fileInput.value = '';
            privateCheckbox.checked = false;
        } catch (err) {
            alert('Upload failed');
        }
    }

    async function loadFiles() {
        const filesList = document.getElementById('files-list');
        filesList.innerHTML = '<div class="loading">Loading files...</div>';
        
        try {
            const response = await fetch(`${apiEndpoint}/files`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                filesList.innerHTML = '<div class="empty-state"><p>Error loading files</p></div>';
                return;
            }
            
            const data = await response.json();
            
            if (data.files.length === 0) {
                filesList.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24">
                            <path d="M13,9V3.5L18.5,9M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6Z"/>
                        </svg>
                        <p>No files available</p>
                    </div>
                `;
                return;
            }
            
            filesList.innerHTML = '';
            
            data.files.reverse().forEach(file => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                
                const uploadDate = new Date(file.uploaded_at);
                const fileSize = formatFileSize(file.size);
                
                let downloadUrl = `${window.location.origin}/${file.original_filename}?id=${currentUser.user_id}`;
                if (file.is_private) {
                    downloadUrl += `&token=${file.token}`;
                }
                
                fileItem.innerHTML = `
                    <div class="file-info">
                        <div class="file-icon">
                            <svg viewBox="0 0 24 24">
                                <path d="M13,9V3.5L18.5,9M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6Z"/>
                            </svg>
                        </div>
                        <div class="file-details">
                            <div class="file-name">
                                ${escapeHtml(file.original_filename)}
                                ${file.is_private ? `
                                    <span class="private-badge">
                                        <svg viewBox="0 0 24 24">
                                            <path d="M12,17A2,2 0 0,0 14,15C14,13.89 13.1,13 12,13A2,2 0 0,0 10,15A2,2 0 0,0 12,17M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V10C4,8.89 4.9,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z"/>
                                        </svg>
                                        Private
                                    </span>
                                ` : ''}
                            </div>
                            <div class="file-meta">${fileSize} • ${formatDate(uploadDate)}</div>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="action-btn" data-url="${escapeHtml(downloadUrl)}" title="Show URL">
                            <svg viewBox="0 0 24 24">
                                <path d="M3.9,12C3.9,10.29 5.29,8.9 7,8.9H11V7H7A5,5 0 0,0 2,12A5,5 0 0,0 7,17H11V15.1H7C5.29,15.1 3.9,13.71 3.9,12M8,13H16V11H8V13M17,7H13V8.9H17C18.71,8.9 20.1,10.29 20.1,12C20.1,13.71 18.71,15.1 17,15.1H13V17H17A5,5 0 0,0 22,12A5,5 0 0,0 17,7Z"/>
                            </svg>
                        </button>
                        <a href="${downloadUrl}" download class="action-btn" title="Download">
                            <svg viewBox="0 0 24 24">
                                <path d="M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z"/>
                            </svg>
                        </a>
                        <button class="action-btn delete" data-file-id="${file.file_id}" title="Delete">
                            <svg viewBox="0 0 24 24">
                                <path d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/>
                            </svg>
                        </button>
                    </div>
                `;
                
                const urlBtn = fileItem.querySelector('.action-btn[data-url]');
                urlBtn.addEventListener('click', () => {
                    showUrlModal(urlBtn.dataset.url);
                });
                
                const deleteBtn = fileItem.querySelector('.action-btn.delete');
                deleteBtn.addEventListener('click', async () => {
                    if (!confirm('Really delete this file?')) return;
                    
                    try {
                        const response = await fetch(`${apiEndpoint}/files/${deleteBtn.dataset.fileId}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        });
                        
                        if (response.ok) {
                            loadFiles();
                        } else {
                            alert('Delete failed');
                        }
                    } catch (err) {
                        alert('Delete failed');
                    }
                });
                
                filesList.appendChild(fileItem);
            });
        } catch (err) {
            filesList.innerHTML = '<div class="empty-state"><p>Error loading files</p></div>';
        }
    }

    async function loadUsers() {
        const usersList = document.getElementById('users-list');
        usersList.innerHTML = '<div class="loading">Loading users...</div>';
        
        try {
            const response = await fetch(`${apiEndpoint}/users`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                usersList.innerHTML = '<div class="empty-state"><p>Error loading users</p></div>';
                return;
            }
            
            const data = await response.json();
            
            if (data.users.length === 0) {
                usersList.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24">
                            <path d="M12,4A4,4 0 0,1 16,8A4,4 0 0,1 12,12A4,4 0 0,1 8,8A4,4 0 0,1 12,4M12,14C16.42,14 20,15.79 20,18V20H4V18C4,15.79 7.58,14 12,14Z"/>
                        </svg>
                        <p>No users available</p>
                    </div>
                `;
                return;
            }
            
            usersList.innerHTML = '';
            
            data.users.forEach(user => {
                const userItem = document.createElement('div');
                userItem.className = 'user-item';
                
                const createdDate = new Date(user.created_at);
                
                userItem.innerHTML = `
                    <div class="user-info">
                        <div class="user-avatar">
                            <svg viewBox="0 0 24 24">
                                <path d="M12,4A4,4 0 0,1 16,8A4,4 0 0,1 12,12A4,4 0 0,1 8,8A4,4 0 0,1 12,4M12,14C16.42,14 20,15.79 20,18V20H4V18C4,15.79 7.58,14 12,14Z"/>
                            </svg>
                        </div>
                        <div class="user-details">
                            <h3>${escapeHtml(user.username)}</h3>
                            <p>ID: ${user.user_id} • Created: ${formatDate(createdDate)}</p>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="action-btn delete" data-user-id="${user.user_id}" title="Delete">
                            <svg viewBox="0 0 24 24">
                                <path d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/>
                            </svg>
                        </button>
                    </div>
                `;
                
                const deleteBtn = userItem.querySelector('.action-btn.delete');
                deleteBtn.addEventListener('click', async () => {
                    if (!confirm('Really delete this user?')) return;
                    
                    try {
                        const response = await fetch(`${apiEndpoint}/users/${deleteBtn.dataset.userId}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        });
                        
                        if (response.ok) {
                            loadUsers();
                        } else {
                            alert('Delete failed');
                        }
                    } catch (err) {
                        alert('Delete failed');
                    }
                });
                
                usersList.appendChild(userItem);
            });
        } catch (err) {
            usersList.innerHTML = '<div class="empty-state"><p>Error loading users</p></div>';
        }
    }

    function showUrlModal(url) {
        const modal = document.getElementById('url-modal');
        const urlDisplay = document.getElementById('url-display');
        
        urlDisplay.textContent = url;
        modal.classList.add('active');
    }

    document.getElementById('close-modal').addEventListener('click', () => {
        document.getElementById('url-modal').classList.remove('active');
    });

    document.getElementById('url-modal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('url-modal')) {
            document.getElementById('url-modal').classList.remove('active');
        }
    });

    document.getElementById('copy-url-btn').addEventListener('click', () => {
        const urlDisplay = document.getElementById('url-display');
        navigator.clipboard.writeText(urlDisplay.textContent);
        
        const btn = document.getElementById('copy-url-btn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z"/></svg>Copied!';
        
        setTimeout(() => {
            btn.innerHTML = originalText;
        }, 2000);
    });

    document.getElementById('create-user-btn').addEventListener('click', () => {
        document.getElementById('create-user-modal').classList.add('active');
    });

    document.getElementById('close-user-modal').addEventListener('click', () => {
        document.getElementById('create-user-modal').classList.remove('active');
    });

    document.getElementById('create-user-modal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('create-user-modal')) {
            document.getElementById('create-user-modal').classList.remove('active');
        }
    });

    document.getElementById('create-user-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('new-username').value.trim();
        const password = document.getElementById('new-password').value;
        const errorMsg = document.getElementById('user-error-message');
        
        errorMsg.classList.remove('visible');
        
        try {
            const response = await fetch(`${apiEndpoint}/users`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                if (data.code === '5xsoftware.username_exists') {
                    errorMsg.textContent = 'Username already exists';
                } else {
                    errorMsg.textContent = 'Error creating user';
                }
                errorMsg.classList.add('visible');
                return;
            }
            
            document.getElementById('create-user-modal').classList.remove('active');
            document.getElementById('create-user-form').reset();
            loadUsers();
        } catch (err) {
            errorMsg.textContent = 'Network error';
            errorMsg.classList.add('visible');
        }
    });

    window.showUrl = showUrlModal;

    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    }

    function formatDate(date) {
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const year = date.getFullYear();
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return `${day}.${month}.${year} ${hours}:${minutes}`;
    }

    verifyAuth();
    loadFiles();

})();