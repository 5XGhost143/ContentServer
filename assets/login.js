(function() {
    'use strict';

    console.log('[DEBUG] Login page loaded');

    const token = localStorage.getItem('admin_token');
    console.log('[DEBUG] Token exists:', !!token);

    if (token) {
        console.log('[DEBUG] Token found, checking if valid...');
        const apiEndpoint = document.querySelector('meta[name="5x-api-endpoint"]').getAttribute('content');
        
        fetch(`${apiEndpoint}/verify`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        }).then(response => {
            if (response.ok) {
                console.log('[DEBUG] Token valid, redirecting to /panel');
                window.location.href = '/panel';
            } else {
                console.log('[DEBUG] Token invalid, removing and staying on login');
                localStorage.removeItem('admin_token');
            }
        }).catch(err => {
            console.log('[DEBUG] Token verification error:', err);
            localStorage.removeItem('admin_token');
        });
    }

    const toggleButton = document.querySelector('.toggle-password');
    const passwordInput = document.getElementById('password');
    const eyeIcon = document.getElementById('eye-icon');
    const form = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');

    const eyeVisiblePath = 'M12,9A3,3 0 0,0 9,12A3,3 0 0,0 12,15A3,3 0 0,0 15,12A3,3 0 0,0 12,9M12,17A5,5 0 0,1 7,12A5,5 0 0,1 12,7A5,5 0 0,1 17,12A5,5 0 0,1 12,17M12,4.5C7,4.5 2.73,7.61 1,12C2.73,16.39 7,19.5 12,19.5C17,19.5 21.27,16.39 23,12C21.27,7.61 17,4.5 12,4.5Z';
    const eyeHiddenPath = 'M11.83,9L15,12.16C15,12.11 15,12.05 15,12A3,3 0 0,0 12,9C11.94,9 11.89,9 11.83,9M7.53,9.8L9.08,11.35C9.03,11.56 9,11.77 9,12A3,3 0 0,0 12,15C12.22,15 12.44,14.97 12.65,14.92L14.2,16.47C13.53,16.8 12.79,17 12,17A5,5 0 0,1 7,12C7,11.21 7.2,10.47 7.53,9.8M2,4.27L4.28,6.55L4.73,7C3.08,8.3 1.78,10 1,12C2.73,16.39 7,19.5 12,19.5C13.55,19.5 15.03,19.2 16.38,18.66L16.81,19.08L19.73,22L21,20.73L3.27,3M12,7A5,5 0 0,1 17,12C17,12.64 16.87,13.26 16.64,13.82L19.57,16.75C21.07,15.5 22.27,13.86 23,12C21.27,7.61 17,4.5 12,4.5C10.6,4.5 9.26,4.75 8,5.2L10.17,7.35C10.74,7.13 11.35,7 12,7Z';

    const apiEndpoint = document.querySelector('meta[name="5x-api-endpoint"]').getAttribute('content');
    
    let loginAttempts = 0;
    const MAX_ATTEMPTS = 5;
    const LOCKOUT_TIME = 300000;
    let lockoutUntil = 0;

    function sanitizeInput(input) {
        return input.trim().replace(/[<>]/g, '');
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.add('visible');
    }

    function hideError() {
        errorMessage.classList.remove('visible');
    }

    function checkLockout() {
        const now = Date.now();
        if (lockoutUntil > now) {
            const remainingSeconds = Math.ceil((lockoutUntil - now) / 1000);
            showError(`Too many failed attempts. Please wait ${remainingSeconds} seconds.`);
            return true;
        }
        return false;
    }

    if (!toggleButton || !passwordInput || !eyeIcon) {
        console.error('Required elements not found');
        return;
    }

    function togglePassword() {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        eyeIcon.innerHTML = `<path d="${isPassword ? eyeHiddenPath : eyeVisiblePath}"/>`;
        toggleButton.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    }

    toggleButton.addEventListener('click', togglePassword);

    toggleButton.addEventListener('keydown', function(event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            togglePassword();
        }
    });

    if (form) {
        form.addEventListener('submit', async function(event) {
            event.preventDefault();
            hideError();

            console.log('[DEBUG] Login form submitted');

            if (checkLockout()) {
                return;
            }

            const usernameRaw = document.getElementById('username').value;
            const username = sanitizeInput(usernameRaw);
            const password = passwordInput.value;

            console.log('[DEBUG] Username:', username);

            if (!username) {
                document.getElementById('username').focus();
                return false;
            }

            if (!password) {
                passwordInput.focus();
                return false;
            }

            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.textContent = 'Logging in...';

            try {
                console.log('[DEBUG] Sending login request to:', `${apiEndpoint}/login`);
                const response = await fetch(`${apiEndpoint}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });

                console.log('[DEBUG] Login response status:', response.status);
                const data = await response.json();
                console.log('[DEBUG] Login response data:', data);

                if (response.ok && data.success) {
                    loginAttempts = 0;
                    console.log('[DEBUG] Login successful, storing token:', data.token.substring(0, 20) + '...');
                    localStorage.setItem('admin_token', data.token);
                    console.log('[DEBUG] Token stored in localStorage');
                    console.log('[DEBUG] Redirecting to /panel');
                    window.location.href = '/panel';
                } else {
                    loginAttempts++;
                    
                    if (loginAttempts >= MAX_ATTEMPTS) {
                        lockoutUntil = Date.now() + LOCKOUT_TIME;
                        showError(`Too many failed attempts. Account locked for 5 minutes.`);
                    } else {
                        let errorMsg = 'Login failed. Please try again.';
                        if (data.code === '5xsoftware.invalid_credentials') {
                            errorMsg = 'Invalid username or password.';
                        } else if (data.code === '5xsoftware.not_setup') {
                            errorMsg = 'System not configured.';
                            setTimeout(() => window.location.reload(), 1500);
                        }
                        showError(errorMsg);
                    }
                }
            } catch (err) {
                console.log('[DEBUG] Login error:', err);
                showError('Network error. Please check your connection.');
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = 'Login';
            }
        });
    }

    window.addEventListener('load', function() {
        const username = document.getElementById('username');
        if (username && !username.value) {
            username.focus();
        }
    });

})();