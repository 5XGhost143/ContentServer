(function() {
    'use strict';

    const toggleButton = document.querySelector('.toggle-password');
    const toggleButtonConfirm = document.querySelector('.toggle-password-confirm');
    const passwordInput = document.getElementById('password');
    const passwordConfirmInput = document.getElementById('password-confirm');
    const eyeIcon = document.getElementById('eye-icon');
    const eyeIconConfirm = document.getElementById('eye-icon-confirm');
    const form = document.getElementById('setup-form');
    const errorMessage = document.getElementById('error-message');

    const eyeVisiblePath = 'M12,9A3,3 0 0,0 9,12A3,3 0 0,0 12,15A3,3 0 0,0 15,12A3,3 0 0,0 12,9M12,17A5,5 0 0,1 7,12A5,5 0 0,1 12,7A5,5 0 0,1 17,12A5,5 0 0,1 12,17M12,4.5C7,4.5 2.73,7.61 1,12C2.73,16.39 7,19.5 12,19.5C17,19.5 21.27,16.39 23,12C21.27,7.61 17,4.5 12,4.5Z';
    const eyeHiddenPath = 'M11.83,9L15,12.16C15,12.11 15,12.05 15,12A3,3 0 0,0 12,9C11.94,9 11.89,9 11.83,9M7.53,9.8L9.08,11.35C9.03,11.56 9,11.77 9,12A3,3 0 0,0 12,15C12.22,15 12.44,14.97 12.65,14.92L14.2,16.47C13.53,16.8 12.79,17 12,17A5,5 0 0,1 7,12C7,11.21 7.2,10.47 7.53,9.8M2,4.27L4.28,6.55L4.73,7C3.08,8.3 1.78,10 1,12C2.73,16.39 7,19.5 12,19.5C13.55,19.5 15.03,19.2 16.38,18.66L16.81,19.08L19.73,22L21,20.73L3.27,3M12,7A5,5 0 0,1 17,12C17,12.64 16.87,13.26 16.64,13.82L19.57,16.75C21.07,15.5 22.27,13.86 23,12C21.27,7.61 17,4.5 12,4.5C10.6,4.5 9.26,4.75 8,5.2L10.17,7.35C10.74,7.13 11.35,7 12,7Z';

    const apiEndpoint = document.querySelector('meta[name="5x-api-endpoint"]').getAttribute('content');

    function togglePassword(input, icon, button) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        icon.innerHTML = `<path d="${isPassword ? eyeHiddenPath : eyeVisiblePath}"/>`;
        button.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.add('visible');
    }

    function hideError() {
        errorMessage.classList.remove('visible');
    }

    if (toggleButton && passwordInput && eyeIcon) {
        toggleButton.addEventListener('click', () => togglePassword(passwordInput, eyeIcon, toggleButton));
        toggleButton.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                togglePassword(passwordInput, eyeIcon, toggleButton);
            }
        });
    }

    if (toggleButtonConfirm && passwordConfirmInput && eyeIconConfirm) {
        toggleButtonConfirm.addEventListener('click', () => togglePassword(passwordConfirmInput, eyeIconConfirm, toggleButtonConfirm));
        toggleButtonConfirm.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                togglePassword(passwordConfirmInput, eyeIconConfirm, toggleButtonConfirm);
            }
        });
    }

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideError();

            const username = document.getElementById('username').value.trim();
            const password = passwordInput.value;
            const passwordConfirm = passwordConfirmInput.value;

            if (username.length < 3) {
                showError('Username must be at least 3 characters long.');
                return;
            }

            if (password.length < 8) {
                showError('Password must be at least 8 characters long.');
                return;
            }

            if (password !== passwordConfirm) {
                showError('Passwords do not match.');
                passwordConfirmInput.classList.add('error');
                return;
            }

            passwordConfirmInput.classList.remove('error');

            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.textContent = 'Creating account...';

            try {
                const response = await fetch(`${apiEndpoint}/setup`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    localStorage.setItem('admin_token', data.token);
                    window.location.href = '/admin';
                } else {
                    let errorMsg = 'Setup failed. Please try again.';
                    if (data.code === '5xsoftware.already_setup') {
                        errorMsg = 'Administrator account already exists.';
                    } else if (data.code === '5xsoftware.invalid_credentials') {
                        errorMsg = 'Invalid username or password format.';
                    }
                    showError(errorMsg);
                }
            } catch (err) {
                showError('Network error. Please check your connection.');
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = 'Create Administrator Account';
            }
        });
    }

    window.addEventListener('load', () => {
        const username = document.getElementById('username');
        if (username && !username.value) {
            username.focus();
        }
    });

})();