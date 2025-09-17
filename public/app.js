class PasskeyAuth {
    constructor() {
        this.baseURL = window.location.origin;
        this.accessToken = null;
        this.username = null;
        this.isRefreshing = false;
        this.pendingRequests = [];
        this.init();
    }

    init() {
        if (!window.PublicKeyCredential) {
            this.showStatus('WebAuthn is not supported in this browser', 'error');
            return;
        }

        this.checkLoginState();

        document.getElementById('register-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('logout-btn').addEventListener('click', () => {
            this.handleLogout();
        });

        document.getElementById('test-protected-btn').addEventListener('click', () => {
            this.testProtectedAccess();
        });
    }

    parseJWT(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload);
        } catch (e) {
            return null;
        }
    }

    isTokenExpired(token) {
        const payload = this.parseJWT(token);
        if (!payload || !payload.exp) return true;
        return Date.now() >= payload.exp * 1000;
    }

    getTokenTimeLeft(token) {
        const payload = this.parseJWT(token);
        if (!payload || !payload.exp) return 0;
        return Math.max(0, payload.exp * 1000 - Date.now());
    }

    async refreshToken() {
        if (this.isRefreshing) {
            return new Promise((resolve, reject) => {
                this.pendingRequests.push({ resolve, reject });
            });
        }

        this.isRefreshing = true;

        try {
            const response = await fetch(`${this.baseURL}/refresh`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.ok) {
                throw new Error('Failed to refresh token');
            }

            const result = await response.json();
            this.accessToken = result.access_token;

            this.pendingRequests.forEach(({ resolve }) => resolve(this.accessToken));
            this.pendingRequests = [];

            return this.accessToken;
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.clearLoginState();
            this.showStatus('Session expired. Please log in again.', 'error');

            this.pendingRequests.forEach(({ reject }) => reject(error));
            this.pendingRequests = [];

            throw error;
        } finally {
            this.isRefreshing = false;
        }
    }

    checkLoginState() {
        this.showAuthForms();
    }

    setLoginState(username, accessToken) {
        this.username = username;
        this.accessToken = accessToken;
        this.showUserDashboard(username, new Date().toISOString());
    }

    clearLoginState() {
        this.accessToken = null;
        this.username = null;
        this.showAuthForms();
    }

    async apiCall(url, options = {}) {
        if (!this.accessToken) {
            throw new Error('No access token available');
        }

        const requestOptions = {
            ...options,
            credentials: 'include',
            headers: {
                'Authorization': `Bearer ${this.accessToken}`,
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        let response = await fetch(url, requestOptions);

        if (response.status === 401) {
            try {
                await this.refreshToken();
                
                requestOptions.headers['Authorization'] = `Bearer ${this.accessToken}`;
                response = await fetch(url, requestOptions);
            } catch (refreshError) {
                throw new Error('Authentication failed');
            }
        }

        return response;
    }

    async testProtectedAccess() {
        if (!this.accessToken) {
            this.showStatus('No access token available', 'error');
            return;
        }

        try {
            const response = await this.apiCall(`${this.baseURL}/protected`, {
                method: 'GET'
            });

            if (response.ok) {
                const result = await response.json();
                this.showStatus(`✅ Protected access successful! Welcome ${result.user}`, 'success');
            } else {
                this.showStatus('❌ Failed to access protected resource', 'error');
            }
        } catch (error) {
            console.error('Protected access test failed:', error);
            this.showStatus(`❌ ${error.message}`, 'error');
        }
    }

    showUserDashboard(username, loginTime) {
        document.getElementById('auth-forms').style.display = 'none';
        document.getElementById('user-dashboard').style.display = 'block';

        document.querySelector('.username-display').textContent = `@${username}`;

        const loginDate = new Date(loginTime);
        const timeString = loginDate.toLocaleString();
        document.querySelector('.login-time').textContent = `Logged in: ${timeString}`;
    }

    showAuthForms() {
        document.getElementById('user-dashboard').style.display = 'none';
        document.getElementById('auth-forms').style.display = 'block';

        const statusEl = document.getElementById('status');
        statusEl.style.display = 'none';
    }

    async handleLogout() {
        try {
            await fetch(`${this.baseURL}/logout`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        } catch (error) {
            console.error('Logout request failed:', error);
        }

        this.clearLoginState();
        this.showStatus('👋 Logged out successfully', 'success');

        document.getElementById('register-username').value = '';
        document.getElementById('login-username').value = '';

        switchTab('login');
    }

    showStatus(message, type = 'info') {
        const statusEl = document.getElementById('status');
        statusEl.textContent = message;
        statusEl.className = `status-message ${type}`;

        if (type !== 'error') {
            setTimeout(() => {
                statusEl.style.display = 'none';
            }, 5000);
        }
    }


    arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }


    base64UrlToArrayBuffer(base64url) {
        if (!base64url) {
            console.error('base64UrlToArrayBuffer: input is null or undefined:', base64url);
            throw new Error('Invalid base64url input');
        }

        console.log('Converting base64url to ArrayBuffer:', base64url);
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = base64.length % 4;
        const padded = base64 + '='.repeat(padding ? 4 - padding : 0);
        const binary = atob(padded);
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return buffer;
    }


    async handleRegister() {
        console.log('Starting registration process...');

        const username = document.getElementById('register-username').value.trim();
        console.log('Username:', username);

        if (!username) {
            this.showStatus('Please enter a username', 'error');
            return;
        }

        const registerBtn = document.querySelector('#register-tab .auth-btn');
        const originalText = registerBtn.innerHTML;

        try {

            registerBtn.disabled = true;
            registerBtn.innerHTML = '<span class="btn-text">Creating passkey...</span><span class="btn-icon">⏳</span>';
            registerBtn.classList.add('loading');

            this.showStatus('Starting registration...', 'info');


            console.log('Making request to /register/start...');
            const startResponse = await fetch(`${this.baseURL}/register/start`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username })
            });

            console.log('Response status:', startResponse.status);

            if (!startResponse.ok) {
                const errorText = await startResponse.text();
                throw new Error(`Registration failed: ${errorText}`);
            }

            const options = await startResponse.json();
            console.log('Received options from server:', options);


            const publicKeyOptions = options.publicKey || options.Response || options;
            console.log('PublicKey options:', publicKeyOptions);
            console.log('Challenge:', publicKeyOptions.challenge);
            console.log('User:', publicKeyOptions.user);
            console.log('User ID:', publicKeyOptions.user?.id);


            const credentialCreationOptions = {
                ...publicKeyOptions,
                challenge: this.base64UrlToArrayBuffer(publicKeyOptions.challenge),
                user: {
                    ...publicKeyOptions.user,
                    id: this.base64UrlToArrayBuffer(publicKeyOptions.user.id)
                }
            };


            if (publicKeyOptions.excludeCredentials) {
                credentialCreationOptions.excludeCredentials = publicKeyOptions.excludeCredentials.map(cred => ({
                    ...cred,
                    id: this.base64UrlToArrayBuffer(cred.id)
                }));
            }

            this.showStatus('Please use your authenticator...', 'info');


            const credential = await navigator.credentials.create({
                publicKey: credentialCreationOptions
            });

            if (!credential) {
                throw new Error('Failed to create credential');
            }

            this.showStatus('Completing registration...', 'info');


            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: this.arrayBufferToBase64Url(credential.response.attestationObject),
                    clientDataJSON: this.arrayBufferToBase64Url(credential.response.clientDataJSON)
                }
            };

            const finishResponse = await fetch(`${this.baseURL}/register/finish`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    data: credentialData
                })
            });

            if (!finishResponse.ok) {
                const errorText = await finishResponse.text();
                throw new Error(`Registration completion failed: ${errorText}`);
            }

            const result = await finishResponse.json();

            if (result.access_token) {
                this.showStatus('Registration successful! Logging you in...', 'success');
                document.getElementById('register-username').value = '';


                setTimeout(() => {
                    this.setLoginState(username, result.access_token);
                }, 1500);
            } else {
                throw new Error('Registration failed');
            }

        } catch (error) {
            console.error('Registration error:', error);
            this.showStatus(`Registration failed: ${error.message}`, 'error');
        } finally {

            registerBtn.disabled = false;
            registerBtn.innerHTML = originalText;
            registerBtn.classList.remove('loading');
        }
    }


    async handleLogin() {
        console.log('Starting login process...');

        const username = document.getElementById('login-username').value.trim();
        console.log('👤 Login Username:', username);

        if (!username) {
            this.showStatus('Please enter a username', 'error');
            return;
        }

        const loginBtn = document.querySelector('#login-tab .auth-btn');
        const originalText = loginBtn.innerHTML;

        try {

            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="btn-text">Authenticating...</span>';
            loginBtn.classList.add('loading');

            this.showStatus('Starting authentication...', 'info');


            const startResponse = await fetch(`${this.baseURL}/login/start`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username })
            });

            if (startResponse.status === 404) {
                throw new Error('User not found. Please register first.');
            }

            if (!startResponse.ok) {
                const errorText = await startResponse.text();
                throw new Error(`Authentication failed: ${errorText}`);
            }

            const options = await startResponse.json();
            console.log('Received login options from server:', options);


            const publicKeyOptions = options.publicKey || options.Response || options;
            console.log('Login PublicKey options:', publicKeyOptions);


            const credentialRequestOptions = {
                ...publicKeyOptions,
                challenge: this.base64UrlToArrayBuffer(publicKeyOptions.challenge)
            };

            if (publicKeyOptions.allowCredentials) {
                credentialRequestOptions.allowCredentials = publicKeyOptions.allowCredentials.map(cred => ({
                    ...cred,
                    id: this.base64UrlToArrayBuffer(cred.id)
                }));
            }

            this.showStatus('Please use your authenticator...', 'info');


            const assertion = await navigator.credentials.get({
                publicKey: credentialRequestOptions
            });

            if (!assertion) {
                throw new Error('Failed to get assertion');
            }

            this.showStatus('Completing authentication...', 'info');


            const assertionData = {
                id: assertion.id,
                rawId: this.arrayBufferToBase64Url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: this.arrayBufferToBase64Url(assertion.response.authenticatorData),
                    clientDataJSON: this.arrayBufferToBase64Url(assertion.response.clientDataJSON),
                    signature: this.arrayBufferToBase64Url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? this.arrayBufferToBase64Url(assertion.response.userHandle) : null
                }
            };

            const finishResponse = await fetch(`${this.baseURL}/login/finish`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    data: assertionData
                })
            });

            if (!finishResponse.ok) {
                const errorText = await finishResponse.text();
                throw new Error(`Authentication completion failed: ${errorText}`);
            }

            const result = await finishResponse.json();

            if (result.access_token) {
                this.showStatus(`Welcome back, ${username}! Login successful.`, 'success');
                document.getElementById('login-username').value = '';


                setTimeout(() => {
                    this.setLoginState(username, result.access_token);
                }, 1000);
            } else {
                throw new Error('Authentication failed');
            }

        } catch (error) {
            console.error('Login error:', error);
            this.showStatus(`Login failed: ${error.message}`, 'error');
        } finally {

            loginBtn.disabled = false;
            loginBtn.innerHTML = originalText;
            loginBtn.classList.remove('loading');
        }
    }
}


function switchTab(tabName) {

    const authForms = document.getElementById('auth-forms');
    if (authForms.style.display === 'none') {
        return;
    }


    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');


    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');


    const statusEl = document.getElementById('status');
    statusEl.style.display = 'none';
}


document.addEventListener('DOMContentLoaded', () => {
    new PasskeyAuth();
});
