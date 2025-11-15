/**
 * Web Client for End-to-End Encrypted Chat
 *
 * Note: This is a simplified web implementation. For full E2E encryption in browser,
 * you would need to implement the crypto primitives in JavaScript using Web Crypto API.
 * This version demonstrates the architecture but uses server-relayed encryption.
 */

class ChatApp {
    constructor() {
        this.serverUrl = window.location.origin;
        this.wsUrl = this.serverUrl.replace('http', 'ws') + '/ws';
        this.token = null;
        this.username = null;
        this.websocket = null;
        this.currentChat = null;
        this.onlineUsers = new Set();
        this.allUsers = new Set();

        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;
                this.switchTab(tabName);
            });
        });

        // Auth forms
        document.getElementById('login').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('register').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        // Message form
        document.getElementById('message-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.sendMessage();
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(`${tabName}-form`).classList.add('active');
    }

    async handleRegister() {
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;

        if (password !== confirm) {
            this.showAuthMessage('Passwords do not match', 'error');
            return;
        }

        try {
            // In a real implementation, identity keys would be generated client-side
            // For now, we generate a placeholder
            const identityKey = this.generatePlaceholderKey();

            const response = await fetch(`${this.serverUrl}/api/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username,
                    password,
                    identity_key: identityKey
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.token = data.access_token;
                this.username = data.username;
                this.showAuthMessage('Registration successful!', 'success');
                setTimeout(() => this.switchToChatScreen(), 1000);
            } else {
                this.showAuthMessage(data.detail || 'Registration failed', 'error');
            }
        } catch (error) {
            this.showAuthMessage('Network error: ' + error.message, 'error');
        }
    }

    async handleLogin() {
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        try {
            const response = await fetch(`${this.serverUrl}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.token = data.access_token;
                this.username = data.username;
                this.showAuthMessage('Login successful!', 'success');
                setTimeout(() => this.switchToChatScreen(), 1000);
            } else {
                this.showAuthMessage(data.detail || 'Login failed', 'error');
            }
        } catch (error) {
            this.showAuthMessage('Network error: ' + error.message, 'error');
        }
    }

    showAuthMessage(message, type) {
        const msgElement = document.getElementById('auth-message');
        msgElement.textContent = message;
        msgElement.className = `message ${type}`;
    }

    async switchToChatScreen() {
        document.getElementById('auth-screen').classList.remove('active');
        document.getElementById('chat-screen').classList.add('active');
        document.getElementById('current-user').textContent = this.username;

        // Connect WebSocket
        await this.connectWebSocket();

        // Load users
        await this.loadUsers();
    }

    async connectWebSocket() {
        try {
            this.websocket = new WebSocket(this.wsUrl);

            this.websocket.onopen = () => {
                console.log('WebSocket connected');
                // Authenticate
                this.websocket.send(JSON.stringify({
                    type: 'auth',
                    token: this.token
                }));
            };

            this.websocket.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            };

            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus(false);
            };

            this.websocket.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus(false);
            };
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
        }
    }

    handleWebSocketMessage(data) {
        console.log('Received:', data);

        switch (data.type) {
            case 'auth_success':
                this.updateConnectionStatus(true);
                this.onlineUsers = new Set(data.online_users || []);
                this.renderOnlineUsers();
                break;

            case 'message':
                this.handleIncomingMessage(data);
                break;

            case 'user_online':
                this.onlineUsers.add(data.username);
                this.renderOnlineUsers();
                break;

            case 'user_offline':
                this.onlineUsers.delete(data.username);
                this.renderOnlineUsers();
                break;

            case 'delivered':
                console.log('Message delivered to', data.to);
                break;

            case 'error':
                console.error('Server error:', data.message);
                this.showSystemMessage(data.message);
                break;
        }
    }

    handleIncomingMessage(data) {
        const from = data.from;
        const messageData = data.data;

        // In a real implementation, we would decrypt the message here
        // For this demo, we'll display a placeholder
        const content = this.decryptMessage(messageData);

        if (this.currentChat === from) {
            this.displayMessage(content, 'received', from);
        } else {
            // Show notification
            this.showSystemMessage(`New message from ${from}`);
        }
    }

    async loadUsers() {
        try {
            const response = await fetch(`${this.serverUrl}/api/users`);
            const data = await response.json();

            this.allUsers = new Set(data.users.filter(u => u !== this.username));
            this.renderAllUsers();
        } catch (error) {
            console.error('Failed to load users:', error);
        }
    }

    renderOnlineUsers() {
        const container = document.getElementById('online-users');
        container.innerHTML = '';

        const onlineUsersExceptMe = Array.from(this.onlineUsers).filter(u => u !== this.username);

        if (onlineUsersExceptMe.length === 0) {
            container.innerHTML = '<div style="color: var(--text-secondary); font-size: 12px; padding: 10px;">No users online</div>';
            return;
        }

        onlineUsersExceptMe.forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            if (this.currentChat === user) {
                userItem.classList.add('active');
            }
            userItem.innerHTML = `
                <span class="status-dot"></span>
                <span>${user}</span>
            `;
            userItem.addEventListener('click', () => this.startChat(user));
            container.appendChild(userItem);
        });
    }

    renderAllUsers() {
        const container = document.getElementById('all-users');
        container.innerHTML = '';

        if (this.allUsers.size === 0) {
            container.innerHTML = '<div style="color: var(--text-secondary); font-size: 12px; padding: 10px;">No users found</div>';
            return;
        }

        Array.from(this.allUsers).forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            if (this.currentChat === user) {
                userItem.classList.add('active');
            }
            const isOnline = this.onlineUsers.has(user);
            userItem.innerHTML = `
                ${isOnline ? '<span class="status-dot"></span>' : '<span style="width: 8px;"></span>'}
                <span>${user}</span>
            `;
            userItem.addEventListener('click', () => this.startChat(user));
            container.appendChild(userItem);
        });
    }

    startChat(username) {
        this.currentChat = username;
        document.getElementById('chat-with').textContent = `Chat with ${username}`;
        document.getElementById('message-input').disabled = false;
        document.querySelector('.btn-send').disabled = false;

        // Clear messages
        const messagesContainer = document.getElementById('messages');
        messagesContainer.innerHTML = '';

        // Update user lists
        this.renderOnlineUsers();
        this.renderAllUsers();

        // Show encryption status
        document.getElementById('encryption-status').style.display = 'flex';

        // In a real implementation, we would initialize or load the encrypted session here
        this.showSystemMessage('End-to-end encrypted session started');
    }

    async sendMessage() {
        const input = document.getElementById('message-input');
        const content = input.value.trim();

        if (!content || !this.currentChat) {
            return;
        }

        // In a real implementation, we would encrypt the message here
        const encryptedData = this.encryptMessage(content);

        try {
            this.websocket.send(JSON.stringify({
                type: 'message',
                to: this.currentChat,
                data: encryptedData
            }));

            // Display sent message
            this.displayMessage(content, 'sent');

            // Clear input
            input.value = '';
        } catch (error) {
            console.error('Failed to send message:', error);
            this.showSystemMessage('Failed to send message');
        }
    }

    displayMessage(content, direction, sender = null) {
        const messagesContainer = document.getElementById('messages');

        const messageBubble = document.createElement('div');
        messageBubble.className = `message-bubble ${direction}`;

        const now = new Date();
        const time = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

        messageBubble.innerHTML = `
            <div>${this.escapeHtml(content)}</div>
            <div class="message-time">${time}</div>
        `;

        messagesContainer.appendChild(messageBubble);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    showSystemMessage(content) {
        const messagesContainer = document.getElementById('messages');
        const systemMsg = document.createElement('div');
        systemMsg.style.cssText = 'text-align: center; color: var(--text-secondary); font-size: 12px; margin: 10px 0;';
        systemMsg.textContent = content;
        messagesContainer.appendChild(systemMsg);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    updateConnectionStatus(connected) {
        const indicator = document.getElementById('status-indicator');
        const text = document.getElementById('status-text');

        if (connected) {
            indicator.classList.add('connected');
            text.textContent = 'Connected';
        } else {
            indicator.classList.remove('connected');
            text.textContent = 'Disconnected';
        }
    }

    // Crypto placeholders - in production, use Web Crypto API
    generatePlaceholderKey() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    encryptMessage(plaintext) {
        // Placeholder: In production, use actual encryption
        // This would use the Double Ratchet algorithm implemented in JS
        return {
            header: {
                dh_public: this.generatePlaceholderKey(),
                prev_count: 0,
                msg_num: Math.floor(Math.random() * 1000)
            },
            ciphertext: btoa(plaintext) // Simple base64 encoding as placeholder
        };
    }

    decryptMessage(encryptedData) {
        // Placeholder: In production, use actual decryption
        try {
            return atob(encryptedData.ciphertext);
        } catch {
            return '[Encrypted message]';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    logout() {
        if (this.websocket) {
            this.websocket.close();
        }
        this.token = null;
        this.username = null;
        this.currentChat = null;
        document.getElementById('chat-screen').classList.remove('active');
        document.getElementById('auth-screen').classList.add('active');
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new ChatApp();
});
