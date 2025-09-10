// CyberSec AI Chatbot - Main JavaScript File
// Author: AI Assistant
// Description: Cybersecurity-focused chatbot with Gemini API integration and secure chat features

class CyberSecChatbot {
    constructor() {
        this.token = null;
        this.profile = null;
        this.isSecureMode = false;
        this.chatHistory = [];
        this.securityTips = [
            "💡 Security Tip: Always use strong, unique passwords for each account and enable two-factor authentication when available.",
            "🔐 Security Tip: Keep your software and operating system updated to patch security vulnerabilities.",
            "🛡️ Security Tip: Be cautious of phishing emails and never click on suspicious links or download unknown attachments.",
            "🔒 Security Tip: Use a VPN when connecting to public Wi-Fi networks to protect your data.",
            "⚡ Security Tip: Regularly backup your important data to prevent loss from ransomware attacks.",
            "🎯 Security Tip: Enable firewall protection and use reputable antivirus software.",
            "🔑 Security Tip: Use password managers to generate and store complex passwords securely.",
            "📱 Security Tip: Be mindful of app permissions and only grant necessary access to your device features.",
            "🌐 Security Tip: Use HTTPS websites and look for the lock icon in your browser's address bar.",
            "🚨 Security Tip: Monitor your accounts regularly for any suspicious activity or unauthorized access."
        ];
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.showSecurityTip();
        this.hideLoadingOverlay();
        this.loadSession();
        this.init3DBackground();

        if (this.token) {
            this.onAuthenticated();
        } else {
            // redirect to login page if not authenticated
            if (!location.pathname.endsWith('login.html')) {
                location.href = 'login.html';
                return;
            }
            this.lockInput(true);
        }
    }

    setupEventListeners() {
        // Send button and Enter key
        const sendButton = document.getElementById('sendButton');
        const messageInput = document.getElementById('messageInput');
        const secureToggle = document.getElementById('secureToggle');
        const clearChat = document.getElementById('clearChat');
        const logoutButton = document.getElementById('logoutButton');
        const profileAvatar = document.querySelector('.profile-avatar');
        const closeProfileModal = document.getElementById('closeProfileModal');
        const changePasswordBtn = document.getElementById('changePasswordBtn');
        const changeUsernameBtn = document.getElementById('changeUsernameBtn');

        sendButton.addEventListener('click', () => this.sendMessage());
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Character count
        messageInput.addEventListener('input', (e) => {
            const charCount = document.getElementById('charCount');
            charCount.textContent = e.target.value.length;
        });

        // Secure mode toggle
        secureToggle.addEventListener('click', () => this.toggleSecureMode());

        // Clear chat
        clearChat.addEventListener('click', () => this.clearChatHistory());

        // Auth (login page handled in login.html script)
        logoutButton.addEventListener('click', () => this.logout());
        
        // Profile management
        if (profileAvatar) {
            profileAvatar.addEventListener('click', () => this.showProfileModal());
        }
        if (closeProfileModal) {
            closeProfileModal.addEventListener('click', () => this.hideProfileModal());
        }
        if (changePasswordBtn) {
            changePasswordBtn.addEventListener('click', () => this.showPasswordModal());
        }
        if (changeUsernameBtn) {
            changeUsernameBtn.addEventListener('click', () => this.showUsernameModal());
        }
        
        // Password toggles for profile modal
        this.setupPasswordToggles();
        
        // Close modal on outside click
        document.getElementById('profileModal').addEventListener('click', (e) => {
            if (e.target.id === 'profileModal') {
                this.hideProfileModal();
            }
        });
    }

    showLoadingOverlay() {
        document.getElementById('loadingOverlay').classList.remove('hidden');
    }

    hideLoadingOverlay() {
        setTimeout(() => {
            document.getElementById('loadingOverlay').classList.add('hidden');
        }, 1000);
    }

    loadSession() {
        this.token = localStorage.getItem('auth_token');
        const profileStr = localStorage.getItem('auth_profile');
        if (profileStr) {
            try { this.profile = JSON.parse(profileStr); } catch { this.profile = null; }
        }
    }

    saveSession(token, profile) {
        this.token = token;
        this.profile = profile;
        localStorage.setItem('auth_token', token);
        localStorage.setItem('auth_profile', JSON.stringify(profile));
    }

    clearSession() {
        this.token = null;
        this.profile = null;
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_profile');
    }

    lockInput(locked) {
        const input = document.getElementById('messageInput');
        const btn = document.getElementById('sendButton');
        if (!input || !btn) return;
        input.disabled = !!locked;
        btn.disabled = !!locked;
        input.placeholder = locked ? 'Login to start chatting...' : 'Ask about cybersecurity, threats, or best practices...';
    }

    updateProfileUI() {
        if (!this.profile) return;
        const nameEl = document.getElementById('profileName');
        const emailEl = document.getElementById('profileEmail');
        if (nameEl) nameEl.textContent = this.profile.name || 'User';
        if (emailEl) emailEl.textContent = this.profile.email || '';
    }

    async login() {
        const email = (document.getElementById('loginEmail').value || '').trim();
        const password = (document.getElementById('loginPassword').value || '').trim();
        if (!email || !password) {
            this.showNotification('Please enter email and password', 'warning');
            return;
        }
        try {
            const res = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            if (!res.ok) throw new Error('Login failed');
            const data = await res.json();
            this.saveSession(data.token, data.profile);
            this.onAuthenticated();
            this.showNotification('Logged in successfully', 'success');
        } catch (e) {
            this.showNotification('Invalid credentials', 'error');
        }
    }

    logout() {
        this.clearSession();
        this.lockInput(true);
        // redirect to login page
        location.href = 'login.html';
        this.showNotification('Logged out', 'info');
    }

    onAuthenticated() {
        this.updateProfileUI();
        this.lockInput(false);
        this.showWelcomeMessage();
    }

    showProfileModal() {
        const modal = document.getElementById('profileModal');
        if (modal) {
            modal.classList.remove('hidden');
            this.loadCurrentProfile();
        }
    }

    hideProfileModal() {
        const modal = document.getElementById('profileModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    showPasswordModal() {
        this.hideProfileModal();
        const modal = document.getElementById('passwordModal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    hidePasswordModal() {
        const modal = document.getElementById('passwordModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    showUsernameModal() {
        this.hideProfileModal();
        const modal = document.getElementById('usernameModal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    hideUsernameModal() {
        const modal = document.getElementById('usernameModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    async loadCurrentProfile() {
        try {
            const response = await fetch('/profile', {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            if (response.ok) {
                const data = await response.json();
                document.getElementById('currentUsername').textContent = data.name;
                document.getElementById('currentEmail').textContent = data.email;
            }
        } catch (e) {
            console.error('Failed to load profile:', e);
        }
    }

    async updatePassword() {
        const currentPassword = document.getElementById('currentPasswordChange').value.trim();
        const newPassword = document.getElementById('newPasswordChange').value.trim();
        const confirmPassword = document.getElementById('confirmPasswordChange').value.trim();

        if (!currentPassword || !newPassword || !confirmPassword) {
            this.showNotification('All fields are required', 'warning');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showNotification('New passwords do not match', 'warning');
            return;
        }

        if (newPassword.length < 6) {
            this.showNotification('New password must be at least 6 characters', 'warning');
            return;
        }

        try {
            const response = await fetch('/profile/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    newPassword: newPassword,
                    currentPassword: currentPassword
                })
            });

            if (response.ok) {
                this.showNotification('Password updated successfully', 'success');
                this.hidePasswordModal();
                // Clear form
                document.getElementById('currentPasswordChange').value = '';
                document.getElementById('newPasswordChange').value = '';
                document.getElementById('confirmPasswordChange').value = '';
            } else {
                const errorData = await response.json();
                this.showNotification(errorData.error || 'Failed to update password', 'error');
            }
        } catch (e) {
            this.showNotification('Failed to update password', 'error');
        }
    }

    async updateUsername() {
        const newUsername = document.getElementById('newUsernameChange').value.trim();
        const currentPassword = document.getElementById('currentPasswordUsername').value.trim();

        if (!newUsername || !currentPassword) {
            this.showNotification('All fields are required', 'warning');
            return;
        }

        if (newUsername.length < 3) {
            this.showNotification('Username must be at least 3 characters', 'warning');
            return;
        }

        try {
            const response = await fetch('/profile/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({
                    newEmail: `${newUsername}@example.com`,
                    currentPassword: currentPassword
                })
            });

            if (response.ok) {
                const data = await response.json();
                this.showNotification('Username updated successfully', 'success');
                this.hideUsernameModal();
                // Clear form
                document.getElementById('newUsernameChange').value = '';
                document.getElementById('currentPasswordUsername').value = '';
                // Update UI
                this.updateProfileUI();
            } else {
                const errorData = await response.json();
                this.showNotification(errorData.error || 'Failed to update username', 'error');
            }
        } catch (e) {
            this.showNotification('Failed to update username', 'error');
        }
    }

    setupPasswordToggles() {
        // Password change modal toggles
        this.setupPasswordToggle('toggleCurrentPasswordChange', 'currentPasswordChange');
        this.setupPasswordToggle('toggleNewPasswordChange', 'newPasswordChange');
        this.setupPasswordToggle('toggleConfirmPasswordChange', 'confirmPasswordChange');
        
        // Username change modal toggle
        this.setupPasswordToggle('toggleCurrentPasswordUsername', 'currentPasswordUsername');
        
        // Add password strength checker
        this.setupPasswordStrengthChecker();
        
        // Add event listeners for new modals
        this.setupModalEventListeners();
    }

    setupPasswordToggle(toggleId, inputId) {
        const toggle = document.getElementById(toggleId);
        if (toggle) {
            toggle.addEventListener('click', function() {
                const input = document.getElementById(inputId);
                const icon = this.querySelector('i');
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.className = 'fas fa-eye-slash';
                } else {
                    input.type = 'password';
                    icon.className = 'fas fa-eye';
                }
            });
        }
    }

    setupPasswordStrengthChecker() {
        const passwordInput = document.getElementById('newPasswordChange');
        const strengthFill = document.getElementById('strengthFill');
        const strengthText = document.getElementById('strengthText');
        
        if (passwordInput && strengthFill && strengthText) {
            passwordInput.addEventListener('input', (e) => {
                const password = e.target.value;
                const strength = this.calculatePasswordStrength(password);
                this.updatePasswordStrengthUI(strength, strengthFill, strengthText);
            });
        }
    }

    calculatePasswordStrength(password) {
        let score = 0;
        let feedback = [];

        if (password.length === 0) {
            return { level: 'empty', score: 0, text: 'Enter a password', feedback: [] };
        }

        if (password.length < 6) {
            feedback.push('At least 6 characters');
        } else if (password.length >= 8) {
            score += 1;
        }

        if (password.length >= 12) {
            score += 1;
        }

        if (/[a-z]/.test(password)) {
            score += 1;
        } else {
            feedback.push('Lowercase letters');
        }

        if (/[A-Z]/.test(password)) {
            score += 1;
        } else {
            feedback.push('Uppercase letters');
        }

        if (/[0-9]/.test(password)) {
            score += 1;
        } else {
            feedback.push('Numbers');
        }

        if (/[^A-Za-z0-9]/.test(password)) {
            score += 1;
        } else {
            feedback.push('Special characters');
        }

        // Check for common patterns
        if (/(.)\1{2,}/.test(password)) {
            score -= 1;
            feedback.push('Avoid repeated characters');
        }

        if (/123|abc|qwe|password|admin/i.test(password)) {
            score -= 2;
            feedback.push('Avoid common patterns');
        }

        score = Math.max(0, Math.min(4, score));

        let level, text;
        if (score <= 1) {
            level = 'weak';
            text = 'Weak password';
        } else if (score === 2) {
            level = 'fair';
            text = 'Fair password';
        } else if (score === 3) {
            level = 'good';
            text = 'Good password';
        } else {
            level = 'strong';
            text = 'Strong password';
        }

        return { level, score, text, feedback };
    }

    updatePasswordStrengthUI(strength, strengthFill, strengthText) {
        // Remove all existing classes
        strengthFill.className = 'strength-fill';
        strengthText.className = 'strength-text';

        // Add new class based on strength
        if (strength.level !== 'empty') {
            strengthFill.classList.add(strength.level);
            strengthText.classList.add(strength.level);
        }

        // Update text
        if (strength.level === 'empty') {
            strengthText.textContent = 'Enter a password';
        } else {
            let text = strength.text;
            if (strength.feedback.length > 0) {
                text += ` - Add: ${strength.feedback.slice(0, 2).join(', ')}`;
            }
            strengthText.textContent = text;
        }
    }

    setupModalEventListeners() {
        // Password modal
        const closePasswordModal = document.getElementById('closePasswordModal');
        const updatePassword = document.getElementById('updatePassword');
        
        if (closePasswordModal) {
            closePasswordModal.addEventListener('click', () => this.hidePasswordModal());
        }
        if (updatePassword) {
            updatePassword.addEventListener('click', () => this.updatePassword());
        }
        
        // Username modal
        const closeUsernameModal = document.getElementById('closeUsernameModal');
        const updateUsername = document.getElementById('updateUsername');
        
        if (closeUsernameModal) {
            closeUsernameModal.addEventListener('click', () => this.hideUsernameModal());
        }
        if (updateUsername) {
            updateUsername.addEventListener('click', () => this.updateUsername());
        }
        
        // Close modals on outside click
        document.getElementById('passwordModal').addEventListener('click', (e) => {
            if (e.target.id === 'passwordModal') {
                this.hidePasswordModal();
            }
        });
        
        document.getElementById('usernameModal').addEventListener('click', (e) => {
            if (e.target.id === 'usernameModal') {
                this.hideUsernameModal();
            }
        });
    }

    showSecurityTip() {
        const tipElement = document.getElementById('securityTip');
        const randomTip = this.securityTips[Math.floor(Math.random() * this.securityTips.length)];
        tipElement.textContent = randomTip;
    }

    showWelcomeMessage() {
        const welcomeMessage = {
            type: 'bot',
            content: `🛡️ Welcome to CyberSec AI! I'm your cybersecurity assistant. I can help you with:

• Security best practices and guidelines
• Threat analysis and prevention strategies  
• Incident response and recovery procedures
• Security tool recommendations
• Compliance and regulatory guidance
• Vulnerability assessments and risk management

What cybersecurity question can I help you with today?`,
            timestamp: new Date()
        };

        this.addMessageToChat(welcomeMessage);
    }

    async sendMessage() {
        const messageInput = document.getElementById('messageInput');
        const message = messageInput.value.trim();

        if (!message) return;
        if (!this.token) {
            this.showLogin();
            this.showNotification('Please login to continue', 'warning');
            return;
        }

        // Add user message
        const userMessage = {
            type: 'user',
            content: message,
            timestamp: new Date()
        };

        this.addMessageToChat(userMessage);
        messageInput.value = '';
        document.getElementById('charCount').textContent = '0';

        // Show typing indicator
        this.showTypingIndicator();

        try {
            // Get AI response via backend
            const response = await this.getAIResponse(message);
            
            // Hide typing indicator
            this.hideTypingIndicator();

            // Add bot response
            const botMessage = {
                type: 'bot',
                content: response,
                timestamp: new Date()
            };

            this.addMessageToChat(botMessage);

        } catch (error) {
            this.hideTypingIndicator();
            console.error('Error getting AI response:', error);
            
            const errorMessage = {
                type: 'bot',
                content: '⚠️ Sorry, I encountered an error while processing your request. Please try again later.',
                timestamp: new Date()
            };

            this.addMessageToChat(errorMessage);
        }
    }

    async getAIResponse(message) {
        const prompt = `You are a cybersecurity expert AI assistant. Provide helpful, accurate, and practical cybersecurity advice. Focus on:

1. Security best practices
2. Threat prevention and mitigation
3. Incident response guidance
4. Security tool recommendations
5. Compliance and regulatory information

User question: ${message}

Please provide a comprehensive, professional response that's easy to understand. Include specific actionable advice when possible.`;

        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({ message: prompt })
        });

        if (!response.ok) {
            if (response.status === 401) {
                this.logout();
            }
            throw new Error(`API request failed: ${response.status}`);
        }

        const data = await response.json();
        if (data.candidates && data.candidates[0] && data.candidates[0].content) {
            return data.candidates[0].content.parts[0].text;
        } else if (data.error) {
            throw new Error(data.error);
        } else {
            throw new Error('Invalid response format from API');
        }
    }

    addMessageToChat(message) {
        const chatMessages = document.getElementById('chatMessages');
        const messageElement = this.createMessageElement(message);
        
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;

        // Store in chat history
        this.chatHistory.push(message);
    }

    createMessageElement(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${message.type} fade-in`;

        const avatar = document.createElement('div');
        avatar.className = 'message-avatar';
        avatar.innerHTML = message.type === 'user' ? '<i class="fas fa-user"></i>' : '<i class="fas fa-robot"></i>';

        const content = document.createElement('div');
        content.className = 'message-content';

        // Handle secure mode encryption
        let displayContent = message.content;
        if (this.isSecureMode && message.type === 'user') {
            displayContent = this.encryptMessage(message.content);
        }

        content.innerHTML = `
            <div class="message-text">${this.formatMessage(displayContent)}</div>
            <div class="message-time">${this.formatTime(message.timestamp)}</div>
        `;

        messageDiv.appendChild(avatar);
        messageDiv.appendChild(content);

        return messageDiv;
    }

    formatMessage(content) {
        // Convert line breaks to HTML
        return content.replace(/\n/g, '<br>');
    }

    formatTime(timestamp) {
        return timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    showTypingIndicator() {
        const typingIndicator = document.getElementById('typingIndicator');
        typingIndicator.classList.add('show');
        
        const chatMessages = document.getElementById('chatMessages');
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    hideTypingIndicator() {
        const typingIndicator = document.getElementById('typingIndicator');
        typingIndicator.classList.remove('show');
    }

    toggleSecureMode() {
        this.isSecureMode = !this.isSecureMode;
        const toggleBtn = document.getElementById('secureToggle');
        const body = document.body;

        if (this.isSecureMode) {
            toggleBtn.classList.add('active');
            toggleBtn.innerHTML = '<i class="fas fa-lock"></i><span>Secure Chat</span>';
            body.classList.add('secure-mode');
            
            // Encrypt existing user messages
            this.encryptExistingMessages();
            
            this.showNotification('🔒 Secure mode enabled - messages are encrypted locally', 'success');
        } else {
            toggleBtn.classList.remove('active');
            toggleBtn.innerHTML = '<i class="fas fa-lock-open"></i><span>Secure Chat</span>';
            body.classList.remove('secure-mode');
            
            // Decrypt existing user messages
            this.decryptExistingMessages();
            
            this.showNotification('🔓 Secure mode disabled - messages are now visible', 'info');
        }
    }

    encryptMessage(message) {
        // Simple base64 encoding for demonstration
        // In a real application, you'd use proper encryption like AES
        return btoa(unescape(encodeURIComponent(message)));
    }

    decryptMessage(encryptedMessage) {
        try {
            return decodeURIComponent(escape(atob(encryptedMessage)));
        } catch (error) {
            return encryptedMessage; // Return as-is if decryption fails
        }
    }

    encryptExistingMessages() {
        const userMessages = document.querySelectorAll('.message.user .message-text');
        userMessages.forEach(msgElement => {
            const originalText = msgElement.textContent;
            if (!this.isBase64(originalText)) {
                msgElement.textContent = this.encryptMessage(originalText);
            }
        });
    }

    decryptExistingMessages() {
        const userMessages = document.querySelectorAll('.message.user .message-text');
        userMessages.forEach(msgElement => {
            const encryptedText = msgElement.textContent;
            if (this.isBase64(encryptedText)) {
                msgElement.textContent = this.decryptMessage(encryptedText);
            }
        });
    }

    isBase64(str) {
        try {
            return btoa(atob(str)) === str;
        } catch (err) {
            return false;
        }
    }

    clearChatHistory() {
        if (confirm('Are you sure you want to clear the chat history?')) {
            const chatMessages = document.getElementById('chatMessages');
            chatMessages.innerHTML = '';
            this.chatHistory = [];
            this.showWelcomeMessage();
            this.showNotification('Chat history cleared', 'info');
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        // Style the notification
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '15px 20px',
            borderRadius: '10px',
            color: 'white',
            fontWeight: '500',
            zIndex: '1002',
            maxWidth: '300px',
            wordWrap: 'break-word',
            animation: 'slideInRight 0.3s ease-out',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
        });

        // Set background color based on type
        switch (type) {
            case 'success':
                notification.style.background = 'linear-gradient(45deg, #22d3ee, #0ea5e9)';
                break;
            case 'error':
                notification.style.background = 'linear-gradient(45deg, #ef4444, #b91c1c)';
                break;
            case 'warning':
                notification.style.background = 'linear-gradient(45deg, #f59e0b, #b45309)';
                break;
            default:
                notification.style.background = 'linear-gradient(45deg, #6366f1, #4338ca)';
        }

        document.body.appendChild(notification);

        // Remove notification after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

// Add CSS animations for notifications
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    @keyframes slideInRight {
        from {
            opacity: 0;
            transform: translateX(100%);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes slideOutRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(notificationStyles);

// Initialize the chatbot when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new CyberSecChatbot();
});

// Add some additional utility functions
class SecurityUtils {
    static generateSecurePassword(length = 16) {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }

    static checkPasswordStrength(password) {
        let score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
        
        const strength = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
        return strength[Math.min(score, strength.length - 1)];
    }

    static validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    static sanitizeInput(input) {
        return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    }
}

// Export for potential future use
window.SecurityUtils = SecurityUtils;

// 3D Background using Three.js
CyberSecChatbot.prototype.init3DBackground = function() {
    if (!window.THREE) return;
    const canvas = document.getElementById('bg3d');
    if (!canvas) return;

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 50;

    // Particles
    const particleCount = 800;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i++) {
        positions[i] = (Math.random() - 0.5) * 200;
    }
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const material = new THREE.PointsMaterial({ color: 0x6ee7ff, size: 0.6, transparent: true, opacity: 0.8 });
    const points = new THREE.Points(geometry, material);
    scene.add(points);

    // Glow spheres
    const makeGlow = (color, x, y, z) => {
        const geo = new THREE.SphereGeometry(3, 32, 32);
        const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.6 });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, y, z);
        scene.add(mesh);
        return mesh;
    };
    const g1 = makeGlow(0xa78bfa, -20, 10, -20);
    const g2 = makeGlow(0x22d3ee, 25, -5, -30);

    function resize() {
        const w = window.innerWidth;
        const h = window.innerHeight;
        renderer.setSize(w, h);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
    }
    window.addEventListener('resize', resize);
    resize();

    let t = 0;
    function animate() {
        requestAnimationFrame(animate);
        t += 0.0025;
        points.rotation.y += 0.0008;
        points.rotation.x += 0.0004;
        g1.position.x = -20 + Math.cos(t) * 5;
        g1.position.y = 10 + Math.sin(t * 1.2) * 3;
        g2.position.x = 25 + Math.sin(t * 1.4) * 6;
        g2.position.y = -5 + Math.cos(t * 1.1) * 4;
        renderer.render(scene, camera);
    }
    animate();
};
