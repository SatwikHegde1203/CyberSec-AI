# CyberSec AI Chatbot

A secure AI-powered cybersecurity assistant with JWT authentication and 3D animated background.

## Features

- 🔐 Secure JWT-based authentication
- 🤖 AI-powered cybersecurity assistance via Google Gemini API
- 🎨 Modern 3D animated background with Three.js
- 👤 User profile management
- 🔒 Secure chat mode with local encryption
- 📱 Responsive design

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure API key:**
   - Get your Google Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Edit `.env` file and replace `your_gemini_api_key_here` with your actual API key

3. **Start the server:**
   ```bash
   npm start
   # or
   node server.js
   ```

4. **Access the application:**
   - Open your browser and go to `http://localhost:3000`
   - Login with default credentials:
     - **Username:** `admin`
     - **Password:** `passw0rd`

## Default Credentials

- **Username:** `admin`
- **Password:** `passw0rd`

You can change these by setting environment variables:
```bash
ADMIN_EMAIL=your_email@example.com
ADMIN_PASSWORD=your_secure_password
```

## Environment Variables

- `GEMINI_API_KEY` - Your Google Gemini API key (required)
- `ADMIN_EMAIL` - Admin email (default: admin)
- `ADMIN_PASSWORD` - Admin password (default: passw0rd)
- `JWT_SECRET` - JWT signing secret (optional, has default)

## Project Structure

- `server.js` - Express server with authentication and API endpoints
- `login.html` - Login page with 3D background
- `index.html` - Main chat interface
- `script.js` - Frontend JavaScript with authentication and chat logic
- `style.css` - Modern styling with 3D theme
- `.env` - Environment configuration

## API Endpoints

- `POST /auth/login` - User authentication
- `POST /chat` - AI chat (requires authentication)

## Security Features

- JWT token-based authentication
- Password hashing support
- CORS protection
- Input validation
- Secure session management


## Results

![Login](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/login.html)
![Profile Settings](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/Profile-settings.png)
![Change User Name](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/Change-username.png)
![Change password](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/Change-password.png)
![Bot Home page](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/Bot-home-page.png)
![Secure chat mode off](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/secure-chat-desabled.png)
![Secure chat mode on](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/Secure-chat-enabled.png)
![Working](https://github.com/SatwikHegde1203/CyberSec-AI/blob/main/Working.png)
