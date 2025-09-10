import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();
app.use(express.json());

// Serve static files
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// Basic CORS for local dev
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// Minimal JWT (HS256) without external deps
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
function signJwt(payload, expiresInSeconds = 60 * 60 * 8) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + expiresInSeconds };
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(body));
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${data}.${signature}`;
}
function verifyJwt(token) {
  try {
    const [headerB64, payloadB64, signature] = token.split(".");
    if (!headerB64 || !payloadB64 || !signature) return null;
    const data = `${headerB64}.${payloadB64}`;
    const expected = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(data)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    if (expected !== signature) return null;
    const payload = JSON.parse(Buffer.from(payloadB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  const payload = verifyJwt(token);
  if (!payload) return res.status(401).json({ error: "Invalid or expired token" });
  req.user = payload;
  next();
}

// Auth endpoint
// If ADMIN_EMAIL and ADMIN_PASSWORD are set, require exact match.
// If ADMIN_PASSWORD_HASH is set (hex of sha256), verify against hash.
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const adminEmail = process.env.ADMIN_EMAIL || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD || 'passw0rd';
  const adminPasswordHashHex = process.env.ADMIN_PASSWORD_HASH; // sha256 hex

  console.log('Login attempt:', { email, adminEmail, hasPasswordHash: !!adminPasswordHashHex });

  let ok = true;
  // Check email match
  ok = ok && email === adminEmail;
  
  // Check password - prefer hash if set, otherwise plain text
  if (adminPasswordHashHex) {
    const hash = crypto.createHash("sha256").update(password, "utf8").digest("hex");
    ok = ok && hash === adminPasswordHashHex;
  } else {
    ok = ok && password === adminPassword;
  }

  if (!ok) {
    console.log('Login failed for:', email);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  console.log('Login successful for:', email);
  const token = signJwt({ sub: email, email });
  res.json({ token, profile: { name: email.split("@")[0], email } });
});

// Profile management endpoints
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ 
    email: req.user.email, 
    name: req.user.email.split("@")[0] 
  });
});

app.post("/profile/update", authMiddleware, (req, res) => {
  const { newEmail, newPassword, currentPassword } = req.body || {};
  
  if (!newEmail && !newPassword) {
    return res.status(400).json({ error: "No changes provided" });
  }
  
  const adminEmail = process.env.ADMIN_EMAIL || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD || 'passw0rd';
  const adminPasswordHashHex = process.env.ADMIN_PASSWORD_HASH;
  
  // Verify current password
  let currentPasswordValid = false;
  if (adminPasswordHashHex) {
    const hash = crypto.createHash("sha256").update(currentPassword, "utf8").digest("hex");
    currentPasswordValid = hash === adminPasswordHashHex;
  } else {
    currentPasswordValid = currentPassword === adminPassword;
  }
  
  if (!currentPasswordValid) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }
  
  // For demo purposes, we'll just return success
  // In a real app, you'd update the database or config
  res.json({ 
    message: "Profile updated successfully",
    profile: { 
      email: newEmail || req.user.email, 
      name: (newEmail || req.user.email).split("@")[0] 
    }
  });
});

// Secure chat endpoint
app.post("/chat", authMiddleware, async (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== "string") return res.status(400).json({ error: "message is required" });
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === "your_gemini_api_key_here") {
      // Demo mode - return a mock response
      console.log("Demo mode: No API key configured, returning mock response");
      // Generate contextual responses based on the message
      let responseText = "";
      
      if (message.toLowerCase().includes("vulnerability") || message.toLowerCase().includes("threat")) {
        responseText = `Threats and vulnerabilities are fundamental concepts in cybersecurity:

**Vulnerability** is a weakness or flaw in a system, application, or process that could be exploited. Examples include:
• Unpatched software
• Weak passwords
• Misconfigured systems
• Human error

**Threat** is any potential danger that could exploit a vulnerability. Examples include:
• Malicious hackers
• Malware
• Insider threats
• Natural disasters

**Risk** is the likelihood that a threat will exploit a vulnerability, resulting in harm to your organization.

Think of it this way: A vulnerability is like an unlocked door, a threat is like a potential burglar, and risk is the probability that the burglar will find and use that unlocked door.

To manage these effectively, implement a comprehensive security program that includes regular vulnerability assessments, threat intelligence, and risk management processes.`;
      } else if (message.toLowerCase().includes("password")) {
        responseText = `Here are essential password security best practices:

**Strong Password Creation:**
• Use at least 12 characters
• Include uppercase, lowercase, numbers, and symbols
• Avoid dictionary words and personal information
• Use unique passwords for each account

**Password Management:**
• Use a reputable password manager
• Enable two-factor authentication (2FA)
• Regularly update passwords
• Never share passwords

**Additional Security:**
• Monitor for data breaches
• Use biometric authentication when available
• Implement account lockout policies
• Educate users on phishing prevention

Remember, the goal is to make passwords both strong and manageable through proper tools and practices.`;
      } else if (message.toLowerCase().includes("phishing") || message.toLowerCase().includes("social engineering")) {
        responseText = `Phishing is a social engineering attack where cybercriminals impersonate legitimate entities to steal sensitive information. Here's how to protect yourself:

**Common Phishing Techniques:**
• Email spoofing
• Fake websites
• SMS phishing (smishing)
• Voice phishing (vishing)

**Red Flags to Watch For:**
• Urgent or threatening language
• Suspicious sender addresses
• Poor grammar and spelling
• Requests for sensitive information
• Unexpected attachments or links

**Protection Strategies:**
• Verify sender identity independently
• Hover over links before clicking
• Use multi-factor authentication
• Keep software updated
• Report suspicious emails

**Best Practices:**
• Never click suspicious links
• Don't download unexpected attachments
• Verify requests through official channels
• Educate employees regularly

When in doubt, contact the organization directly through their official website or phone number.`;
      } else if (message.toLowerCase().includes("security") || message.toLowerCase().includes("cyber") || message.toLowerCase().includes("hack") || message.toLowerCase().includes("attack") || message.toLowerCase().includes("malware") || message.toLowerCase().includes("firewall") || message.toLowerCase().includes("encryption") || message.toLowerCase().includes("network") || message.toLowerCase().includes("secure")) {
        responseText = `I'd be happy to help with your cybersecurity question! Here's some general guidance:

**Cybersecurity Fundamentals:**
• **Defense in Depth**: Implement multiple layers of security controls
• **Regular Updates**: Keep all software and systems patched
• **Access Control**: Implement least privilege principles
• **Monitoring**: Use security monitoring and logging
• **Incident Response**: Have a plan for security incidents

**Common Security Measures:**
• Multi-factor authentication (MFA)
• Regular security awareness training
• Network segmentation
• Data encryption (at rest and in transit)
• Regular backups and recovery testing

**Best Practices:**
• Conduct regular security assessments
• Implement a security framework (NIST, ISO 27001)
• Monitor for threats and vulnerabilities
• Maintain an incident response plan
• Regular security training for all users

For more specific guidance on your question, please configure your Gemini API key to get detailed, real-time responses.`;
      } else {
        responseText = `I'd be happy to help with your cybersecurity question! However, I'm currently running in demo mode. 

To get comprehensive, real-time AI responses, please configure your Gemini API key:

1. Visit: https://makersuite.google.com/app/apikey
2. Create an API key
3. Update the GEMINI_API_KEY in your .env file
4. Restart the server

Once configured, I'll provide detailed, up-to-date cybersecurity guidance tailored to your specific needs.`;
      }
      
      const mockResponse = {
        candidates: [{
          content: {
            parts: [{
              text: responseText
            }]
          }
        }]
      };
      return res.json(mockResponse);
    }
    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + apiKey,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: message }] }] })
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
  console.log("Open http://localhost:3000 to access the login page");
});
