
const express = require('express');
const { makeWASocket, useMultiFileAuthState, DisconnectReason } = require('@whiskeysockets/baileys');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');
const http = require('http');
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 5000;
const sessionsDir = './sessions';
const authCodesFile = './auth_codes.json';

// Store active WhatsApp sockets for each user
const userSockets = new Map();
const userConnections = new Map();

// Telegram redirect URL
const TELEGRAM_REDIRECT = 'https://t.me/reemasilhen';

// Initialize auth codes file with phone numbers
if (!fs.existsSync(authCodesFile)) {
    const initialAuthCodes = {
        "authorizedNumbers": [
            "9209778319"
        ],
        "adminNumbers": [
            "9209778319"
        ]
    };
    fs.writeFileSync(authCodesFile, JSON.stringify(initialAuthCodes, null, 2));
}

// Generate random phone number for new users
function generatePhoneNumber() {
    const number = Math.floor(1000000000 + Math.random() * 9000000000);
    return number.toString();
}

// Load auth codes from file
function loadAuthCodes() {
    try {
        const data = fs.readFileSync(authCodesFile, 'utf8');
        const authData = JSON.parse(data);
        
        // Convert new format to old format for compatibility
        if (authData.authorizedNumbers && Array.isArray(authData.authorizedNumbers)) {
            const convertedData = {};
            authData.authorizedNumbers.forEach(phone => {
                convertedData[phone] = {
                    phone: phone,
                    isAdmin: authData.adminNumbers && authData.adminNumbers.includes(phone),
                    createdAt: new Date().toISOString(),
                    lastLogin: null,
                    description: authData.adminNumbers && authData.adminNumbers.includes(phone) ? "Admin User" : "Authorized User"
                };
            });
            return convertedData;
        }
        
        return authData;
    } catch (error) {
        return {};
    }
}

// Save auth codes to file
function saveAuthCodes(authCodes) {
    // Convert back to new array format
    const authorizedNumbers = [];
    const adminNumbers = [];
    
    Object.values(authCodes).forEach(user => {
        if (user.phone) {
            authorizedNumbers.push(user.phone);
            if (user.isAdmin) {
                adminNumbers.push(user.phone);
            }
        }
    });
    
    const newFormat = {
        authorizedNumbers: authorizedNumbers,
        adminNumbers: adminNumbers
    };
    
    fs.writeFileSync(authCodesFile, JSON.stringify(newFormat, null, 2));
}

// Ensure sessions directory exists
if (!fs.existsSync(sessionsDir)) {
    fs.mkdirSync(sessionsDir);
}

// Session middleware with short timeout for auto-logout on refresh
app.use(session({
    secret: 'whatsapp-banner-tool-secret-key',
    resave: false,
    saveUninitialized: false, // Don't save empty sessions
    cookie: { 
        secure: false,
        maxAge: 30 * 60 * 1000, // 30 minutes only - auto logout on refresh
        httpOnly: true
    },
    rolling: false // Don't extend session on each request
}));

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.loggedIn) {
        return res.redirect('/login');
    }
    next();
}

// Sanitize user ID for safe file operations
function sanitizeUserID(userID) {
    return userID.replace(/[^a-zA-Z0-9_]/g, '');
}

// Get user session directory - each user gets their own WhatsApp session
function getUserSessionDir(userID) {
    const sanitized = sanitizeUserID(userID);
    // Create unique directory for each phone number
    const userSessionPath = path.join(sessionsDir, `user_${sanitized}`);
    
    // Ensure user's session directory exists
    if (!fs.existsSync(userSessionPath)) {
        fs.mkdirSync(userSessionPath, { recursive: true });
        console.log(`Created session directory for user: ${userID}`);
    }
    
    return userSessionPath;
}

// Login page
app.get('/login', (req, res) => {
    if (req.session.loggedIn) {
        return res.redirect('/');
    }

    let errorMessage = '';
    const error = req.query.error;
    if (error === 'missing') {
        errorMessage = '<div class="error">📱 Phone number is required!</div>';
    } else if (error === 'invalid') {
        errorMessage = '<div class="error">❌ Invalid phone number! Contact @reemasilhen on Telegram</div>';
    }

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔐 WhatsApp Banner Tool - Login</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #ff6b6b 0%, #4ecdc4 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 25px 50px rgba(0,0,0,0.15);
                padding: 40px;
                max-width: 400px;
                width: 100%;
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
            }
            .header h1 {
                color: #667eea;
                font-size: 2em;
                margin-bottom: 10px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: bold;
                color: #333;
            }
            .form-group input {
                width: 100%;
                padding: 15px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 16px;
                transition: all 0.3s ease;
                text-transform: uppercase;
            }
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            .btn {
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3);
            }
            .error {
                background: #ff6b6b;
                color: white;
                padding: 10px;
                border-radius: 8px;
                margin-bottom: 20px;
                text-align: center;
            }
            .contact-note {
                background: #f8f9fa;
                border: 2px solid #e9ecef;
                border-radius: 10px;
                padding: 15px;
                margin-top: 20px;
                text-align: center;
                font-size: 14px;
                color: #666;
            }
            .telegram-link {
                color: #0088cc;
                text-decoration: none;
                font-weight: bold;
            }
            .examples {
                margin-top: 10px;
                font-size: 12px;
                color: #999;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="header">
                <h1>🔐 Access Login</h1>
                <p>WhatsApp Banner Tool</p>
            </div>

            ${errorMessage}

            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="phone">📱 Phone Number</label>
                    <input type="text" id="phone" name="phone" placeholder="Enter phone number" maxlength="10" required>
                    <div class="examples">Enter your 10-digit phone number</div>
                </div>

                <button type="submit" class="btn">🚀 Login</button>
            </form>

            <div class="contact-note">
                <strong>Need Access?</strong><br>
                Contact <a href="${TELEGRAM_REDIRECT}" class="telegram-link" target="_blank">@reemasilhen</a> on Telegram
            </div>
        </div>

        <script>
            // Auto redirect to Telegram on invalid access code
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('error') === 'invalid') {
                setTimeout(() => {
                    window.open('${TELEGRAM_REDIRECT}', '_blank');
                }, 3000);
            }
            
            // Phone number validation
            document.getElementById('phone').addEventListener('input', function(e) {
                e.target.value = e.target.value.replace(/\D/g, '').substring(0, 10);
            });
        </script>
    </body>
    </html>
    `);
});

// Handle login
app.post('/login', (req, res) => {
    const { phone } = req.body;

    if (!phone) {
        return res.redirect('/login?error=missing');
    }

    const authCodes = loadAuthCodes();
    const validAuth = authCodes[phone];

    if (!validAuth) {
        return res.redirect('/login?error=invalid');
    }

    // Update last login
    validAuth.lastLogin = new Date().toISOString();
    saveAuthCodes(authCodes);

    // Set session
    req.session.loggedIn = true;
    req.session.authCode = validAuth.phone;
    req.session.isAdmin = validAuth.isAdmin || false;

    console.log(`User ${validAuth.phone} logged in successfully`);
    res.redirect('/dashboard');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Admin panel (only for admin users)
app.get('/admin', (req, res) => {
    if (!req.session.loggedIn) {
        return res.redirect('/login');
    }

    const authCodes = loadAuthCodes();
    const user = authCodes[req.session.authCode];

    if (!user || !user.isAdmin) {
        return res.status(403).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body { font-family: Arial; text-align: center; padding: 50px; background: #f0f0f0; }
                    .error { background: white; padding: 40px; border-radius: 10px; max-width: 500px; margin: 0 auto; }
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>🚫 Access Denied</h1>
                    <p>Only admin users can access this panel.</p>
                    <a href="/dashboard">← Back to Dashboard</a>
                </div>
            </body>
            </html>
        `);
    }

    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Admin API routes
app.get('/admin/users', (req, res) => {
    if (!req.session.loggedIn) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const authCodes = loadAuthCodes();
    const user = authCodes[req.session.authCode];

    if (!user || !user.isAdmin) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }

    res.json({ success: true, users: authCodes });
});

app.post('/admin/add-user', (req, res) => {
    if (!req.session.loggedIn) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const authCodes = loadAuthCodes();
    const adminUser = authCodes[req.session.authCode];

    if (!adminUser || !adminUser.isAdmin) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }

    const { phone, isAdmin, description } = req.body;

    if (!phone || phone.length !== 10) {
        return res.status(400).json({ success: false, message: 'Phone number must be 10 digits' });
    }

    if (authCodes[phone]) {
        return res.status(400).json({ success: false, message: 'Phone number already exists' });
    }

    authCodes[phone] = {
        phone: phone,
        isAdmin: isAdmin || false,
        createdAt: new Date().toISOString(),
        lastLogin: null,
        description: description || 'User created by admin'
    };

    saveAuthCodes(authCodes);
    console.log(`Admin ${req.session.authCode} added phone ${phone}`);

    res.json({ success: true, message: 'Phone number added successfully', phone: phone });
});

app.post('/admin/remove-user', (req, res) => {
    if (!req.session.loggedIn) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const authCodes = loadAuthCodes();
    const adminUser = authCodes[req.session.authCode];

    if (!adminUser || !adminUser.isAdmin) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }

    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({ success: false, message: 'Phone number required' });
    }

    if (!authCodes[phone]) {
        return res.status(404).json({ success: false, message: 'Phone number not found' });
    }

    if (authCodes[phone].isAdmin) {
        return res.status(400).json({ success: false, message: 'Cannot remove admin phone numbers' });
    }

    delete authCodes[phone];
    saveAuthCodes(authCodes);
    console.log(`Admin ${req.session.authCode} removed phone ${phone}`);

    res.json({ success: true, message: 'Phone number removed successfully' });
});

app.post('/admin/regenerate-code', (req, res) => {
    if (!req.session.loggedIn) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const authCodes = loadAuthCodes();
    const adminUser = authCodes[req.session.authCode];

    if (!adminUser || !adminUser.isAdmin) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }

    const { oldPhone } = req.body;

    if (!oldPhone || !authCodes[oldPhone]) {
        return res.status(404).json({ success: false, message: 'Phone number not found' });
    }

    const newPhone = generatePhoneNumber();
    
    // Copy user data to new phone
    const userData = { ...authCodes[oldPhone] };
    userData.phone = newPhone;
    
    // Add new phone and remove old one
    authCodes[newPhone] = userData;
    delete authCodes[oldPhone];
    
    saveAuthCodes(authCodes);

    console.log(`Admin ${req.session.authCode} regenerated phone from ${oldPhone} to ${newPhone}`);

    res.json({ success: true, message: 'Phone number regenerated', phone: newPhone });
});

// Root page - redirect to login if not authenticated, otherwise go to dashboard
app.get('/', (req, res) => {
    console.log('Root page accessed, checking authentication...');
    console.log('Session data:', req.session);

    // Check if user has valid session
    if (!req.session || !req.session.loggedIn) {
        console.log('No session found, redirecting to login');
        return res.redirect('/login');
    }

    // Validate user exists in auth codes database
    const authCodes = loadAuthCodes();
    const user = authCodes[req.session.authCode];

    if (!user) {
        console.log(`User ${req.session.authCode} not found in database, destroying session`);
        req.session.destroy((err) => {
            if (err) console.log('Session destroy error:', err);
            return res.redirect('/login');
        });
        return;
    }

    // User is authenticated, redirect to dashboard
    console.log(`User ${req.session.authCode} authenticated, redirecting to dashboard`);
    res.redirect('/dashboard');
});

// Dashboard/Tool page (protected)
app.get('/dashboard', requireAuth, (req, res) => {
    console.log('Dashboard accessed by authenticated user:', req.session.authCode);
    
    // Validate user exists in auth codes database
    const authCodes = loadAuthCodes();
    const user = authCodes[req.session.authCode];

    if (!user) {
        console.log(`User ${req.session.authCode} not found in database, destroying session`);
        req.session.destroy((err) => {
            if (err) console.log('Session destroy error:', err);
            return res.redirect('/login');
        });
        return;
    }

    // Set user data for further requests
    req.user = user;
    console.log(`User ${req.session.authCode} accessing dashboard`);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize WhatsApp connection for specific user with isolated sessions
async function connectUserToWhatsApp(userID, socketId = null) {
    try {
        console.log(`Initializing WhatsApp connection for user: ${userID}`);
        
        // First, properly close any existing connection for this user
        if (userSockets.has(userID)) {
            const existingSock = userSockets.get(userID);
            try {
                // Remove all event listeners to prevent duplicate handlers
                existingSock.ev.removeAllListeners();
                // Properly logout and close
                await existingSock.logout();
                existingSock.end();
            } catch (error) {
                console.log(`Error closing existing socket for ${userID}:`, error.message);
            }
            userSockets.delete(userID);
        }

        // Get user-specific session directory
        const userSessionDir = getUserSessionDir(userID);
        console.log(`Using session directory: ${userSessionDir}`);

        const { state, saveCreds } = await useMultiFileAuthState(userSessionDir);

        const sock = makeWASocket({
            auth: state,
            printQRInTerminal: false,
            generateHighQualityLinkPreview: true
        });

        sock.ev.on('creds.update', saveCreds);

        sock.ev.on('connection.update', async (update) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                console.log(`QR generated for user ${userID}`);
                const qrCodeDataURL = await QRCode.toDataURL(qr);
                // Send QR to specific user's socket
                if (socketId) {
                    io.to(socketId).emit('qr', qrCodeDataURL);
                } else {
                    // Send to specific user's room only
                    io.to(`user-${userID}`).emit('qr', qrCodeDataURL);
                }
            }

            if (connection === 'close') {
                const shouldReconnect = (lastDisconnect?.error)?.output?.statusCode !== DisconnectReason.loggedOut;
                userConnections.set(userID, false);
                
                console.log(`User ${userID} WhatsApp connection closed`);

                if (socketId) {
                    io.to(socketId).emit('disconnected');
                } else {
                    io.to(`user-${userID}`).emit('disconnected');
                }

                if (shouldReconnect) {
                    console.log(`Reconnecting user ${userID} in 5 seconds...`);
                    setTimeout(() => {
                        connectUserToWhatsApp(userID, socketId);
                    }, 5000);
                } else {
                    // Clean up user session completely
                    console.log(`Cleaning up session for user ${userID}`);
                    userSockets.delete(userID);
                    userConnections.delete(userID);
                    
                    // Optionally clean up session files for security
                    // (commented out to preserve login - uncomment if you want to clear on logout)
                    /*
                    try {
                        const userSessionDir = getUserSessionDir(userID);
                        if (fs.existsSync(userSessionDir)) {
                            fs.rmSync(userSessionDir, { recursive: true, force: true });
                            console.log(`Cleaned session files for user ${userID}`);
                        }
                    } catch (error) {
                        console.log(`Error cleaning session files for ${userID}:`, error.message);
                    }
                    */
                }
            } else if (connection === 'open') {
                userConnections.set(userID, true);

                if (socketId) {
                    io.to(socketId).emit('connected');
                } else {
                    io.to(`user-${userID}`).emit('connected');
                }

                console.log(`User ${userID} successfully connected to WhatsApp`);
            }
        });

        userSockets.set(userID, sock);
        return sock;

    } catch (error) {
        console.error(`Error connecting user ${userID} to WhatsApp:`, error);
        if (socketId) {
            io.to(socketId).emit('error', error.message);
        } else {
            io.to(`user-${userID}`).emit('error', error.message);
        }
        return null;
    }
}

// Get user's socket status
app.get('/user-status', (req, res) => {
    console.log('User status check, session:', req.session);

    // Check if user is authenticated
    if (!req.session || !req.session.loggedIn) {
        console.log('No authentication for user-status');
        return res.status(401).json({ 
            error: 'Not authenticated',
            connected: false,
            userID: null,
            redirectToLogin: true
        });
    }

    const authCodes = loadAuthCodes();
    if (!authCodes[req.session.authCode]) {
        console.log('User not found in database for user-status');
        req.session.destroy((err) => {
            if (err) console.log('Session destroy error:', err);
        });
        return res.status(401).json({ 
            error: 'User not found',
            connected: false,
            userID: null,
            redirectToLogin: true
        });
    }

    const userID = req.session.authCode;
    const isConnected = userConnections.get(userID) || false;
    console.log(`User ${userID} status: connected=${isConnected}`);
    res.json({ 
        connected: isConnected, 
        userID: userID,
        user: authCodes[userID]
    });
});

// Process groups - Banner Tool Logic
app.post('/process-groups', requireAuth, async (req, res) => {
    const userID = req.session.authCode;
    const sock = userSockets.get(userID);
    const isConnected = userConnections.get(userID) || false;

    if (!isConnected || !sock) {
        return res.json({ success: false, message: 'WhatsApp not connected' });
    }

    const { groupLinks, makeAdmin, foreignNumbers } = req.body;
    const links = groupLinks.split('\n').filter(link => link.trim());
    const numbers = foreignNumbers.filter(num => num.trim());

    try {
        for (const link of links) {
            try {
                io.emit('user-status', { userID, message: `🔗 Processing group: ${link}` });

                // Extract group code from invite link
                const groupCode = link.split('/').pop().split('?')[0];

                // Join group
                const joinResult = await sock.groupAcceptInvite(groupCode);
                io.emit('user-status', { userID, message: `✅ Joined group: ${joinResult}` });

                // Wait for group join to complete
                await new Promise(resolve => setTimeout(resolve, 3000));

                // Get group metadata
                const groupMetadata = await sock.groupMetadata(joinResult);
                const currentUserId = sock.user.id;

                if (makeAdmin) {
                    io.emit('user-status', { userID, message: `👥 Making all members admin...` });

                    // Get all non-admin participants (excluding current user)
                    const nonAdmins = groupMetadata.participants
                        .filter(p => !p.admin && p.id !== currentUserId);

                    if (nonAdmins.length > 0) {
                        const numbersToPromote = nonAdmins.map(p => p.id);

                        try {
                            await sock.groupParticipantsUpdate(joinResult, numbersToPromote, 'promote');
                            io.emit('user-status', { userID, message: `🔥 Promoted ${numbersToPromote.length} members to admin` });
                        } catch (promoteError) {
                            io.emit('user-status', { userID, message: `⚠️ Failed to promote some members: ${promoteError.message}` });
                        }

                        // Ensure logged-in user is also admin
                        try {
                            await sock.groupParticipantsUpdate(joinResult, [currentUserId], 'promote');
                            io.emit('user-status', { userID, message: `👑 Current user promoted to admin` });
                        } catch (selfPromoteError) {
                            io.emit('user-status', { userID, message: `⚠️ Already admin or failed to promote self` });
                        }
                    }

                    await new Promise(resolve => setTimeout(resolve, 2000));
                }

                // Add foreign numbers rapidly
                if (numbers.length > 0) {
                    io.emit('user-status', { userID, message: `🌍 Adding ${numbers.length} foreign numbers...` });

                    const formattedNumbers = numbers.map(num => {
                        // Clean and format number
                        let formatted = num.replace(/\D/g, '');
                        if (formatted.startsWith('00')) {
                            formatted = formatted.substring(2);
                        }
                        if (!formatted.includes('@')) {
                            formatted = formatted + '@s.whatsapp.net';
                        }
                        return formatted;
                    });

                    try {
                        await sock.groupParticipantsUpdate(joinResult, formattedNumbers, 'add');
                        io.emit('user-status', { userID, message: `🚀 Successfully added all foreign numbers` });
                    } catch (addError) {
                        if (addError.message.includes('not allowed') || addError.message.includes('privacy')) {
                            io.emit('user-status', { userID, message: `⚠️ Group privacy settings prevent adding numbers` });
                        } else if (addError.message.includes('full') || addError.message.includes('capacity')) {
                            io.emit('user-status', { userID, message: `⚠️ Group is full, skipping number additions` });
                        } else {
                            io.emit('user-status', { userID, message: `⚠️ Failed to add numbers: ${addError.message}` });
                        }
                    }
                }

                await new Promise(resolve => setTimeout(resolve, 1500));

            } catch (groupError) {
                io.emit('user-status', { userID, message: `❌ Error processing group ${link}: ${groupError.message}` });
            }
        }

        io.emit('user-status', { userID, message: '🎉 All groups processed successfully! Banner tool complete.' });
        res.json({ success: true });

    } catch (error) {
        io.emit('user-status', { userID, message: `💥 Error: ${error.message}` });
        res.json({ success: false, message: error.message });
    }
});

// Restart session for specific user
app.post('/restart-session', requireAuth, async (req, res) => {
    const userID = req.session.authCode;

    try {
        console.log(`Restarting session for user ${userID}`);

        // Step 1: Properly close current connection for this user
        if (userSockets.has(userID)) {
            const sock = userSockets.get(userID);
            try {
                // Remove all event listeners first
                sock.ev.removeAllListeners();
                // Logout properly to clean WhatsApp session
                await sock.logout();
                // Close the socket
                sock.end();
            } catch (error) {
                console.log(`Error during logout for ${userID}:`, error.message);
            }
            userSockets.delete(userID);
        }

        // Step 2: Delete user's session files completely
        const userSessionDir = getUserSessionDir(userID);
        if (fs.existsSync(userSessionDir)) {
            fs.rmSync(userSessionDir, { recursive: true, force: true });
            console.log(`Deleted session directory for user ${userID}`);
        }

        // Step 3: Reset user connection state
        userConnections.set(userID, false);

        // Step 4: Notify user that session is being restarted
        io.to(`user-${userID}`).emit('disconnected');

        // Step 5: Initialize fresh session with new QR
        setTimeout(async () => {
            console.log(`Initializing fresh session for user ${userID}`);
            await connectUserToWhatsApp(userID);
        }, 2000);

        res.json({ success: true, message: 'Session restarted successfully' });
    } catch (error) {
        console.error(`Error restarting session for ${userID}:`, error);
        res.json({ success: false, message: error.message });
    }
});

// Socket.io connection
io.on('connection', (socket) => {
    console.log('Client connected');

    // Handle user session initialization with proper authentication check
    socket.on('initialize-session', (sessionData) => {
        // Validate session data
        const userID = sessionData?.userPhone;
        
        if (!userID) {
            console.log(`Socket ${socket.id} missing user authentication`);
            socket.emit('error', 'Authentication required');
            socket.disconnect();
            return;
        }
        
        // Verify user exists in auth codes
        const authCodes = loadAuthCodes();
        if (!authCodes[userID]) {
            console.log(`Socket ${socket.id} invalid user: ${userID}`);
            socket.emit('error', 'Invalid user');
            socket.disconnect();
            return;
        }
        
        socket.userID = userID;
        socket.join(`user-${userID}`);
        console.log(`Socket ${socket.id} authenticated and joined room for user ${userID}`);

        // Check if user is connected to WhatsApp
        const isConnected = userConnections.get(userID) || false;
        if (isConnected) {
            socket.emit('connected');
        } else {
            // Initialize WhatsApp connection for this user if not exists
            if (!userSockets.has(userID)) {
                console.log(`Initializing new WhatsApp session for user ${userID}`);
                connectUserToWhatsApp(userID, socket.id);
            } else {
                socket.emit('disconnected');
            }
        }
    });

    // Handle manual QR request (for restart scenarios)
    socket.on('request-qr', async () => {
        if (socket.userID) {
            const userID = socket.userID;
            const isConnected = userConnections.get(userID) || false;

            console.log(`Manual QR request for user ${userID}, connected: ${isConnected}`);

            if (!isConnected) {
                // If there's an existing socket, close it first
                if (userSockets.has(userID)) {
                    const existingSock = userSockets.get(userID);
                    try {
                        existingSock.ev.removeAllListeners();
                        existingSock.end();
                    } catch (error) {
                        console.log(`Error closing existing socket: ${error.message}`);
                    }
                    userSockets.delete(userID);
                }

                // Create fresh connection to generate new QR
                console.log(`Generating fresh QR for user ${userID}`);
                await connectUserToWhatsApp(userID, socket.id);
            } else {
                // User is already connected, inform them
                socket.emit('error', 'Already connected to WhatsApp');
            }
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

// Clear all existing sessions on server start
function clearAllSessions() {
    try {
        // Clear all active connections
        userSockets.clear();
        userConnections.clear();

        console.log('✅ All previous sessions cleared');
    } catch (error) {
        console.log('Error clearing sessions:', error.message);
    }
}

// Start server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log('Multi-user WhatsApp Banner Tool ready!');

    const authCodes = loadAuthCodes();
    const adminCodes = Object.keys(authCodes).filter(code => authCodes[code].isAdmin);
    console.log(`Admin auth codes: ${adminCodes.join(', ')}`);

    // Clear all sessions on startup
    clearAllSessions();

    console.log('🔐 All users must login again with auth codes');
});
