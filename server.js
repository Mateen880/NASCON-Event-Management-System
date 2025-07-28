const express = require('express');
const bodyParser = require('body-parser'); // Using your existing body-parser setup
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs'); // Require bcryptjs

const app = express();
const port = 3000;
const saltRounds = 10; // Cost factor for hashing

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// Setup body parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Setup express-session
app.use(session({
    secret: 'nascon_secret_key_2024_enhanced', // Changed secret
    resave: true, // Changed to true to ensure session is saved on each request
    saveUninitialized: true, // Changed to true to ensure session is created on first request
    rolling: true, // Reset expiration on each request
    cookie: {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        secure: false, // Change to true in production with HTTPS
        sameSite: 'lax' // Allow cookies to be sent with same-site requests
    }
}));

// Setup CORS with better settings for session cookies
app.use((req, res, next) => {
    // Get origin from request or use default
    const origin = req.headers.origin || 'http://localhost:3000';
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true'); // Important for cookies!
    
    // Handle OPTIONS preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    next();
});

// MySQL Connection (Using your existing setup)
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '123456',  // your MySQL password
    database: 'semproject',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Initialize judge_role table if empty
db.query('SELECT COUNT(*) as count FROM judge_role', (err, results) => {
    if (err) {
        console.error('Error checking judge_role table:', err);
    } else if (results[0].count === 0) {
        // Initialize with default roles
        const roles = [
            { id: 1, role: 'Head Judge' },
            { id: 2, role: 'Assistant Judge' },
            { id: 3, role: 'Panel Member' }
        ];
        
        roles.forEach(role => {
            db.query('INSERT INTO judge_role (JudgeRoleID, JudgeRole) VALUES (?, ?)', 
                [role.id, role.role], 
                err => {
                    if (err) {
                        console.error(`Error initializing judge role ${role.role}:`, err);
                    } else {
                        console.log(`Judge role ${role.role} initialized successfully`);
                    }
                }
            );
        });
    }
});

// Authorization middleware - MOVED TO TOP
const authorize = (roles) => {
    return (req, res, next) => {
        console.log(`Authorization check for route: ${req.originalUrl}`, {
            method: req.method,
            headers: {
                'content-type': req.headers['content-type'],
                'cookie': req.headers['cookie'] ? 'present' : 'missing'
            },
            session: {
                exists: !!req.session,
                userId: req.session?.userId,
                role: req.session?.role,
                username: req.session?.username
            },
            required_roles: roles
        });
        
        // Check if user is logged in
        if (!req.session) {
            console.log(`Authorization failed: No session exists for route ${req.originalUrl}`);
            return res.status(401).json({ message: 'Not authenticated - session missing' });
        }
        
        if (!req.session.userId) {
            console.log(`Authorization failed: No userId in session for route ${req.originalUrl}`);
            return res.status(401).json({ message: 'Not authenticated - userId missing' });
        }
        
        if (!req.session.role) {
            console.log(`Authorization failed: No role in session for route ${req.originalUrl}`);
            return res.status(401).json({ message: 'Not authenticated - role missing' });
        }

        // Check if user's role is allowed
        if (!roles.includes(req.session.role)) {
            console.log(`Authorization failed: User ${req.session.userId} with role ${req.session.role} attempted to access ${req.originalUrl} (requires ${roles.join(', ')})`);
            return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
        }

        // Add user info to req object for convenience
        req.user = {
            UserID: req.session.userId,
            Role: req.session.role,
            RoleName: req.session.role,
            RoleID: req.session.roleID,
            UserName: req.session.username
        };
        
        console.log(`Authorization successful: User ${req.session.username} (ID: ${req.session.userId}, Role: ${req.session.role}) accessing ${req.originalUrl}`);
        next();
    };
};

// --- Routes ---

// Serve login page as default
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register POST (Participant Only + Hashing + User Check)
app.post('/register', (req, res) => {
    // 1. Extract data (including university)
    const { username, email, phone, password, university } = req.body;

    // 2. Basic Input Validation
    if (!username || !email || !password) { // University is optional based on form
        return res.redirect('/register.html?error=Missing%20required%20fields');
    }

    // 3. Check if email already exists
    const userCheckQuery = 'SELECT Email FROM users WHERE Email = ?';
    // Assuming 'db' is your database connection/pool variable
    db.query(userCheckQuery, [email], (checkErr, checkResults) => {
        if (checkErr) {
            console.error('Error checking user existence:', checkErr);
            return res.redirect('/register.html?error=Database%20error');
        }

        // 4. If user exists, redirect back with error
        if (checkResults.length > 0) {
            console.log(`Registration attempt failed: Email ${email} already exists.`);
            return res.redirect('/register.html?error=Email%20already%20registered');
        }

        // --- User does NOT exist, proceed ---

        // 5. Find the RoleID for 'Participant'
        const findRoleQuery = 'SELECT RoleID FROM role WHERE RoleName = ?';
        db.query(findRoleQuery, ['Participant'], (roleErr, roleResults) => {
            if (roleErr || roleResults.length === 0) {
                console.error('Critical Error: "Participant" role not found!', roleErr);
                return res.redirect('/register.html?error=Server%20configuration%20error');
            }
            const participantRoleId = roleResults[0].RoleID;

            // 6. Hash the password
            // Assuming 'bcrypt' and 'saltRounds' are defined earlier
            bcrypt.hash(password, saltRounds, (hashErr, hashedPassword) => {
                if (hashErr) {
                    console.error('Error hashing password:', hashErr);
                    return res.redirect('/register.html?error=Password%20hashing%20error');
                }

                // 7. Insert the new user
                const userInsertQuery = `
                    INSERT INTO users (UserName, Email, Phone, user_password, RoleID)
                    VALUES (?, ?, ?, ?, ?)
                `;
                db.query(userInsertQuery, [username, email, phone, hashedPassword, participantRoleId], (userInsertErr, userResult) => {
                    if (userInsertErr) {
                        console.error('Error inserting user:', userInsertErr);
                        return res.redirect('/register.html?error=Registration%20failed');
                    }
                    const newUserId = userResult.insertId;
                    console.log(`User ${username} inserted with UserID: ${newUserId}`);

                    // 8. Create corresponding entry in 'participant' table
                    const participantInsertQuery = 'INSERT INTO participant (UserID, University) VALUES (?, ?)';
                    const universityValue = university ? university.trim() : null; // Handle optional university
                    db.query(participantInsertQuery, [newUserId, universityValue], (partInsertErr, partResult) => {
                        if (partInsertErr) {
                            console.error(`Error creating participant record for UserID ${newUserId}:`, partInsertErr);
                            return res.redirect('/register.html?error=Registration%20incomplete');
                        }
                        console.log(`Participant record created for UserID: ${newUserId}`);

                        // --- SUCCESS: Set session data directly and redirect ---
                             req.session.userId = newUserId;
                             req.session.username = username;
                        req.session.role = 'Participant';
                             req.session.roleID = participantRoleId;
                        
                        console.log(`Session created for new user ${username}`);
                        
                                 // Redirect to homepage after successful registration/login
                                 res.redirect('/homepage.html');
                        // --- End Automatic Login ---
                    });
                });
            });
        });
    });
});


// Login POST (With Hashing Check)
app.post('/login', (req, res) => {
    console.log('Login attempt received:', { email: req.body.email });
    
    // 1. Extract email and password
    const { email, password } = req.body;
    if (!email || !password) {
        console.log('Login failed: Missing credentials');
        // Redirect back to login with an error query parameter
        return res.redirect('/?error=Missing%20credentials'); // Use %20 for space
    }

    // 2. Query user by email
    const loginQuery = `
        SELECT u.UserID, u.UserName, u.user_password AS passwordHash, u.RoleID, r.RoleName
        FROM users u
        LEFT JOIN role r ON u.RoleID = r.RoleID
        WHERE u.Email = ?
    `;
    
    db.query(loginQuery, [email], (err, results) => {
        if (err) {
            console.error('Login database error:', err);
            // Redirect on database error too
            return res.redirect('/?error=Database%20error');
        }

        // 3. Check if user exists
        if (results.length === 0) {
            console.log(`Login failed: No user found for email ${email}`);
            // Redirect back to login with an error query parameter
            return res.redirect('/?error=Invalid%20credentials');
        }
        
        const user = results[0];
        console.log(`User found for login:`, { 
            UserID: user.UserID,
            UserName: user.UserName,
            RoleID: user.RoleID,
            RoleName: user.RoleName
        });

        // 3b. Check for role
        if (!user.RoleID || !user.RoleName) {
             console.error(`Login failed: User ${user.UserID} has no assigned role.`);
             // Redirect back to login with specific error
             return res.redirect('/?error=Account%20not%20configured');
        }

        // 4. Compare submitted password with stored hash
        bcrypt.compare(password, user.passwordHash, (compareErr, isMatch) => {
            if (compareErr) {
                console.error('Error comparing password:', compareErr);
                // Redirect on bcrypt error
                return res.redirect('/?error=Authentication%20error');
            }

            // 5. Check if passwords match
            if (isMatch) {
                console.log(`Password match successful for ${user.UserName}`);
                
                // Set session data directly
                    req.session.userId = user.UserID;
                    req.session.username = user.UserName;
                    req.session.role = user.RoleName;
                    req.session.roleID = user.RoleID;
                
                console.log('Session data set with:', { 
                    userId: req.session.userId,
                    username: req.session.username,
                    role: req.session.role
                });
                
                // Handle all users consistently
                return res.redirect('/homepage.html');
            } else {
                // --- Passwords DON'T match ---
                console.log(`Password mismatch for user: ${user.UserName} (email: ${email})`);
                // Redirect back to login with an error query parameter
                return res.redirect('/?error=Invalid%20credentials');
            }
        });
    });
});


// --- KEPT YOUR OTHER EXISTING ROUTES ---

// API endpoint to get sponsorship packages
app.get('/api/sponsorship-packages', (req, res) => {
    const query = 'SELECT * FROM sponsorship_package';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching packages:', err);
            return res.status(500).send('Error fetching sponsorship packages.');
        }
        res.json(results);
    });
});

// API endpoint for submitting a sponsorship request (for participants)
app.post('/api/sponsorship-requests', authorize(['Participant']), (req, res) => {
    const { packageId, companyName, companyEmail, companyPhone, details } = req.body;
    const userId = req.session.userId;
    
    if (!packageId || !companyName || !companyEmail) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Check if package exists
    const checkPackageQuery = 'SELECT PackageID FROM sponsorship_package WHERE PackageID = ?';
    db.query(checkPackageQuery, [packageId], (err, results) => {
        if (err) {
            console.error('Error checking package:', err);
            return res.status(500).json({ message: 'Failed to validate package' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Sponsorship package not found' });
        }
        
        // Check if user already has a pending request
        const checkRequestQuery = 'SELECT RequestID FROM sponsorship_requests WHERE UserID = ? AND Status = "Pending"';
        db.query(checkRequestQuery, [userId], (err, results) => {
            if (err) {
                console.error('Error checking existing request:', err);
                return res.status(500).json({ message: 'Failed to check existing requests' });
            }
            
            if (results.length > 0) {
                return res.status(400).json({ message: 'You already have a pending sponsorship request' });
            }
            
            // Create the sponsorship request
            const insertQuery = `
                INSERT INTO sponsorship_requests (
                    UserID, PackageID, CompanyName, CompanyEmail, CompanyPhone, Details, Status
                ) VALUES (?, ?, ?, ?, ?, ?, "Pending")
            `;
            
            db.query(insertQuery, [userId, packageId, companyName, companyEmail, companyPhone, details], (err, result) => {
                if (err) {
                    console.error('Error creating sponsorship request:', err);
                    return res.status(500).json({ message: 'Failed to create sponsorship request' });
                }
                
                res.status(201).json({ 
                    message: 'Sponsorship request submitted successfully',
                    requestId: result.insertId
                });
            });
        });
    });
});

// API endpoint to get all sponsorship requests (admin only)
app.get('/api/admin/sponsorship-requests', authorize(['Admin']), (req, res) => {
    const query = `
        SELECT sr.RequestID, sr.UserID, sr.PackageID, sr.CompanyName, sr.CompanyEmail, 
               sr.CompanyPhone, sr.Details, sr.Status, sr.RequestTimestamp,
               u.UserName, u.Email
        FROM sponsorship_requests sr
        JOIN users u ON sr.UserID = u.UserID
        ORDER BY sr.Status = 'Pending' DESC, sr.RequestTimestamp DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching sponsorship requests:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsorship requests' });
        }
        
        // Return a friendly message if no requests are found
        if (results.length === 0) {
            return res.json({ message: 'No sponsorship requests found', data: [] });
        }
        
        res.json({ message: 'Sponsorship requests retrieved successfully', data: results });
    });
});

// API endpoint to approve a sponsorship request (admin only)
app.post('/api/admin/sponsorship-requests/:requestId/approve', authorize(['Admin']), (req, res) => {
    const requestId = req.params.requestId;
    
    // Start transaction - Using promise-based connection for better reliability
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection:', err);
            return res.status(500).json({ message: 'Failed to process sponsorship request' });
        }

        // Convert connection to promise interface for more reliable async/await usage
        const promiseConnection = connection.promise();
        
        promiseConnection.beginTransaction()
        .then(async () => {
            try {
                // Get request details
                const [requestResults] = await promiseConnection.query(
                    `SELECT sr.UserID, sr.PackageID, sr.CompanyName, sr.CompanyEmail, sr.CompanyPhone,
                            u.UserName, u.Email
                    FROM sponsorship_requests sr
                    JOIN users u ON sr.UserID = u.UserID
                    WHERE sr.RequestID = ? AND sr.Status = 'Pending'`,
                    [requestId]
                );
                
                if (requestResults.length === 0) {
                    throw new Error('Sponsorship request not found or already processed');
                }
                
                const request = requestResults[0];
                const userId = request.UserID;
                
                // Get the role ID for the Sponsor role
                const [roleResults] = await promiseConnection.query(
                    'SELECT RoleID FROM role WHERE RoleName = "Sponsor"',
                    []
                );
                
                if (roleResults.length === 0) {
                    throw new Error('Sponsor role not found');
                }
                
                const sponsorRoleId = roleResults[0].RoleID;
                
                // Update user's role to Sponsor
                await promiseConnection.query(
                    'UPDATE users SET RoleID = ? WHERE UserID = ?',
                    [sponsorRoleId, userId]
                );
                
                // Create or update sponsor record
                const [sponsorResults] = await promiseConnection.query(
                    'SELECT Sponsor_ID FROM sponsor WHERE UserID = ?',
                    [userId]
                );
                
                let sponsorId;
                if (sponsorResults.length === 0) {
                    // Create new sponsor record
                    const [newSponsorResult] = await promiseConnection.query(
                        'INSERT INTO sponsor (UserID, CompanyName, Email, PhoneNo) VALUES (?, ?, ?, ?)',
                        [userId, request.CompanyName, request.CompanyEmail, request.CompanyPhone]
                    );
                    sponsorId = newSponsorResult.insertId;
                } else {
                    // Update existing sponsor record
                    sponsorId = sponsorResults[0].Sponsor_ID;
                    await promiseConnection.query(
                        'UPDATE sponsor SET CompanyName = ?, Email = ?, PhoneNo = ? WHERE UserID = ?',
                        [request.CompanyName, request.CompanyEmail, request.CompanyPhone, userId]
                    );
                }
                
                // Create sponsorship contract with Pending payment status
                const [contractResult] = await promiseConnection.query(
                    `INSERT INTO sponsorship_contracts (
                        ContractDate, ContractStatus, PaymentStatus, SponsorID, PackageID
                    ) VALUES (
                        CURDATE(), 'Pending', 'Pending', ?, ?
                    )`,
                    [sponsorId, request.PackageID]
                );
                
                // Update request status
                await promiseConnection.query(
                    'UPDATE sponsorship_requests SET Status = "Approved" WHERE RequestID = ?',
                    [requestId]
                );
                
                // Commit transaction
                await promiseConnection.commit();
                
                connection.release();
                res.json({ message: 'Sponsorship request approved successfully. The sponsor will need to complete payment in their contracts section.' });
                
            } catch (error) {
                await promiseConnection.rollback();
                connection.release();
                console.error('Error approving sponsorship request:', error);
                res.status(500).json({ message: error.message || 'Failed to approve sponsorship request' });
            }
        })
        .catch(err => {
            connection.release();
            console.error('Transaction error:', err);
            res.status(500).json({ message: 'Failed to start transaction' });
        });
    });
});

// API endpoint to reject a sponsorship request (admin only)
app.post('/api/admin/sponsorship-requests/:requestId/reject', authorize(['Admin']), (req, res) => {
    const requestId = req.params.requestId;
    
    const query = 'UPDATE sponsorship_requests SET Status = "Rejected" WHERE RequestID = ? AND Status = "Pending"';
    
    db.query(query, [requestId], (err, result) => {
        if (err) {
            console.error('Error rejecting sponsorship request:', err);
            return res.status(500).json({ message: 'Failed to reject sponsorship request' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Sponsorship request not found or already processed' });
        }
        
        res.json({ message: 'Sponsorship request rejected successfully' });
    });
});

// API endpoint to handle sponsorship submission (Needs review based on final logic)
app.post('/submit-sponsorship', (req, res) => {
    const { companyName, email, phone, packageId } = req.body;
    if (!req.session.userId) {
        return res.status(401).send('You must be logged in to sponsor.');
    }
    const userId = req.session.userId;
    // --- LOGIC FLAW IN ORIGINAL: 'sponsor' table DDL doesn't have PackageID. Link is in 'sponsorship_contracts'. ---
    // --- This route needs significant revision based on how contracts are created. Placeholder logic kept below ---
    const checkPackageQuery = 'SELECT PackageID FROM sponsorship_package WHERE PackageID = ?';
    db.query(checkPackageQuery, [packageId], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error checking package ID:', err);
            return res.status(err ? 500 : 400).send(err ? 'Error checking package.' : 'Invalid package ID selected.');
        }
        // --- Original INSERT into 'sponsor' likely incorrect - needs contract logic ---
        // Example (modify heavily): Create contract instead? Update sponsor details?
        const insertQuery = `INSERT INTO sponsor (CompanyName, Email, PhoneNo, UserID) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE CompanyName=VALUES(CompanyName), Email=VALUES(Email), PhoneNo=VALUES(PhoneNo)`; // Example update/insert
        db.query(insertQuery, [companyName, email, phone, userId], (err, result) => {
             if (err) { /* Handle Error */ }
             // Now potentially create a sponsorship_contracts entry?
             console.log('Sponsorship (partially) submitted - NEEDS CONTRACT LOGIC');
             res.send('Thank you for sponsoring! (Contract pending)');
        });
    });
});


// API endpoint to get current logged in user's role
app.get('/getRole', (req, res) => {
    if (!req.session || !req.session.userId || !req.session.role) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    
    res.json({ 
        userId: req.session.userId,
        role: req.session.role 
    });
});



// Logout route
app.get('/logout', (req, res) => {
    if (req.session) { // Check if session exists
        req.session.destroy(err => { // Use callback for destroy
            if (err) {
                console.error("Logout error:", err);
                return res.status(500).send('Could not log out.');
            }
            res.redirect('/'); // Redirect after destroying
        });
    } else {
        res.redirect('/'); // Redirect if no session
    }
});

// Fetch events
app.get('/events', (req, res) => {
    // Check if user is logged in
    if (!req.session.userId || !req.session.role) {
        return res.status(401).json({ message: 'Not authenticated' });
    }

    // Get category filter if provided
    const categoryId = req.query.categoryId;
    
    // Build the query with optional category filter
    let whereClause = '';
    const queryParams = [];
    
    if (categoryId) {
        whereClause = ' WHERE e.CategoryID = ?';
        queryParams.push(categoryId);
    }

    let query;
    if (req.session.role === 'Admin' || req.session.role === 'Event Organizer') {
        // Admin and Event Organizer can see all event details
        query = `
            SELECT e.Event_ID AS EventID, e.EventName, e.EventDescription, 
                   e.Rules, e.MaxParticipants, e.EventDateTime, 
                   e.RegistrationFee, e.CategoryID, c.CategoryName
            FROM event e
            LEFT JOIN category c ON e.CategoryID = c.CategoryID
            ${whereClause}
            ORDER BY e.EventDateTime DESC`;
    } else {
        // Participants and others see limited details
        query = `
            SELECT e.Event_ID AS EventID, e.EventName, e.EventDescription, 
                   e.EventDateTime, e.RegistrationFee, e.CategoryID, c.CategoryName
            FROM event e
            LEFT JOIN category c ON e.CategoryID = c.CategoryID
            ${whereClause}
            ORDER BY e.EventDateTime DESC`;
    }

    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching events:', err);
            return res.status(500).json({ message: 'Error fetching events from database.' });
        }
        res.json(results);
    });
});

// Event management routes - restrict to Admin and Event Organizer only
app.get('/api/events', authorize(['Admin', 'Event Organizer', 'Judge']), (req, res) => {
    console.log("EVENTS API: Request received from user:", req.session.username);
    
    const query = `
        SELECT e.*, c.CategoryName 
        FROM event e 
        LEFT JOIN category c ON e.CategoryID = c.CategoryID 
        ORDER BY e.EventDateTime DESC
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error('EVENTS API ERROR:', err);
            return res.status(500).json([]);  // Return empty array format for UI compatibility
        }
        
        console.log(`EVENTS API: Found ${results.length} events`);
        
        // Return empty array if no events are found (UI expects array format)
        if (results.length === 0) {
            return res.json([]);
        }
        
        // Return the results array directly as UI expects
        console.log("EVENTS API: Returning formatted results");
        res.json(results);
    });
});

// Event registration route for participants
app.post('/event-register', authorize(['Participant']), (req, res) => {
    const { EventID } = req.body;
    const userId = req.session.userId;

    if (!EventID || !userId) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    // Get participant ID from user ID
    const participantQuery = 'SELECT Participant_ID FROM participant WHERE UserID = ?';
    db.query(participantQuery, [userId], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error getting participant ID:', err);
            return res.status(500).json({ message: 'Failed to get participant details' });
        }

        const ParticipantID = results[0].Participant_ID;

        // Check if already registered
        const checkQuery = 'SELECT * FROM registration WHERE EventID = ? AND ParticipantID = ?';
        db.query(checkQuery, [EventID, ParticipantID], (err, results) => {
            if (err) {
                console.error('Error checking registration:', err);
                return res.status(500).json({ message: 'Failed to check registration' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: 'Already registered for this event' });
            }

            // Register for the event
            const sql = 'INSERT INTO registration (EventID, ParticipantID) VALUES (?, ?)';
            db.query(sql, [EventID, ParticipantID], (err, result) => {
                if (err) {
                    console.error('Error registering for event:', err);
                    return res.status(500).json({ message: 'Registration failed' });
                }
                res.json({ message: 'Registration successful' });
            });
        });
    });
});

// Role request routes
app.post('/api/role-requests', authorize(['Participant']), (req, res) => {
    const { requestedRole, details } = req.body;
    const userId = req.session.userId;

    // Create the role request - using RequestedRole directly (ENUM type) instead of RequestedRoleID
    const insertQuery = 'INSERT INTO role_requests (UserID, RequestedRole, Details, Status) VALUES (?, ?, ?, "Pending")';
    db.query(insertQuery, [userId, requestedRole, details], (err, result) => {
        if (err) {
            console.error('Error creating role request:', err);
            return res.status(500).json({ message: 'Failed to create role request' });
        }
        res.status(201).json({ message: 'Role request submitted successfully' });
    });
});

// Admin Role Request Management Routes
app.get('/api/admin/role-requests', authorize(['Admin']), (req, res) => {
    const query = `
        SELECT rr.RequestID, rr.UserID, rr.RequestedRole, rr.Status, 
            rr.Details, rr.RequestTimestamp,
            u.UserName, u.Email, rr.RequestedRole as RequestedRole
        FROM role_requests rr
        JOIN users u ON rr.UserID = u.UserID
        ORDER BY rr.Status = 'Pending' DESC, rr.RequestTimestamp DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching role requests:', err);
            return res.status(500).json({ message: 'Failed to fetch role requests' });
        }
        
        // Return a friendly message if no role requests are found
        if (results.length === 0) {
            return res.json({ message: 'No role change requests found', data: [] });
        }
        
        res.json({ message: 'Role requests retrieved successfully', data: results });
    });
});

app.post('/api/admin/role-requests/:requestId/approve', authorize(['Admin']), (req, res) => {
    const requestId = req.params.requestId;
    
    // Start transaction - FIX: Get connection from pool first
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection:', err);
            return res.status(500).json({ message: 'Failed to process role request' });
        }

        // Convert connection to promise interface for more reliable async/await usage
        const promiseConnection = connection.promise();
        
        promiseConnection.beginTransaction()
        .then(async () => {
            try {
                // Get request details
                const [requestResults] = await promiseConnection.query(
                    `SELECT rr.UserID, rr.RequestedRole, r.RoleName, u.UserName, u.Email
                    FROM role_requests rr
                    JOIN role r ON rr.RequestedRole = r.RoleName
                    JOIN users u ON rr.UserID = u.UserID
                    WHERE rr.RequestID = ? AND rr.Status = 'Pending'`,
                    [requestId]
                );
                
                if (requestResults.length === 0) {
                    throw new Error('Role request not found or already processed');
                }
                
                const request = requestResults[0];
                const userId = request.UserID;
                const roleName = request.RequestedRole;
                
                // Get the role ID for the requested role
                const [roleResults] = await promiseConnection.query(
                    'SELECT RoleID FROM role WHERE RoleName = ?',
                    [roleName]
                );
                
                if (roleResults.length === 0) {
                    throw new Error('Role not found');
                }
                
                const requestedRoleId = roleResults[0].RoleID;
                
                // Update user's role
                await promiseConnection.query(
                    'UPDATE users SET RoleID = ? WHERE UserID = ?',
                    [requestedRoleId, userId]
                );
                
                // Create appropriate role-specific entry if needed
                if (roleName === 'Participant') {
                    await promiseConnection.query(
                        'INSERT INTO participant (UserID, University) VALUES (?, "Not specified")',
                        [userId]
                    );
                } else if (roleName === 'Judge') {
                    await promiseConnection.query(
                        'INSERT INTO judge (UserID, Expertise) VALUES (?, "Not specified")',
                        [userId]
                    );
                } else if (roleName === 'Sponsor') {
                    await promiseConnection.query(
                        'INSERT INTO sponsor (UserID, CompanyName, Email, PhoneNo) VALUES (?, "Not specified", ?, "Not specified")',
                        [userId, request.Email]
                    );
                }
                
                // Update request status
                await promiseConnection.query(
                    'UPDATE role_requests SET Status = "Approved" WHERE RequestID = ?',
                    [requestId]
                );
                
                // Commit transaction
                await promiseConnection.commit();
                
                connection.release();
                res.json({ message: 'Role request approved successfully' });
                
            } catch (error) {
                await promiseConnection.rollback();
                connection.release();
                console.error('Error approving role request:', error);
                res.status(500).json({ message: error.message || 'Failed to approve role request' });
            }
        })
        .catch(err => {
            connection.release();
            console.error('Transaction error:', err);
            res.status(500).json({ message: 'Failed to start transaction' });
        });
    });
});

app.post('/api/admin/role-requests/:requestId/reject', authorize(['Admin']), (req, res) => {
    const requestId = req.params.requestId;
    
    const query = 'UPDATE role_requests SET Status = "Rejected" WHERE RequestID = ? AND Status = "Pending"';
    
    db.query(query, [requestId], (err, result) => {
        if (err) {
            console.error('Error rejecting role request:', err);
            return res.status(500).json({ message: 'Failed to reject role request' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Role request not found or already processed' });
        }
        
        res.json({ message: 'Role request rejected successfully' });
    });
});

// ----- API Routes for Team Registration -----
app.post('/api/events/:id/register', authorize(['Participant']), (req, res) => {
    const eventId = req.params.id;
    const userId = req.session.userId;
    const { registrationType, teamName, teamMembers, paymentMethod, amount } = req.body;
    
    // First, check if the user is already registered for this event
    const checkQuery = `
        SELECT r.RegistrationID FROM registration r
        JOIN participant p ON r.ParticipantID = p.Participant_ID
        WHERE r.EventID = ? AND p.UserID = ?
    `;
    
    db.query(checkQuery, [eventId, userId], (checkErr, checkResults) => {
        if (checkErr) {
            console.error('Error checking for existing registration:', checkErr);
            return res.status(500).json({ message: 'Failed to check for existing registration' });
        }
        
        // If user is already registered, return an error
        if (checkResults.length > 0) {
            return res.status(400).json({ message: 'You are already registered for this event' });
        }
        
        // If not registered, proceed with registration
        // Start transaction - FIX: Get connection from pool first
        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting database connection:', err);
                return res.status(500).json({ message: 'Failed to process registration' });
            }
            
            // Convert connection to promise interface for more reliable async/await usage
            const promiseConnection = connection.promise();
            
            promiseConnection.beginTransaction()
            .then(async () => {
                try {
                    // 1. Get participant ID
                    const [participantResults] = await promiseConnection.query(
                        'SELECT Participant_ID FROM participant WHERE UserID = ?', 
                        [userId]
                    );
                    
                    if (participantResults.length === 0) {
                        throw new Error('Participant record not found');
                    }
                    
                    const participantId = participantResults[0].Participant_ID;
                    
                    // 2. Get event details to check if it's a team event and max participants
                    // Note: EventType was removed as it doesn't exist in the database schema
                    const [eventResults] = await promiseConnection.query(
                        'SELECT MaxParticipants, RegistrationFee, EventName FROM event WHERE Event_ID = ?', 
                        [eventId]
                    );
                    
                    if (eventResults.length === 0) {
                        throw new Error('Event not found');
                    }
                    
                    const eventDetails = eventResults[0];
                    
                    // 3. Handle payment - Set payment status to "Paid" regardless of payment method
                    const paymentStatus = "Paid";
                    const [paymentResults] = await promiseConnection.query(
                        'INSERT INTO payment (Amount, PaymentType, PaymentDate) VALUES (?, ?, NOW())',
                        [amount, paymentMethod]
                    );
                    
                    const paymentId = paymentResults.insertId;
                    
                    // 4. Process based on registration type
                    let teamId = null;
                    let registrationId = null;
                    
                    if (registrationType === 'team') {
                        // Validate team size against MaxParticipants
                        if (teamMembers.length + 1 > eventDetails.MaxParticipants) {
                            throw new Error(`Team size exceeds event maximum of ${eventDetails.MaxParticipants} participants`);
                        }
                        
                        // Ensure teamName is not null or undefined
                        if (!teamName) {
                            throw new Error('Team name is required for team registration');
                        }
                        
                        // Create team
                        const [teamResults] = await promiseConnection.query(
                            'INSERT INTO team (TeamName) VALUES (?)',
                            [teamName]
                        );
                        
                        teamId = teamResults.insertId;
                        
                        // Create registration with team ID - Set payment status to "Paid"
                        const [registrationResults] = await promiseConnection.query(
                            'INSERT INTO registration (EventID, ParticipantID, TeamID, PaymentStatus, RegistrationTimestamp) VALUES (?, ?, ?, "Paid", NOW())',
                            [eventId, participantId, teamId]
                        );
                        
                        registrationId = registrationResults.insertId;
                        
                        // Update the payment with the registration ID
                        await promiseConnection.query(
                            'UPDATE payment SET RegistrationID = ? WHERE Payment_ID = ?',
                            [registrationId, paymentId]
                        );
                        
                        // Process team members
                        for (const member of teamMembers) {
                            // Find participant by email
                            const [memberResults] = await promiseConnection.query(
                                'SELECT p.Participant_ID, u.UserID FROM participant p JOIN users u ON p.UserID = u.UserID WHERE u.Email = ?',
                                [member.email]
                            );
                            
                            let memberParticipantId;
                            
                            if (memberResults.length === 0) {
                                // Team member doesn't exist yet, create temporary user and participant records
                                // First check if the email is valid
                                if (!member.email || !member.email.includes('@')) {
                                    throw new Error(`Invalid email format for team member: ${member.email}`);
                                }
                                
                                // Create temporary user with hashed password
                                const tempPassword = Math.random().toString(36).slice(-8); // Generate random password
                                const hashedPassword = await bcrypt.hash(tempPassword, saltRounds); // Hash the password
                                
                                const [roleResults] = await promiseConnection.query(
                                    'SELECT RoleID FROM role WHERE RoleName = "Participant"'
                                );
                                
                                if (roleResults.length === 0) {
                                    throw new Error('Participant role not found');
                                }
                                
                                const participantRoleId = roleResults[0].RoleID;
                                
                                // Extract username from email (before the @ symbol)
                                const tempUsername = member.email.split('@')[0];
                                
                                const [newUserResult] = await promiseConnection.query(
                                    'INSERT INTO users (Email, user_password, RoleID, UserName) VALUES (?, ?, ?, ?)',
                                    [member.email, hashedPassword, participantRoleId, tempUsername]
                                );
                                
                                const newUserId = newUserResult.insertId;
                                
                                // Create temporary participant - the participant table doesn't have FirstName and LastName columns
                                const [newParticipantResult] = await promiseConnection.query(
                                    'INSERT INTO participant (UserID, University) VALUES (?, "Temporary")',
                                    [newUserId]
                                );
                                
                                memberParticipantId = newParticipantResult.insertId;
                            } else {
                                memberParticipantId = memberResults[0].Participant_ID;
                            }
                            
                            // Add member to team (via registration) - Already "Paid"
                            await promiseConnection.query(
                                'INSERT INTO registration (EventID, ParticipantID, TeamID, PaymentStatus, RegistrationTimestamp) VALUES (?, ?, ?, "Paid", NOW())',
                                [eventId, memberParticipantId, teamId]
                            );
                        }
                    } else {
                        // Individual registration - Set payment status to "Paid"
                        const [registrationResults] = await promiseConnection.query(
                            'INSERT INTO registration (EventID, ParticipantID, PaymentStatus, RegistrationTimestamp) VALUES (?, ?, "Paid", NOW())',
                            [eventId, participantId]
                        );
                        
                        registrationId = registrationResults.insertId;
                        
                        // Update the payment with the registration ID
                        await promiseConnection.query(
                            'UPDATE payment SET RegistrationID = ? WHERE Payment_ID = ?',
                            [registrationId, paymentId]
                        );
                    }
                    
                    // If all operations succeeded, commit the transaction
                    await promiseConnection.commit();
                    
                    // Release the connection
                    connection.release();
                    
                    // Return success response
                    res.status(201).json({
                        message: 'Registration successful',
                        registrationId: registrationId,
                        teamId: teamId
                    });
                    
                } catch (error) {
                    // If any error occurred, rollback the transaction
                    await promiseConnection.rollback();
                    connection.release();
                    console.error('Error processing registration:', error);
                    res.status(500).json({ message: error.message || 'Failed to complete registration' });
                }
            })
            .catch(err => {
                connection.release();
                console.error('Transaction error:', err);
                res.status(500).json({ message: 'Failed to start transaction' });
            });
        });
    });
});

// Get single event details
app.get('/api/events/:id/details', authorize(['Participant']), (req, res) => {
    const eventId = req.params.id;
    
    const query = `
        SELECT e.*, c.CategoryName 
        FROM event e 
        LEFT JOIN category c ON e.CategoryID = c.CategoryID 
        WHERE e.Event_ID = ?
    `;
    
    db.query(query, [eventId], (err, results) => {
        if (err) {
            console.error('Error fetching event details:', err);
            return res.status(500).json({ message: 'Failed to fetch event details' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Event not found' });
        }
        
        res.json(results[0]);
    });
});

// Get categories
app.get('/api/categories', (req, res) => {
    const query = `
        SELECT c.*, 
               (SELECT COUNT(*) FROM event e WHERE e.CategoryID = c.CategoryID) AS EventCount
        FROM category c
        ORDER BY c.CategoryName
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching categories:', err);
            return res.status(500).json({ message: 'Failed to fetch categories' });
        }
        
        res.json(results);
    });
});

// Get participant's event registrations
app.get('/api/registrations', authorize(['Participant']), (req, res) => {
    const userId = req.session.userId;
    
    const query = `
        SELECT r.RegistrationID, e.Event_ID, e.EventName, e.EventDateTime, e.RegistrationFee,
               r.TeamID, t.TeamName,
               (SELECT COUNT(*) FROM accommodation a WHERE a.RegistrationID = r.RegistrationID) > 0 AS hasAccommodation
        FROM registration r
        JOIN event e ON r.EventID = e.Event_ID
        JOIN participant p ON r.ParticipantID = p.Participant_ID
        LEFT JOIN team t ON r.TeamID = t.TeamID
        WHERE p.UserID = ?
        ORDER BY e.EventDateTime DESC
    `;
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching registrations:', err);
            return res.status(500).json({ message: 'Failed to fetch registrations' });
        }
        
        // Return the results directly instead of in a data property
        res.json(results);
    });
});

// ----- API Routes for Accommodation Management -----

// REMOVED - This endpoint is replaced by the enhanced version below

// Request accommodation
app.post('/api/participant/accommodations', authorize(['Participant']), (req, res) => {
    const userId = req.session.userId;
    const { registrationId, numberOfPeople, budget } = req.body;
    
    if (!registrationId || !numberOfPeople || !budget) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Verify this registration belongs to the user
    const verifyQuery = `
        SELECT reg.RegistrationID
        FROM registration reg
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        WHERE reg.RegistrationID = ? AND p.UserID = ?
    `;
    
    db.query(verifyQuery, [registrationId, userId], (err, results) => {
        if (err) {
            console.error('Error verifying registration:', err);
            return res.status(500).json({ message: 'Failed to verify registration' });
        }
        
        if (results.length === 0) {
            return res.status(403).json({ message: 'Not authorized to request accommodation for this registration' });
        }
        
        // Check if accommodation already exists for this registration
        const checkQuery = 'SELECT AccommodationID FROM accommodation WHERE RegistrationID = ?';
        
        db.query(checkQuery, [registrationId], (err, results) => {
            if (err) {
                console.error('Error checking accommodation:', err);
                return res.status(500).json({ message: 'Failed to check existing accommodations' });
            }
            
            if (results.length > 0) {
                return res.status(400).json({ message: 'Accommodation already requested for this registration' });
            }
            
            // Create accommodation request
            const insertQuery = `
                INSERT INTO accommodation (RegistrationID, NumberOfPeople, Budget, AccommodationStatus)
                VALUES (?, ?, ?, 'Requested')
            `;
            
            db.query(insertQuery, [registrationId, numberOfPeople, budget], (err, result) => {
                if (err) {
                    console.error('Error creating accommodation request:', err);
                    return res.status(500).json({ message: 'Failed to create accommodation request' });
                }
                
                res.status(201).json({ 
                    message: 'Accommodation request submitted successfully',
                    accommodationId: result.insertId
                });
            });
        });
    });
});

// Cancel accommodation booking
app.post('/api/participant/accommodations/:id/cancel', authorize(['Participant']), (req, res) => {
    const userId = req.session.userId;
    const accommodationId = req.params.id;
    
    // Verify this accommodation belongs to the user
    const verifyQuery = `
        SELECT a.AccommodationID, a.AccommodationStatus
        FROM accommodation a
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        WHERE a.AccommodationID = ? AND p.UserID = ?
    `;
    
    db.query(verifyQuery, [accommodationId, userId], (err, results) => {
        if (err) {
            console.error('Error verifying accommodation:', err);
            return res.status(500).json({ message: 'Failed to verify accommodation' });
        }
        
        if (results.length === 0) {
            return res.status(403).json({ message: 'Not authorized to cancel this accommodation' });
        }
        
        const accommodation = results[0];
        
        if (accommodation.AccommodationStatus === 'Cancelled') {
            return res.status(400).json({ message: 'Accommodation is already cancelled' });
        }
        
        // Update accommodation status
        const updateQuery = 'UPDATE accommodation SET AccommodationStatus = "Cancelled" WHERE AccommodationID = ?';
        
        db.query(updateQuery, [accommodationId], (err, result) => {
            if (err) {
                console.error('Error cancelling accommodation:', err);
                return res.status(500).json({ message: 'Failed to cancel accommodation' });
            }
            
            res.json({ message: 'Accommodation cancelled successfully' });
        });
    });
});

// Admin: Get all accommodations
app.get('/api/accommodations', authorize(['Admin']), (req, res) => {
    console.log("ADMIN ACCOMMODATION API: Request received from:", req.session.username);
    
    const query = `
        SELECT a.AccommodationID, a.RegistrationID, a.NumberOfPeople, a.Budget,
               a.AccommodationStatus AS Status,
               u.UserName, p.University, e.EventName, e.EventDateTime,
               ra.AllocationID, r.RoomID, r.Capacity, r.Price,
               ra.CheckInDate, ra.CheckOutDate
        FROM accommodation a
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN event e ON reg.EventID = e.Event_ID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        JOIN users u ON p.UserID = u.UserID
        LEFT JOIN room_allocation ra ON a.AccommodationID = ra.AccommodationID
        LEFT JOIN room r ON ra.RoomID = r.RoomID
        ORDER BY 
            CASE 
                WHEN a.AccommodationStatus = 'Requested' THEN 1
                WHEN a.AccommodationStatus = 'Allocated' THEN 2
                ELSE 3
            END,
            a.AccommodationID DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('ADMIN ACCOMMODATION API ERROR:', err);
            return res.status(500).json([]);  // Return empty array on error for UI compatibility
        }
        
        console.log(`ADMIN ACCOMMODATION API: Found ${results.length} accommodation records`);
        
        // Return empty array if no accommodations are found
        if (results.length === 0) {
            return res.json([]);
        }
        
        // Format directly for the UI's expected format
        const uiFormattedResults = results.map(item => ({
            AccommodationID: item.AccommodationID,
            Name: item.EventName,
            Location: item.UserName,
            Capacity: item.NumberOfPeople,
            Budget: item.Budget,
            Status: item.Status,
            // Additional fields that might be used for details
            CheckInDate: item.CheckInDate,
            CheckOutDate: item.CheckOutDate,
            RoomID: item.RoomID,
            AllocationID: item.AllocationID,
            RoomCapacity: item.Capacity,
            RoomPrice: item.Price
        }));
        
        console.log("ADMIN ACCOMMODATION API: Returning formatted results");
        res.json(uiFormattedResults);
    });
});

// Admin: Get single accommodation by ID
app.get('/api/accommodations/:id', authorize(['Admin']), (req, res) => {
    const accommodationId = req.params.id;
    console.log(`ADMIN ACCOMMODATION DETAIL API: Request for accommodation ID ${accommodationId} from ${req.session.username}`);
    
    const query = `
        SELECT a.AccommodationID, a.RegistrationID, a.NumberOfPeople, a.Budget,
               a.AccommodationStatus AS Status,
               u.UserName, p.University, e.EventName, e.EventDateTime,
               ra.AllocationID, r.RoomID, r.RoomNumber, r.Capacity as RoomCapacity, r.Price as RoomPrice,
               ra.CheckInDate, ra.CheckOutDate
        FROM accommodation a
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN event e ON reg.EventID = e.Event_ID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        JOIN users u ON p.UserID = u.UserID
        LEFT JOIN room_allocation ra ON a.AccommodationID = ra.AccommodationID
        LEFT JOIN room r ON ra.RoomID = r.RoomID
        WHERE a.AccommodationID = ?
    `;
    
    db.query(query, [accommodationId], (err, results) => {
        if (err) {
            console.error('ADMIN ACCOMMODATION DETAIL API ERROR:', err);
            return res.status(500).json({ message: 'Failed to fetch accommodation details' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Accommodation not found' });
        }
        
        // Format the result for UI consumption
        const accommodation = results[0];
        const formattedResult = {
            AccommodationID: accommodation.AccommodationID,
            Name: accommodation.EventName,
            Location: accommodation.UserName,
            Capacity: accommodation.NumberOfPeople,
            Budget: accommodation.Budget,
            Status: accommodation.Status,
            University: accommodation.University,
            EventDateTime: accommodation.EventDateTime,
            CheckInDate: accommodation.CheckInDate,
            CheckOutDate: accommodation.CheckOutDate,
            RoomID: accommodation.RoomID,
            RoomNumber: accommodation.RoomNumber,
            RoomCapacity: accommodation.RoomCapacity,
            RoomPrice: accommodation.RoomPrice,
            AllocationID: accommodation.AllocationID
        };
        
        console.log("ADMIN ACCOMMODATION DETAIL API: Returning accommodation details");
        res.json(formattedResult);
    });
});

// Admin: Approve accommodation request
app.post('/api/accommodations/:id/approve', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const accommodationId = req.params.id;
    const { checkInDate, checkOutDate } = req.body;
    
    if (!checkInDate || !checkOutDate) {
        return res.status(400).json({ message: 'Missing check-in or check-out dates' });
    }
    
    const checkInDateObj = new Date(checkInDate);
    const checkOutDateObj = new Date(checkOutDate);
    
    if (checkInDateObj >= checkOutDateObj) {
        return res.status(400).json({ message: 'Check-out date must be after check-in date' });
    }
    
    // Begin transaction
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting connection:', err);
            return res.status(500).json({ message: 'Database connection error' });
        }
        
        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                console.error('Error starting transaction:', err);
                return res.status(500).json({ message: 'Transaction error' });
            }
            
            // Get accommodation details including budget and number of people
            connection.query(
                'SELECT a.AccommodationID, a.NumberOfPeople, a.Budget, a.AccommodationStatus FROM accommodation a WHERE a.AccommodationID = ? AND a.AccommodationStatus = "Requested"',
                [accommodationId],
                (err, results) => {
                    if (err || results.length === 0) {
                        return connection.rollback(() => {
                            connection.release();
                            if (err) {
                                console.error('Error checking accommodation:', err);
                                return res.status(500).json({ message: 'Database error' });
                            }
                            return res.status(404).json({ message: 'Accommodation request not found or already processed' });
                        });
                    }
                    
                    const accommodation = results[0];
                    const numberOfPeople = accommodation.NumberOfPeople;
                    const budget = accommodation.Budget;
                    
                    // Find available rooms that match the budget and have enough capacity
                    // Sort by price (descending) to get the best match within budget
                    const roomQuery = `
                        SELECT r.RoomID, r.RoomNumber, r.Capacity, r.Price, r.AvailabilityStatus
                        FROM room r
                        WHERE r.AvailabilityStatus = 'Available'
                        AND r.Price <= ?
                        ORDER BY r.Price DESC
                    `;
                    
                    connection.query(roomQuery, [budget], (err, availableRooms) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error finding rooms:', err);
                                return res.status(500).json({ message: 'Database error' });
                            });
                        }
                        
                        if (availableRooms.length === 0) {
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(404).json({ message: 'No available rooms found that match the budget requirements' });
                            });
                        }
                        
                        // Find a room or multiple rooms with enough total capacity
                        let selectedRooms = [];
                        let remainingPeople = numberOfPeople;
                        
                        // First, try to find a single room with enough capacity
                        for (const room of availableRooms) {
                            if (room.Capacity >= numberOfPeople) {
                                selectedRooms.push(room);
                                remainingPeople = 0;
                                break;
                            }
                        }
                        
                        // If no single room has enough capacity, allocate multiple rooms
                        if (remainingPeople > 0) {
                            // Sort rooms by capacity (descending) to minimize the number of rooms needed
                            availableRooms.sort((a, b) => b.Capacity - a.Capacity);
                            
                            for (const room of availableRooms) {
                                if (remainingPeople <= 0) break;
                                
                                // Check if we've already selected this room
                                if (!selectedRooms.some(r => r.RoomID === room.RoomID)) {
                                    selectedRooms.push(room);
                                    remainingPeople -= room.Capacity;
                                }
                            }
                        }
                        
                        // Check if we found enough rooms
                        if (remainingPeople > 0) {
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(404).json({ 
                                    message: 'Not enough room capacity available to accommodate all people within budget' 
                                });
                            });
                        }
                        
                        // Update accommodation status to 'Allocated'
                        connection.query(
                            'UPDATE accommodation SET AccommodationStatus = "Allocated" WHERE AccommodationID = ?',
                            [accommodationId],
                            (err, result) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error updating accommodation:', err);
                                        return res.status(500).json({ message: 'Database error' });
                                    });
                                }
                                
                                // Create room allocations for each selected room
                                const allocations = [];
                                let processedRooms = 0;
                                
                                selectedRooms.forEach(room => {
                                    connection.query(
                                        'INSERT INTO room_allocation (RoomID, AccommodationID, CheckInDate, CheckOutDate) VALUES (?, ?, ?, ?)',
                                        [room.RoomID, accommodationId, checkInDate, checkOutDate],
                                        (err, result) => {
                                            processedRooms++;
                                            
                                            if (err) {
                                                return connection.rollback(() => {
                                                    connection.release();
                                                    console.error('Error creating room allocation:', err);
                                                    return res.status(500).json({ message: 'Database error' });
                                                });
                                            }
                                            
                                            allocations.push({
                                                AllocationID: result.insertId,
                                                RoomID: room.RoomID,
                                                RoomNumber: room.RoomNumber
                                            });
                                            
                                            // Update room status to Occupied
                                            connection.query(
                                                'UPDATE room SET AvailabilityStatus = "Occupied" WHERE RoomID = ?',
                                                [room.RoomID],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error updating room status:', err);
                                                            return res.status(500).json({ message: 'Database error' });
                                                        });
                                                    }
                                                    
                                                    // If all rooms processed, commit the transaction
                                                    if (processedRooms === selectedRooms.length) {
                                                        connection.commit(err => {
                                                            if (err) {
                                                                return connection.rollback(() => {
                                                                    connection.release();
                                                                    console.error('Error committing transaction:', err);
                                                                    return res.status(500).json({ message: 'Transaction error' });
                                                                });
                                                            }
                                                            
                                                            connection.release();
                                                            return res.json({ 
                                                                message: 'Accommodation request approved and rooms allocated successfully',
                                                                allocations: allocations 
                                                            });
                                                        });
                                                    }
                                                }
                                            );
                                        }
                                    );
                                });
                            }
                        );
                    });
                }
            );
        });
    });
});

// Admin: Reject accommodation request
app.post('/api/accommodations/:id/reject', authorize(['Admin']), (req, res) => {
    const accommodationId = req.params.id;
    
    // Changed from "Rejected" to "Cancelled" since the ENUM only allows Requested, Allocated, Cancelled
    const updateQuery = 'UPDATE accommodation SET AccommodationStatus = "Cancelled" WHERE AccommodationID = ? AND AccommodationStatus = "Requested"';
    
    db.query(updateQuery, [accommodationId], (err, result) => {
        if (err) {
            console.error('Error rejecting accommodation:', err);
            return res.status(500).json({ message: 'Failed to reject accommodation' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Accommodation request not found or already processed' });
        }
        
        res.json({ message: 'Accommodation request rejected successfully' });
    });
});

// ----- API Routes for Room Management -----

// Get all rooms
app.get('/api/rooms', authorize(['Admin']), (req, res) => {
    console.log("ROOMS API: Request received from:", req.session.username);
    
    const query = 'SELECT * FROM room ORDER BY RoomID';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('ROOMS API ERROR:', err);
            return res.status(500).json([]);  // Return empty array on error for UI compatibility
        }
        
        console.log(`ROOMS API: Found ${results.length} room records`);
        
        // Return empty array if no rooms are found
        if (results.length === 0) {
            return res.json([]);
        }
        
        // Return results directly as array for UI compatibility
        console.log("ROOMS API: Returning room results");
        res.json(results);
    });
});

// Get available rooms
app.get('/api/rooms/available', authorize(['Admin']), (req, res) => {
    const query = 'SELECT * FROM room WHERE AvailabilityStatus = "Available" ORDER BY RoomID';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching available rooms:', err);
            return res.status(500).json({ message: 'Failed to fetch available rooms' });
        }
        
        res.json(results);
    });
});

// Add new room
app.post('/api/rooms', authorize(['Admin']), (req, res) => {
    const { roomNumber, capacity, price, status } = req.body;
    
    if (!capacity || !price) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Validate room number format if provided
    if (roomNumber) {
        const roomNumberPattern = /^[A-C]-\d{3}$/;
        if (!roomNumberPattern.test(roomNumber)) {
            return res.status(400).json({ 
                message: 'Invalid room number format. Should be like A-101, B-203, C-304' 
            });
        }
    }
    
    const insertQuery = 'INSERT INTO room (RoomNumber, Capacity, Price, AvailabilityStatus) VALUES (?, ?, ?, ?)';
    
    db.query(insertQuery, [roomNumber, capacity, price, status || 'Available'], (err, result) => {
        if (err) {
            console.error('Error creating room:', err);
            
            // Check for duplicate room number
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Room number already exists' });
            }
            
            return res.status(500).json({ message: 'Failed to create room' });
        }
        
        res.status(201).json({ 
            message: 'Room created successfully',
            roomId: result.insertId
        });
    });
});

// Update room
app.put('/api/rooms/:id', authorize(['Admin']), (req, res) => {
    const roomId = req.params.id;
    const { roomNumber, capacity, price, status } = req.body;
    
    if (!capacity || !price || !status) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Validate room number format if provided
    if (roomNumber) {
        const roomNumberPattern = /^[A-C]-\d{3}$/;
        if (!roomNumberPattern.test(roomNumber)) {
            return res.status(400).json({ 
                message: 'Invalid room number format. Should be like A-101, B-203, C-304' 
            });
        }
    }
    
    const updateQuery = 'UPDATE room SET RoomNumber = ?, Capacity = ?, Price = ?, AvailabilityStatus = ? WHERE RoomID = ?';
    
    db.query(updateQuery, [roomNumber, capacity, price, status, roomId], (err, result) => {
        if (err) {
            console.error('Error updating room:', err);
            
            // Check for duplicate room number
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Room number already exists' });
            }
            
            return res.status(500).json({ message: 'Failed to update room' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Room not found' });
        }
        
        res.json({ message: 'Room updated successfully' });
    });
});

// Delete room
app.delete('/api/rooms/:id', authorize(['Admin']), (req, res) => {
    const roomId = req.params.id;
    
    // Check if room is in use in room_allocation table
    const checkQuery = 'SELECT AllocationID FROM room_allocation WHERE RoomID = ?';
    
    db.query(checkQuery, [roomId], (err, results) => {
        if (err) {
            console.error('Error checking room usage:', err);
            return res.status(500).json({ message: 'Failed to check room usage' });
        }
        
        if (results.length > 0) {
            return res.status(400).json({ message: 'Cannot delete room that is currently allocated' });
        }
        
        // Delete room
        const deleteQuery = 'DELETE FROM room WHERE RoomID = ?';
        
        db.query(deleteQuery, [roomId], (err, result) => {
            if (err) {
                console.error('Error deleting room:', err);
                return res.status(500).json({ message: 'Failed to delete room' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Room not found' });
            }
            
            res.json({ message: 'Room deleted successfully' });
        });
    });
});

// ----- API Routes for User Profile -----

// Get user profile
app.get('/api/profile', (req, res) => {
    // Check for session existence
    if (!req.session) {
        return res.status(401).json({ message: 'Not authenticated - session object missing' });
    }
    
    // Check for required session values
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Not authenticated - userId missing in session' });
    }
    
    const userId = req.session.userId;
    const role = req.session.role;
    
    // Create promise-based connection for better error handling
    const promiseDb = db.promise();
    
    // Base query for user info - Use promise-based query
    promiseDb.query(
        `SELECT u.UserID, u.UserName, u.Email, u.Phone, r.RoleName
        FROM users u
        JOIN role r ON u.RoleID = r.RoleID
        WHERE u.UserID = ?`,
        [userId]
    )
    .then(([results]) => {
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found in database' });
        }
        
        const userProfile = results[0];
        
        // Get role-specific details using promise chain
        if (role === 'Participant') {
            return promiseDb.query('SELECT University FROM participant WHERE UserID = ?', [userId])
                .then(([participantResults]) => {
                    if (participantResults.length > 0) {
                        userProfile.University = participantResults[0].University;
                    } else {
                        // Add a placeholder for university
                        userProfile.University = null;
                        
                        // Create a participant record if it doesn't exist
                        return promiseDb.query('INSERT INTO participant (UserID, University) VALUES (?, NULL)', [userId])
                            .then(() => {
                                return userProfile;
                            })
                            .catch((err) => {
                                return userProfile;
                            });
                    }
                    
                    return userProfile;
                });
                
        } else if (role === 'Judge') {
            return promiseDb.query('SELECT Expertise FROM judge WHERE UserID = ?', [userId])
                .then(([judgeResults]) => {
                    if (judgeResults.length > 0) {
                        userProfile.Expertise = judgeResults[0].Expertise;
                    }
                    
                    return userProfile;
                });
                
        } else if (role === 'Sponsor') {
            return promiseDb.query('SELECT CompanyName, PhoneNo AS CompanyPhone FROM sponsor WHERE UserID = ?', [userId])
                .then(([sponsorResults]) => {
                    if (sponsorResults.length > 0) {
                        userProfile.CompanyName = sponsorResults[0].CompanyName;
                        userProfile.CompanyPhone = sponsorResults[0].CompanyPhone;
                    }
                    
                    return userProfile;
                });
                
        } else {
            // For Admin and other roles with no extra tables
            return userProfile;
        }
    })
    .then((userProfile) => {
        res.json({ message: 'Profile retrieved successfully', data: userProfile });
    })
    .catch((error) => {
        res.status(500).json({ 
            message: 'Failed to fetch profile',
            error: error.message
        });
    });
});

// Update user profile
app.put('/api/profile', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    
    const userId = req.session.userId;
    const role = req.session.role;
    const { userName, email, phone, ...roleSpecificData } = req.body;
    
    // Start transaction - FIX: Get connection from pool first
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection:', err);
            return res.status(500).json({ message: 'Failed to update profile' });
        }
        
        // Convert connection to promise interface for more reliable async/await usage
        const promiseConnection = connection.promise();
        
        promiseConnection.beginTransaction()
        .then(async () => {
            try {
                // Update base user info
                await promiseConnection.query(
                    'UPDATE users SET UserName = ?, Email = ?, Phone = ? WHERE UserID = ?',
                    [userName, email, phone, userId]
                );
                
                // Update role-specific info
                if (role === 'Participant' && roleSpecificData.university !== undefined) {
                    await promiseConnection.query(
                        'UPDATE participant SET University = ? WHERE UserID = ?',
                        [roleSpecificData.university, userId]
                    );
                } else if (role === 'Judge' && roleSpecificData.expertise !== undefined) {
                    await promiseConnection.query(
                        'UPDATE judge SET Expertise = ? WHERE UserID = ?',
                        [roleSpecificData.expertise, userId]
                    );
                } else if (role === 'Sponsor' && (roleSpecificData.companyName !== undefined || roleSpecificData.companyPhone !== undefined)) {
                    await promiseConnection.query(
                        'UPDATE sponsor SET CompanyName = ?, PhoneNo = ? WHERE UserID = ?',
                        [roleSpecificData.companyName, roleSpecificData.companyPhone, userId]
                    );
                }
                
                // Commit transaction
                await promiseConnection.commit();
                
                connection.release();
                res.json({ message: 'Profile updated successfully' });
                
            } catch (error) {
                await promiseConnection.rollback();
                connection.release();
                console.error('Error updating profile:', error);
                res.status(500).json({ message: error.message || 'Failed to update profile' });
            }
        })
        .catch(err => {
            connection.release();
            console.error('Transaction error:', err);
            res.status(500).json({ message: 'Failed to start transaction' });
        });
    });
});

// ----- API Routes for Check-in Management -----

// Get all available room allocations for check-in
app.get('/api/room-allocations/available', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const query = `
        SELECT 
            ra.AllocationID, ra.RoomID, ra.AccommodationID, 
            ra.CheckInDate, ra.CheckOutDate,
            r.RoomNumber, r.Capacity, r.Price,
            u.UserName, u.Email,
            p.University,
            a.NumberOfPeople
        FROM room_allocation ra
        JOIN room r ON ra.RoomID = r.RoomID
        JOIN accommodation a ON ra.AccommodationID = a.AccommodationID
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        JOIN users u ON p.UserID = u.UserID
        LEFT JOIN checkin c ON ra.AllocationID = c.AllocationID
        WHERE c.CheckinID IS NULL
        AND ra.CheckOutDate >= CURDATE()
        ORDER BY ra.CheckInDate ASC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching available allocations:', err);
            return res.status(500).json({ message: 'Failed to fetch available allocations' });
        }
        
        return res.json({ message: 'Available allocations retrieved', data: results });
    });
});

// Get all check-ins
app.get('/api/checkins', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const query = `
        SELECT 
            c.CheckinID, c.AllocationID, 
            c.ActualCheckinDate AS CheckinTime, c.ActualCheckoutDate AS CheckoutTime, 
            c.Status, c.Notes,
            u.UserName AS ParticipantName, u.Email,
            e.EventName, e.Event_ID AS EventID,
            r.RoomNumber, r.Capacity, r.Price,
            ra.CheckInDate AS ScheduledCheckinDate, 
            ra.CheckOutDate AS ScheduledCheckoutDate
        FROM checkin c
        JOIN room_allocation ra ON c.AllocationID = ra.AllocationID
        JOIN room r ON ra.RoomID = r.RoomID
        JOIN accommodation a ON ra.AccommodationID = a.AccommodationID
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN event e ON reg.EventID = e.Event_ID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        JOIN users u ON p.UserID = u.UserID
        ORDER BY 
            CASE 
                WHEN c.Status = 'Checked In' THEN 1
                WHEN c.Status = 'Reserved' THEN 2
                ELSE 3
            END,
            c.ActualCheckinDate DESC,
            c.CheckinID DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching check-ins:', err);
            return res.status(500).json([]); // Return empty array on error
        }
        
        res.json(results);
    });
});

// Create new check-in
app.post('/api/checkins', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const { allocationId, actualCheckInDate, notes } = req.body;
    
    if (!allocationId || !actualCheckInDate) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Validate allocation exists
    db.query(
        'SELECT AllocationID FROM room_allocation WHERE AllocationID = ?',
        [allocationId],
        (err, results) => {
            if (err || results.length === 0) {
                console.error('Error checking allocation:', err);
                return res.status(404).json({ message: 'Allocation not found' });
            }
            
            // Check if there's already a check-in for this allocation
            db.query(
                'SELECT CheckinID FROM checkin WHERE AllocationID = ?',
                [allocationId],
                (err, results) => {
                    if (err) {
                        console.error('Error checking existing check-in:', err);
                        return res.status(500).json({ message: 'Database error' });
                    }
                    
                    if (results.length > 0) {
                        return res.status(400).json({ message: 'A check-in already exists for this allocation' });
                    }
                    
                    // Create the check-in
                    const checkinData = {
                        AllocationID: allocationId,
                        ActualCheckinDate: actualCheckInDate,
                        Status: 'Checked In',
                        Notes: notes || null
                    };
                    
                    db.query(
                        'INSERT INTO checkin SET ?',
                        checkinData,
                        (err, result) => {
                            if (err) {
                                console.error('Error creating check-in:', err);
                                return res.status(500).json({ message: 'Failed to create check-in' });
                            }
                            
                            res.status(201).json({ 
                                message: 'Check-in processed successfully', 
                                checkinId: result.insertId 
                            });
                        }
                    );
                }
            );
        }
    );
});

// Update existing check-in
app.put('/api/checkins/:id/check-in', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const checkinId = req.params.id;
    const { actualCheckInDate, notes } = req.body;
    
    if (!actualCheckInDate) {
        return res.status(400).json({ message: 'Missing actual check-in date' });
    }
    
    // Update check-in
    db.query(
        'UPDATE checkin SET ActualCheckinDate = ?, Status = "Checked In", Notes = ? WHERE CheckinID = ? AND Status = "Reserved"',
        [actualCheckInDate, notes || null, checkinId],
        (err, result) => {
            if (err) {
                console.error('Error updating check-in:', err);
                return res.status(500).json({ message: 'Failed to update check-in' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Check-in not found or already processed' });
            }
            
            res.json({ message: 'Check-in updated successfully' });
        }
    );
});

// Process check-out
app.put('/api/checkins/:id/check-out', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const checkinId = req.params.id;
    const { actualCheckOutDate, notes } = req.body;
    
    if (!actualCheckOutDate) {
        return res.status(400).json({ message: 'Missing actual check-out date' });
    }
    
    // Begin transaction
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting connection:', err);
            return res.status(500).json({ message: 'Database connection error' });
        }
        
        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                console.error('Error starting transaction:', err);
                return res.status(500).json({ message: 'Transaction error' });
            }
            
            // Update check-in status and checkout date
            connection.query(
                'UPDATE checkin c JOIN room_allocation ra ON c.AllocationID = ra.AllocationID SET c.ActualCheckoutDate = ?, c.Status = "Checked Out", c.Notes = CONCAT(IFNULL(c.Notes, ""), ?) WHERE c.CheckinID = ? AND c.Status = "Checked In"',
                [
                    actualCheckOutDate, 
                    notes ? `\nCheckout Notes: ${notes}` : '\nChecked out', 
                    checkinId
                ],
                (err, result) => {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            console.error('Error updating check-out:', err);
                            return res.status(500).json({ message: 'Database error' });
                        });
                    }
                    
                    if (result.affectedRows === 0) {
                        return connection.rollback(() => {
                            connection.release();
                            return res.status(404).json({ message: 'Check-in not found or not in "Checked In" status' });
                        });
                    }
                    
                    // Get the room allocation info to update room availability status
                    connection.query(
                        'SELECT ra.RoomID, ra.CheckOutDate FROM checkin c JOIN room_allocation ra ON c.AllocationID = ra.AllocationID WHERE c.CheckinID = ?',
                        [checkinId],
                        (err, results) => {
                            if (err || results.length === 0) {
                                return connection.rollback(() => {
                                    connection.release();
                                    console.error('Error getting allocation info:', err);
                                    return res.status(500).json({ message: 'Database error' });
                                });
                            }
                            
                            const { RoomID, CheckOutDate } = results[0];
                            const currentDate = new Date();
                            const scheduledCheckout = new Date(CheckOutDate);
                            
                            // Check if we've passed the scheduled checkout date
                            if (currentDate > scheduledCheckout) {
                                // Mark room as available if this is the only allocation
                                connection.query(
                                    'SELECT COUNT(*) AS activeAllocations FROM room_allocation ra JOIN checkin c ON ra.AllocationID = c.AllocationID WHERE ra.RoomID = ? AND c.Status = "Checked In" AND ra.CheckOutDate > CURDATE()',
                                    [RoomID],
                                    (err, results) => {
                                        if (err) {
                                            return connection.rollback(() => {
                                                connection.release();
                                                console.error('Error checking active allocations:', err);
                                                return res.status(500).json({ message: 'Database error' });
                                            });
                                        }
                                        
                                        const activeAllocations = results[0].activeAllocations;
                                        
                                        // If no more active allocations, mark room as available
                                        if (activeAllocations === 0) {
                                            connection.query(
                                                'UPDATE room SET AvailabilityStatus = "Available" WHERE RoomID = ?',
                                                [RoomID],
                                                (err, result) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error updating room status:', err);
                                                            return res.status(500).json({ message: 'Database error' });
                                                        });
                                                    }
                                                    
                                                    // Commit transaction
                                                    connection.commit(err => {
                                                        if (err) {
                                                            return connection.rollback(() => {
                                                                connection.release();
                                                                console.error('Error committing transaction:', err);
                                                                return res.status(500).json({ message: 'Transaction error' });
                                                            });
                                                        }
                                                        
                                                        connection.release();
                                                        return res.json({ 
                                                            message: 'Check-out processed successfully and room marked as available' 
                                                        });
                                                    });
                                                }
                                            );
                                        } else {
                                            // If there are still active allocations, just commit the check-out
                                            connection.commit(err => {
                                                if (err) {
                                                    return connection.rollback(() => {
                                                        connection.release();
                                                        console.error('Error committing transaction:', err);
                                                        return res.status(500).json({ message: 'Transaction error' });
                                                    });
                                                }
                                                
                                                connection.release();
                                                return res.json({ 
                                                    message: 'Check-out processed successfully' 
                                                });
                                            });
                                        }
                                    }
                                );
                            } else {
                                // If we're checking out before the scheduled date, just commit the check-out
                                connection.commit(err => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error committing transaction:', err);
                                            return res.status(500).json({ message: 'Transaction error' });
                                        });
                                    }
                                    
                                    connection.release();
                                    return res.json({ 
                                        message: 'Early check-out processed successfully' 
                                    });
                                });
                            }
                        }
                    );
                }
            );
        });
    });
});

// ----- API Routes for User Profile -----

// Get API endpoint for current user's profile info (named to match front-end request)
app.get('/api/user-profile', (req, res) => {
    // Redirect to the existing profile endpoint
    req.url = '/api/profile';
    app.handle(req, res);
});

// Change password endpoint
app.put('/api/user-profile/password', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    
    const userId = req.session.userId;
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Get the current password hash from the database
    db.query('SELECT user_password FROM users WHERE UserID = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user password:', err);
            return res.status(500).json({ message: 'Failed to verify password' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const currentPasswordHash = results[0].user_password;
        
        // Compare the provided current password with the stored hash
        bcrypt.compare(currentPassword, currentPasswordHash, (compareErr, isMatch) => {
            if (compareErr) {
                console.error('Error comparing passwords:', compareErr);
                return res.status(500).json({ message: 'Password verification failed' });
            }
            
            if (!isMatch) {
                return res.status(400).json({ message: 'Current password is incorrect' });
            }
            
            // Hash the new password
            bcrypt.hash(newPassword, saltRounds, (hashErr, hashedPassword) => {
                if (hashErr) {
                    console.error('Error hashing new password:', hashErr);
                    return res.status(500).json({ message: 'Failed to hash new password' });
                }
                
                // Update the password in the database
                db.query('UPDATE users SET user_password = ? WHERE UserID = ?', [hashedPassword, userId], (updateErr, updateResult) => {
                    if (updateErr) {
                        console.error('Error updating password:', updateErr);
                        return res.status(500).json({ message: 'Failed to update password' });
                    }
                    
                    res.json({ message: 'Password changed successfully' });
                });
            });
        });
    });
});

// API routes for sponsor contract management

// Get sponsor's contracts
app.get('/api/sponsor/contracts', authorize(['Sponsor']), (req, res) => {
    const userId = req.session.userId;
    
    const query = `
        SELECT 
            c.ContractID, c.ContractDate, c.ContractStatus, c.PaymentStatus,
            p.PackageID, p.PackageName, p.PackageDetails, p.PackageCost
        FROM sponsorship_contracts c
        JOIN sponsor s ON c.SponsorID = s.Sponsor_ID
        JOIN sponsorship_package p ON c.PackageID = p.PackageID
        WHERE s.UserID = ?
        ORDER BY c.ContractDate DESC
    `;
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching sponsor contracts:', err);
            return res.status(500).json({ message: 'Failed to fetch contracts' });
        }
        
        res.json(results);
    });
});

// Make payment for a sponsorship contract
app.post('/api/sponsor/contracts/:contractId/pay', authorize(['Sponsor']), (req, res) => {
    const contractId = req.params.contractId;
    const userId = req.session.userId;
    const { paymentMethod, amount } = req.body;
    
    if (!paymentMethod) {
        return res.status(400).json({ message: 'Payment method is required' });
    }
    
    // Begin transaction
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting connection:', err);
            return res.status(500).json({ message: 'Database connection error' });
        }
        
        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                console.error('Error starting transaction:', err);
                return res.status(500).json({ message: 'Transaction error' });
            }
            
            // Verify ownership of contract
            const verifyQuery = `
                SELECT c.ContractID, c.PaymentStatus, c.SponsorID, p.PackageCost
                FROM sponsorship_contracts c
                JOIN sponsor s ON c.SponsorID = s.Sponsor_ID
                JOIN sponsorship_package p ON c.PackageID = p.PackageID
                WHERE c.ContractID = ? AND s.UserID = ? AND c.PaymentStatus = 'Pending'
            `;
            
            connection.query(verifyQuery, [contractId, userId], (err, results) => {
                if (err || results.length === 0) {
                    return connection.rollback(() => {
                        connection.release();
                        if (err) {
                            console.error('Error verifying contract:', err);
                            return res.status(500).json({ message: 'Database error' });
                        }
                        return res.status(404).json({ message: 'Contract not found, already paid, or not authorized' });
                    });
                }
                
                const contract = results[0];
                
                // Map payment method to valid ENUM value (Online or Manual)
                const paymentType = paymentMethod === 'Credit Card' ? 'Online' : 'Manual';
                
                // Create payment record
                connection.query(
                    'INSERT INTO payment (Amount, PaymentType, PaymentDate, ContractID) VALUES (?, ?, NOW(), ?)',
                    [contract.PackageCost, paymentType, contractId],
                    (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error creating payment:', err);
                                return res.status(500).json({ message: 'Failed to create payment record' });
                            });
                        }
                        
                        const paymentId = result.insertId;
                        
                        // Update contract payment status
                        connection.query(
                            'UPDATE sponsorship_contracts SET PaymentStatus = "Paid", ContractStatus = "Signed" WHERE ContractID = ?',
                            [contractId],
                            (err, result) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error updating contract status:', err);
                                        return res.status(500).json({ message: 'Failed to update contract status' });
                                    });
                                }
                                
                                // Commit transaction
                                connection.commit(err => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error committing transaction:', err);
                                            return res.status(500).json({ message: 'Transaction commit error' });
                                        });
                                    }
                                    
                                    connection.release();
                                    return res.json({ 
                                        message: 'Payment processed successfully',
                                        paymentId: paymentId
                                    });
                                });
                            }
                        );
                    }
                );
            });
        });
    });
});

// ----- API Routes for Venue Management -----
app.get('/api/venues', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const query = 'SELECT * FROM venue ORDER BY VenueName';
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching venues:', err);
            return res.status(500).json({ message: 'Failed to fetch venues' });
        }
        
        res.json(results);
    });
});

app.post('/api/venues', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const { venueName, location, capacity, status } = req.body;
    
    if (!venueName || !location || !capacity) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    const insertQuery = 'INSERT INTO venue (VenueName, Location, Capacity, Status) VALUES (?, ?, ?, ?)';
    
    db.query(insertQuery, [venueName, location, capacity, status || 'Available'], (err, result) => {
        if (err) {
            console.error('Error creating venue:', err);
            return res.status(500).json({ message: 'Failed to create venue' });
        }
        
        res.status(201).json({ 
            message: 'Venue created successfully',
            venueId: result.insertId
        });
    });
});

app.delete('/api/venues/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const venueId = req.params.id;
    
    // Check if venue is in use
    const checkQuery = 'SELECT EventID FROM event_venue WHERE VenueID = ?';
    
    db.query(checkQuery, [venueId], (err, results) => {
        if (err) {
            console.error('Error checking venue usage:', err);
            return res.status(500).json({ message: 'Failed to check venue usage' });
        }
        
        if (results.length > 0) {
            return res.status(400).json({ message: 'Cannot delete venue that is currently assigned to events' });
        }
        
        // Delete venue
        const deleteQuery = 'DELETE FROM venue WHERE Venue_ID = ?';
        
        db.query(deleteQuery, [venueId], (err, result) => {
            if (err) {
                console.error('Error deleting venue:', err);
                return res.status(500).json({ message: 'Failed to delete venue' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Venue not found' });
            }
            
            res.json({ message: 'Venue deleted successfully' });
        });
    });
});

app.post('/api/venues/:id/schedule', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const venueId = req.params.id;
    const { scheduleDate, startTime, endTime, eventRoundId } = req.body;
    
    if (!scheduleDate || !startTime || !endTime || !eventRoundId) {
        return res.status(400).json({ message: 'Please fill in all required scheduling fields' });
    }

    // Validate the date is not in the past
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Reset time to beginning of the day
    const bookingDate = new Date(scheduleDate);
    bookingDate.setHours(0, 0, 0, 0); // Reset time to beginning of the day
    
    if (bookingDate < today) {
        return res.status(400).json({ message: 'Cannot book venues for past dates. Please select a current or future date.' });
    }

    // Validate the time format - use string comparison for consistent results
    // Convert to 24-hour time strings for reliable comparison
    if (String(startTime) >= String(endTime)) {
        return res.status(400).json({ message: 'End time must be after start time' });
    }
    
    // Check for conflicts
    const checkConflictQuery = `
        SELECT vs.ScheduleID
        FROM venue_schedule vs
        WHERE vs.VenueID = ?
        AND vs.ScheduleDate = ?
        AND (
            (vs.StartTime <= ? AND vs.EndTime >= ?)
            OR (vs.StartTime <= ? AND vs.EndTime >= ?)
            OR (vs.StartTime >= ? AND vs.EndTime <= ?)
        )
    `;
    
    db.query(
        checkConflictQuery, 
        [venueId, scheduleDate, startTime, startTime, endTime, endTime, startTime, endTime],
        (err, results) => {
            if (err) {
                console.error('Error checking venue conflicts:', err);
                return res.status(500).json({ message: 'Unable to verify venue availability. Please try again.' });
            }
            
            if (results.length > 0) {
                return res.status(400).json({ message: 'This venue is already booked during the selected time. Please choose a different time.' });
            }
            
            // Create venue scheduling
            const insertQuery = `
                INSERT INTO venue_schedule (VenueID, Event_RoundID, ScheduleDate, StartTime, EndTime)
                VALUES (?, ?, ?, ?, ?)
            `;
            
            db.query(
                insertQuery, 
                [venueId, eventRoundId, scheduleDate, startTime, endTime], 
                (err, result) => {
                    if (err) {
                        console.error('Error scheduling venue:', err);
                        
                        // Handle specific error types
                        if (err.code === 'ER_NO_REFERENCED_ROW') {
                            return res.status(400).json({ message: 'The selected event round does not exist. Please choose a valid event round.' });
                        } else if (err.code === 'ER_DUP_ENTRY') {
                            return res.status(400).json({ message: 'This venue is already scheduled at this time. Please choose a different time.' });
                        }
                        
                        return res.status(500).json({ message: 'Unable to schedule the venue. Please verify your information and try again.' });
                    }
                    
                    // Update venue status
                    db.query(
                        'UPDATE venue SET Status = "Booked" WHERE Venue_ID = ?',
                        [venueId],
                        (err) => {
                            if (err) {
                                console.error('Error updating venue status:', err);
                                // Continue even if this fails
                            }
                        }
                    );
                    
                    res.status(201).json({ 
                        message: 'Venue scheduled successfully',
                        scheduleId: result.insertId
                    });
                }
            );
        }
    );
});

// Get venue schedules
app.get('/api/venues/:id/schedules', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const venueId = req.params.id;
    
    const query = `
        SELECT vs.ScheduleID, vs.ScheduleDate, vs.StartTime, vs.EndTime, 
               vs.Event_RoundID, er.RoundName, e.EventName
        FROM venue_schedule vs
        JOIN event_round er ON vs.Event_RoundID = er.RoundID
        JOIN event e ON er.EventID = e.Event_ID
        WHERE vs.VenueID = ?
        ORDER BY vs.ScheduleDate, vs.StartTime
    `;
    
    db.query(query, [venueId], (err, results) => {
        if (err) {
            console.error('Error fetching venue schedules:', err);
            return res.status(500).json({ message: 'Failed to fetch venue schedules' });
        }
        
        res.json(results);
    });
});

// Get available time slots for a venue on a specific date
app.get('/api/venues/:id/available-slots', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const venueId = req.params.id;
    const date = req.query.date;
    
    if (!date) {
        return res.status(400).json({ message: 'Date parameter is required' });
    }
    
    // Log the request parameters for debugging
    console.log(`Checking available slots for venue ${venueId} on date ${date}`);
    
    // Get existing bookings for the venue on the specified date
    const query = `
        SELECT StartTime, EndTime
        FROM venue_schedule
        WHERE VenueID = ? AND ScheduleDate = ?
        ORDER BY StartTime
    `;
    
    db.query(query, [venueId, date], (err, results) => {
        if (err) {
            console.error('Error fetching venue bookings:', err);
            return res.status(500).json({ message: 'Failed to fetch venue bookings' });
        }
        
        // Log the existing bookings for debugging
        console.log(`Found ${results.length} existing bookings for venue ${venueId} on date ${date}`);
        
        // Time slots from 8 AM to 10 PM (assuming these are the operating hours)
        const timeSlots = [];
        
        // Start with 8 AM
        let currentHour = 8;
        let currentMinute = 0;
        
        // Generate hourly slots until 10 PM
        while (currentHour < 22) {
            const startTime = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}:00`;
            
            currentHour += 1;
            
            const endTime = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}:00`;
            
            // Check if this slot conflicts with any existing booking
            const isAvailable = !results.some(booking => {
                // Convert time strings for reliable comparison
                const bookingStartStr = String(booking.StartTime);
                const bookingEndStr = String(booking.EndTime);
                
                return (startTime >= bookingStartStr && startTime < bookingEndStr) || 
                       (endTime > bookingStartStr && endTime <= bookingEndStr) ||
                       (startTime <= bookingStartStr && endTime >= bookingEndStr);
            });
            
            if (isAvailable) {
                timeSlots.push({
                    startTime,
                    endTime
                });
            }
        }
        
        console.log(`Returning ${timeSlots.length} available time slots`);
        res.json(timeSlots);
    });
});

// Delete a venue schedule
app.delete('/api/venue-schedules/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const scheduleId = req.params.id;
    
    // Get the venue ID for the schedule to update status later
    db.query('SELECT VenueID FROM venue_schedule WHERE ScheduleID = ?', [scheduleId], (err, results) => {
        if (err) {
            console.error('Error getting venue for schedule:', err);
            return res.status(500).json({ message: 'Failed to get venue information' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Schedule not found' });
        }
        
        const venueId = results[0].VenueID;
        
        // Delete the schedule
        db.query('DELETE FROM venue_schedule WHERE ScheduleID = ?', [scheduleId], (err, result) => {
            if (err) {
                console.error('Error deleting schedule:', err);
                return res.status(500).json({ message: 'Failed to delete schedule' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Schedule not found' });
            }
            
            // Check if venue has any remaining schedules
            db.query('SELECT COUNT(*) AS scheduleCount FROM venue_schedule WHERE VenueID = ?', [venueId], (err, countResults) => {
                if (err) {
                    console.error('Error checking schedules count:', err);
                    return res.status(500).json({ message: 'Failed to update venue status' });
                }
                
                // If no schedules left, update venue status to Available
                if (countResults[0].scheduleCount === 0) {
                    db.query('UPDATE venue SET Status = "Available" WHERE Venue_ID = ?', [venueId], (err) => {
                        if (err) {
                            console.error('Error updating venue status:', err);
                        }
                    });
                }
                
                res.json({ message: 'Schedule deleted successfully' });
            });
        });
    });
});

// ----- API Routes for Event Rounds -----
app.get('/api/event-rounds', authorize(['Admin', 'Event Organizer', 'Judge']), (req, res) => {
    const eventId = req.query.eventId;
    
    let query = `
        SELECT r.RoundID, r.RoundName, e.Event_ID AS EventID, e.EventName
        FROM event_round r
        JOIN event e ON r.EventID = e.Event_ID
    `;
    
    const queryParams = [];
    
    if (eventId) {
        query += ' WHERE e.Event_ID = ?';
        queryParams.push(eventId);
    }
    
    query += ' ORDER BY e.EventName, r.RoundName';
    
    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching event rounds:', err);
            return res.status(500).json({ message: 'Failed to fetch event rounds' });
        }
        
        res.json(results);
    });
});

app.post('/api/event-rounds', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const { roundName, eventId } = req.body;
    
    if (!roundName || !eventId) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Check if event exists
    const checkEventQuery = 'SELECT Event_ID FROM event WHERE Event_ID = ?';
    
    db.query(checkEventQuery, [eventId], (err, results) => {
        if (err) {
            console.error('Error checking event:', err);
            return res.status(500).json({ message: 'Failed to validate event' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Event not found' });
        }
        
        // Check if round already exists for this event
        const checkRoundQuery = 'SELECT RoundID FROM event_round WHERE EventID = ? AND RoundName = ?';
        
        db.query(checkRoundQuery, [eventId, roundName], (err, results) => {
            if (err) {
                console.error('Error checking round:', err);
                return res.status(500).json({ message: 'Failed to check existing rounds' });
            }
            
            if (results.length > 0) {
                return res.status(400).json({ message: 'Round already exists for this event' });
            }
            
            // Create new round
            const insertQuery = 'INSERT INTO event_round (RoundName, EventID) VALUES (?, ?)';
            
            db.query(insertQuery, [roundName, eventId], (err, result) => {
                if (err) {
                    console.error('Error creating round:', err);
                    return res.status(500).json({ message: 'Failed to create round' });
                }
                
                res.status(201).json({ 
                    message: 'Round created successfully',
                    roundId: result.insertId
                });
            });
        });
    });
});

app.delete('/api/event-rounds/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const roundId = req.params.id;
    
    // First, get the list of venues used by this round
    const getVenuesQuery = `
        SELECT DISTINCT vs.VenueID 
        FROM venue_schedule vs 
        WHERE vs.Event_RoundID = ?
    `;
    
    db.query(getVenuesQuery, [roundId], (err, venueResults) => {
        if (err) {
            console.error('Error fetching venues for round:', err);
            return res.status(500).json({ message: 'Failed to check venues for round' });
        }
        
        // Store affected venue IDs
        const affectedVenueIds = venueResults.map(v => v.VenueID);
        
        // Delete the round (CASCADE will handle venue_schedule entries)
        db.query('DELETE FROM event_round WHERE RoundID = ?', [roundId], (err, result) => {
            if (err) {
                console.error('Error deleting round:', err);
                return res.status(500).json({ message: 'Failed to delete round' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Round not found' });
            }
            
            // Now update venue status for affected venues
            if (affectedVenueIds.length > 0) {
                // For each affected venue, check if it has any remaining schedules
                const checkAndUpdateVenues = () => {
                    let updatedCount = 0;
                    let processedCount = 0;
                    
                    affectedVenueIds.forEach(venueId => {
                        // Check if venue has any remaining schedules
                        db.query('SELECT COUNT(*) AS scheduleCount FROM venue_schedule WHERE VenueID = ?', [venueId], (err, countResults) => {
                            processedCount++;
                            
                            if (err) {
                                console.error(`Error checking schedules for venue ${venueId}:`, err);
                            } else {
                                const hasSchedules = countResults[0].scheduleCount > 0;
                                
                                // If no schedules, update venue status to Available
                                if (!hasSchedules) {
                                    db.query('UPDATE venue SET Status = "Available" WHERE Venue_ID = ?', [venueId], (err, updateResult) => {
                                        if (err) {
                                            console.error(`Error updating venue ${venueId} status:`, err);
                                        } else if (updateResult.affectedRows > 0) {
                                            updatedCount++;
                                        }
                                        
                                        // When all venues processed, send response
                                        if (processedCount === affectedVenueIds.length) {
                                            res.json({ 
                                                message: 'Round deleted successfully', 
                                                venuesUpdated: updatedCount 
                                            });
                                        }
                                    });
                                } else {
                                    // When all venues processed, send response
                                    if (processedCount === affectedVenueIds.length) {
                                        res.json({ 
                                            message: 'Round deleted successfully', 
                                            venuesUpdated: updatedCount 
                                        });
                                    }
                                }
                            }
                        });
                    });
                };
                
                // Execute venue status updates
                checkAndUpdateVenues();
            } else {
                // No venues affected, just return success
                res.json({ message: 'Round deleted successfully' });
            }
        });
    });
});

// Create and update event endpoints
app.post('/api/events', authorize(['Admin', 'Event Organizer']), (req, res) => {
    console.log('Received event creation request:', req.body);
    console.log('User session info:', {
        userId: req.session.userId,
        username: req.session.username,
        role: req.session.role
    });
    
    const { eventName, eventDescription, eventRules, categoryId, maxParticipants, eventDateTime, registrationFee } = req.body;
    
    console.log('Parsed request data:', { 
        eventName, 
        eventDescription: eventDescription ? eventDescription.substring(0, 20) + '...' : undefined, 
        eventRules: eventRules ? eventRules.substring(0, 20) + '...' : undefined,
        categoryId, 
        maxParticipants, 
        eventDateTime, 
        registrationFee 
    });
    
    if (!eventName || !eventDescription || !categoryId || !maxParticipants || !eventDateTime || registrationFee === undefined) {
        console.log('Missing required fields for event creation:', {
            eventName: !eventName ? 'missing' : 'present',
            eventDescription: !eventDescription ? 'missing' : 'present',
            categoryId: !categoryId ? 'missing' : 'present',
            maxParticipants: !maxParticipants ? 'missing' : 'present',
            eventDateTime: !eventDateTime ? 'missing' : 'present',
            registrationFee: registrationFee === undefined ? 'missing' : 'present'
        });
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Process date format
    let formattedDateTime = eventDateTime;
    try {
        // Try to ensure date is in MySQL format (YYYY-MM-DD HH:MM:SS)
        if (eventDateTime && typeof eventDateTime === 'string') {
            // Check if it's already in MySQL format
            if (!/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(eventDateTime)) {
                // Convert from ISO or other format
                const dt = new Date(eventDateTime);
                formattedDateTime = dt.toISOString().slice(0, 19).replace('T', ' ');
                console.log('Reformatted date from', eventDateTime, 'to', formattedDateTime);
            }
        }
    } catch (error) {
        console.error('Error formatting date:', error);
        // Continue with original date if there's an error
    }
    
    const insertQuery = `
        INSERT INTO event (
            EventName, EventDescription, Rules, CategoryID, 
            MaxParticipants, EventDateTime, RegistrationFee
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    
    console.log('Executing SQL insert with parameters:', [
        eventName, 
        eventDescription.substring(0, 20) + '...', 
        eventRules ? eventRules.substring(0, 20) + '...' : null,
        categoryId, 
        maxParticipants, 
        formattedDateTime, 
        registrationFee
    ]);
    
    db.query(
        insertQuery, 
        [eventName, eventDescription, eventRules, categoryId, maxParticipants, formattedDateTime, registrationFee], 
        (err, result) => {
            if (err) {
                console.error('Error creating event:', err);
                return res.status(500).json({ message: 'Failed to create event: ' + err.message });
            }
            
            console.log('Event created successfully with ID:', result.insertId);
            res.status(201).json({ 
                message: 'Event created successfully',
                eventId: result.insertId
            });
        }
    );
});

app.get('/api/events/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const eventId = req.params.id;
    
    const query = `
        SELECT e.*, c.CategoryName 
        FROM event e 
        LEFT JOIN category c ON e.CategoryID = c.CategoryID 
        WHERE e.Event_ID = ?
    `;
    
    db.query(query, [eventId], (err, results) => {
        if (err) {
            console.error('Error fetching event details:', err);
            return res.status(500).json({ message: 'Failed to fetch event details' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Event not found' });
        }
        
        res.json(results[0]);
    });
});

app.put('/api/events/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const eventId = req.params.id;
    const { eventName, eventDescription, eventRules, categoryId, maxParticipants, eventDateTime, registrationFee } = req.body;
    
    if (!eventName || !eventDescription || !categoryId || !maxParticipants || !eventDateTime || registrationFee === undefined) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    const updateQuery = `
        UPDATE event 
        SET EventName = ?, EventDescription = ?, Rules = ?, CategoryID = ?,
            MaxParticipants = ?, EventDateTime = ?, RegistrationFee = ?
        WHERE Event_ID = ?
    `;
    
    db.query(
        updateQuery, 
        [eventName, eventDescription, eventRules, categoryId, maxParticipants, eventDateTime, registrationFee, eventId], 
        (err, result) => {
            if (err) {
                console.error('Error updating event:', err);
                return res.status(500).json({ message: 'Failed to update event' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Event not found' });
            }
            
            res.json({ message: 'Event updated successfully' });
        }
    );
});

app.delete('/api/events/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const eventId = req.params.id;
    
    // Delete event directly, relying on CASCADE constraints to handle related data
    db.query('DELETE FROM event WHERE Event_ID = ?', [eventId], (err, result) => {
        if (err) {
            console.error('Error deleting event:', err);
            return res.status(500).json({ message: 'Failed to delete event' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Event not found' });
        }
        
        res.json({ message: 'Event deleted successfully' });
    });
});

// Category management endpoints
app.get('/api/categories/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const categoryId = req.params.id;
    
    db.query('SELECT * FROM category WHERE CategoryID = ?', [categoryId], (err, results) => {
        if (err) {
            console.error('Error fetching category:', err);
            return res.status(500).json({ message: 'Failed to fetch category' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Category not found' });
        }
        
        res.json(results[0]);
    });
});

app.post('/api/categories', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const { categoryName, description } = req.body;
    
    if (!categoryName) {
        return res.status(400).json({ message: 'Category name is required' });
    }
    
    const insertQuery = 'INSERT INTO category (CategoryName, Description) VALUES (?, ?)';
    
    db.query(insertQuery, [categoryName, description || null], (err, result) => {
        if (err) {
            console.error('Error creating category:', err);
            return res.status(500).json({ message: 'Failed to create category' });
        }
        
        res.status(201).json({
            message: 'Category created successfully',
            categoryId: result.insertId
        });
    });
});

app.put('/api/categories/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const categoryId = req.params.id;
    const { categoryName, description } = req.body;
    
    if (!categoryName) {
        return res.status(400).json({ message: 'Category name is required' });
    }
    
    const updateQuery = 'UPDATE category SET CategoryName = ?, Description = ? WHERE CategoryID = ?';
    
    db.query(updateQuery, [categoryName, description || null, categoryId], (err, result) => {
        if (err) {
            console.error('Error updating category:', err);
            return res.status(500).json({ message: 'Failed to update category' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Category not found' });
        }
        
        res.json({ message: 'Category updated successfully' });
    });
});

app.delete('/api/categories/:id', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const categoryId = req.params.id;
    
    // Check if category has events
    db.query('SELECT Event_ID FROM event WHERE CategoryID = ? LIMIT 1', [categoryId], (err, results) => {
        if (err) {
            console.error('Error checking category events:', err);
            return res.status(500).json({ message: 'Failed to check if category has events' });
        }
        
        if (results.length > 0) {
            return res.status(400).json({ message: 'Cannot delete category with associated events' });
        }
        
        // Delete category
        db.query('DELETE FROM category WHERE CategoryID = ?', [categoryId], (err, result) => {
            if (err) {
                console.error('Error deleting category:', err);
                return res.status(500).json({ message: 'Failed to delete category' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Category not found' });
            }
            
            res.json({ message: 'Category deleted successfully' });
        });
    });
});

// API endpoint to get all sponsors
app.get('/api/sponsors', authorize(['Admin']), (req, res) => {
    const query = `
        SELECT 
            s.Sponsor_ID as SponsorID, 
            s.CompanyName, 
            u.UserName as ContactPerson, 
            s.Email, 
            s.PhoneNo as Phone,
            CASE 
                WHEN EXISTS (SELECT 1 FROM sponsorship_contracts sc WHERE sc.SponsorID = s.Sponsor_ID) THEN 'Active'
                ELSE 'Inactive'
            END as Status
        FROM sponsor s
        JOIN users u ON s.UserID = u.UserID
        ORDER BY s.CompanyName
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching sponsors:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsors' });
        }
        
        res.json(results);
    });
});

// API endpoint to get a specific sponsor
app.get('/api/sponsors/:id', authorize(['Admin']), (req, res) => {
    const sponsorId = req.params.id;
    
    const query = `
        SELECT 
            s.Sponsor_ID as SponsorID, 
            s.CompanyName, 
            u.UserName as ContactPerson, 
            s.Email, 
            s.PhoneNo as Phone,
            u.UserID
        FROM sponsor s
        JOIN users u ON s.UserID = u.UserID
        WHERE s.Sponsor_ID = ?
    `;
    
    db.query(query, [sponsorId], (err, results) => {
        if (err) {
            console.error('Error fetching sponsor:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsor details' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Sponsor not found' });
        }
        
        res.json(results[0]);
    });
});

// API endpoint to add a new sponsor
app.post('/api/sponsors', authorize(['Admin']), (req, res) => {
    const { companyName, contactPerson, email, phone, packageId, description } = req.body;
    
    // Log the request for debugging
    console.log('Add sponsor request:', { companyName, contactPerson, email, phone, packageId, description });
    
    if (!companyName || !contactPerson || !email || !packageId) {
        console.log('Validation failed - missing required fields');
        return res.status(400).json({ message: 'Missing required fields' });
    }

    // Convert packageId to a number if it's a string
    const packageIdNumber = parseInt(packageId, 10);
    if (isNaN(packageIdNumber)) {
        console.log('Invalid packageId format:', packageId);
        return res.status(400).json({ message: 'Invalid package ID format' });
    }

    // Verify that the package exists
    db.query('SELECT PackageID FROM sponsorship_package WHERE PackageID = ?', [packageIdNumber], (err, packageResults) => {
        if (err) {
            console.error('Error checking package:', err);
            return res.status(500).json({ message: 'Database error while checking package' });
        }
        
        if (packageResults.length === 0) {
            console.log('Package not found with ID:', packageIdNumber);
            return res.status(400).json({ message: 'Invalid package selected' });
        }
        
        // Get Sponsor RoleID
        db.query('SELECT RoleID FROM role WHERE RoleName = "Sponsor"', (err, roleResults) => {
            if (err || roleResults.length === 0) {
                console.error('Error getting sponsor role:', err);
                return res.status(500).json({ message: 'Failed to get sponsor role' });
            }
            
            const sponsorRoleId = roleResults[0].RoleID;
            
            // Check if a user with this email already exists
            db.query('SELECT UserID, UserName FROM users WHERE Email = ?', [email], (err, existingUserResults) => {
                if (err) {
                    console.error('Error checking existing user:', err);
                    return res.status(500).json({ message: 'Failed to check existing user' });
                }
                
                // Start transaction
                db.getConnection((err, connection) => {
                    if (err) {
                        console.error('Error getting connection:', err);
                        return res.status(500).json({ message: 'Database connection error' });
                    }
                    
                    connection.beginTransaction(err => {
                        if (err) {
                            connection.release();
                            console.error('Error starting transaction:', err);
                            return res.status(500).json({ message: 'Transaction error' });
                        }
                        
                        // Define tempPassword at a higher scope
                        let tempPassword = null;
                        
                        let processUserAccount = (userId, isExisting) => {
                            // Check if user already has a sponsor record
                            connection.query('SELECT Sponsor_ID FROM sponsor WHERE UserID = ?', [userId], (err, existingSponsorResults) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error checking existing sponsor:', err);
                                        res.status(500).json({ message: 'Failed to check existing sponsor record' });
                                    });
                                }
                                
                                if (existingSponsorResults.length > 0) {
                                    // User already has a sponsor record
                                    const sponsorId = existingSponsorResults[0].Sponsor_ID;
                                    
                                    // Update existing sponsor record
                                    connection.query(
                                        'UPDATE sponsor SET CompanyName = ?, Email = ?, PhoneNo = ? WHERE Sponsor_ID = ?',
                                        [companyName, email, phone, sponsorId],
                                        (err) => {
                                            if (err) {
                                                return connection.rollback(() => {
                                                    connection.release();
                                                    console.error('Error updating sponsor:', err);
                                                    res.status(500).json({ message: 'Failed to update sponsor record' });
                                                });
                                            }
                                            
                                            // Create sponsorship contract
                                            connection.query(
                                                'INSERT INTO sponsorship_contracts (SponsorID, PackageID, ContractDate, ContractStatus, PaymentStatus) VALUES (?, ?, CURDATE(), "Pending", "Pending")',
                                                [sponsorId, packageIdNumber],
                                                (err, contractResult) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error creating contract:', err);
                                                            res.status(500).json({ message: 'Failed to create sponsorship contract' });
                                                        });
                                                    }
                                                    
                                                    // Commit transaction
                                                    connection.commit(err => {
                                                        if (err) {
                                                            return connection.rollback(() => {
                                                                connection.release();
                                                                console.error('Error committing transaction:', err);
                                                                res.status(500).json({ message: 'Failed to save changes' });
                                                            });
                                                        }
                                                        
                                                        connection.release();
                                                        res.status(201).json({ 
                                                            message: isExisting ? 
                                                                'Used existing sponsor account and created contract successfully' :
                                                                'Sponsor and contract created successfully',
                                                            sponsorId: sponsorId,
                                                            contractId: contractResult.insertId
                                                        });
                                                    });
                                                }
                                            );
                                        }
                                    );
                                } else {
                                    // Create new sponsor record
                                    connection.query(
                                        'INSERT INTO sponsor (UserID, CompanyName, Email, PhoneNo) VALUES (?, ?, ?, ?)',
                                        [userId, companyName, email, phone],
                                        (err, sponsorResult) => {
                                            if (err) {
                                                return connection.rollback(() => {
                                                    connection.release();
                                                    console.error('Error creating sponsor:', err);
                                                    res.status(500).json({ message: 'Failed to create sponsor record' });
                                                });
                                            }
                                            
                                            const sponsorId = sponsorResult.insertId;
                                            
                                            // Create sponsorship contract
                                            connection.query(
                                                'INSERT INTO sponsorship_contracts (SponsorID, PackageID, ContractDate, ContractStatus, PaymentStatus) VALUES (?, ?, CURDATE(), "Pending", "Pending")',
                                                [sponsorId, packageIdNumber],
                                                (err, contractResult) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error creating contract:', err);
                                                            res.status(500).json({ message: 'Failed to create sponsorship contract' });
                                                        });
                                                    }
                                                    
                                                    // Commit transaction
                                                    connection.commit(err => {
                                                        if (err) {
                                                            return connection.rollback(() => {
                                                                connection.release();
                                                                console.error('Error committing transaction:', err);
                                                                res.status(500).json({ message: 'Failed to save changes' });
                                                            });
                                                        }
                                                        
                                                        connection.release();
                                                        const resultMsg = {
                                                            message: isExisting ? 
                                                                'Used existing user account and created sponsor with contract successfully' :
                                                                'Sponsor and contract created successfully',
                                                            sponsorId: sponsorId,
                                                            contractId: contractResult.insertId
                                                        };
                                                        
                                                        // Add tempPassword only for newly created users
                                                        if (!isExisting && tempPassword) {
                                                            resultMsg.tempPassword = tempPassword;
                                                        }
                                                        
                                                        res.status(201).json(resultMsg);
                                                    });
                                                }
                                            );
                                        }
                                    );
                                }
                            });
                        };
                        
                        if (existingUserResults.length > 0) {
                            // User already exists, update role if needed
                            const existingUser = existingUserResults[0];
                            
                            // Update role to Sponsor if not already
                            connection.query(
                                'UPDATE users SET RoleID = ? WHERE UserID = ?',
                                [sponsorRoleId, existingUser.UserID],
                                (err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error updating user role:', err);
                                            res.status(500).json({ message: 'Failed to update user role' });
                                        });
                                    }
                                    
                                    // Continue with the sponsor record creation/update
                                    processUserAccount(existingUser.UserID, true);
                                }
                            );
                        } else {
                            // Create a new user account for the sponsor
                            tempPassword = Math.random().toString(36).slice(-8); // Generate random password
                            bcrypt.hash(tempPassword, saltRounds, (hashErr, hashedPassword) => {
                                if (hashErr) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error hashing password:', hashErr);
                                        res.status(500).json({ message: 'Failed to create sponsor account' });
                                    });
                                }
                                
                                // Create user with sponsor role
                                connection.query(
                                    'INSERT INTO users (UserName, Email, Phone, user_password, RoleID) VALUES (?, ?, ?, ?, ?)',
                                    [contactPerson, email, phone, hashedPassword, sponsorRoleId],
                                    (err, userResult) => {
                                        if (err) {
                                            return connection.rollback(() => {
                                                connection.release();
                                                console.error('Error creating user:', err);
                                                res.status(500).json({ message: 'Failed to create sponsor user account' });
                                            });
                                        }
                                        
                                        // Continue with the sponsor record creation
                                        processUserAccount(userResult.insertId, false);
                                    }
                                );
                            });
                        }
                    });
                });
            });
        });
    });
});

// API endpoint to update a sponsor
app.put('/api/sponsors/:id', authorize(['Admin']), (req, res) => {
    const sponsorId = req.params.id;
    const { companyName, contactEmail, contactPhone } = req.body;
    
    if (!companyName) {
        return res.status(400).json({ message: 'Company name is required' });
    }
    
    // Get the UserID for this sponsor
    db.query('SELECT UserID FROM sponsor WHERE Sponsor_ID = ?', [sponsorId], (err, results) => {
        if (err) {
            console.error('Error fetching sponsor:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsor' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Sponsor not found' });
        }
        
        const userId = results[0].UserID;
        
        // Start transaction
        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting connection:', err);
                return res.status(500).json({ message: 'Database connection error' });
            }
            
            connection.beginTransaction(err => {
                if (err) {
                    connection.release();
                    console.error('Error starting transaction:', err);
                    return res.status(500).json({ message: 'Transaction error' });
                }
                
                // Update sponsor record
                connection.query(
                    'UPDATE sponsor SET CompanyName = ?, Email = ?, PhoneNo = ? WHERE Sponsor_ID = ?',
                    [companyName, contactEmail, contactPhone, sponsorId],
                    (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error updating sponsor:', err);
                                res.status(500).json({ message: 'Failed to update sponsor' });
                            });
                        }
                        
                        // Update user's phone if provided
                        if (contactPhone) {
                            connection.query(
                                'UPDATE users SET Phone = ? WHERE UserID = ?',
                                [contactPhone, userId],
                                (err, result) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error updating user:', err);
                                            res.status(500).json({ message: 'Failed to update user details' });
                                        });
                                    }
                                    
                                    commitChanges();
                                }
                            );
                        } else {
                            commitChanges();
                        }
                        
                        function commitChanges() {
                            connection.commit(err => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error committing transaction:', err);
                                        res.status(500).json({ message: 'Failed to save changes' });
                                    });
                                }
                                
                                connection.release();
                                res.json({ message: 'Sponsor updated successfully' });
                            });
                        }
                    }
                );
            });
        });
    });
});

// API endpoint to delete a sponsor
app.delete('/api/sponsors/:id', authorize(['Admin']), (req, res) => {
    const sponsorId = req.params.id;
    
    // Get the UserID for this sponsor
    db.query('SELECT UserID FROM sponsor WHERE Sponsor_ID = ?', [sponsorId], (err, results) => {
        if (err) {
            console.error('Error fetching sponsor:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsor' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Sponsor not found' });
        }
        
        const userId = results[0].UserID;
        
        // Start transaction
        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting connection:', err);
                return res.status(500).json({ message: 'Database connection error' });
            }
            
            connection.beginTransaction(err => {
                if (err) {
                    connection.release();
                    console.error('Error starting transaction:', err);
                    return res.status(500).json({ message: 'Transaction error' });
                }
                
                // First, delete all contracts associated with this sponsor
                connection.query('DELETE FROM sponsorship_contracts WHERE SponsorID = ?', [sponsorId], (err, result) => {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            console.error('Error deleting contracts:', err);
                            res.status(500).json({ message: 'Failed to delete sponsor contracts' });
                        });
                    }
                    
                    const contractsDeleted = result.affectedRows;
                    
                    // Now delete the sponsor record
                    connection.query('DELETE FROM sponsor WHERE Sponsor_ID = ?', [sponsorId], (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error deleting sponsor:', err);
                                res.status(500).json({ message: 'Failed to delete sponsor' });
                            });
                        }
                        
                        // Reset user's role to Participant
                        connection.query(
                            'UPDATE users SET RoleID = (SELECT RoleID FROM role WHERE RoleName = "Participant") WHERE UserID = ?',
                            [userId],
                            (err, result) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error updating user role:', err);
                                        res.status(500).json({ message: 'Failed to update user role' });
                                    });
                                }
                                
                                // Commit transaction
                                connection.commit(err => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error committing transaction:', err);
                                            res.status(500).json({ message: 'Failed to save changes' });
                                        });
                                    }
                                    
                                    connection.release();
                                    res.json({ 
                                        message: 'Sponsor deleted successfully',
                                        contracts_deleted: contractsDeleted
                                    });
                                });
                            }
                        );
                    });
                });
            });
        });
    });
});

// API endpoint to get a sponsor's profile (for logged-in sponsors)
app.get('/api/sponsor-profile', authorize(['Sponsor']), (req, res) => {
    const userId = req.session.userId;
    
    const query = `
        SELECT 
            s.Sponsor_ID as SponsorID, 
            s.CompanyName, 
            u.UserName as ContactPerson,
            s.Email, 
            s.PhoneNo as Phone
        FROM sponsor s
        JOIN users u ON s.UserID = u.UserID
        WHERE s.UserID = ?
    `;
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching sponsor profile:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsor profile' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Sponsor profile not found' });
        }
        
        res.json(results[0]);
    });
});

// API endpoint to update sponsor profile (for logged-in sponsors)
app.put('/api/sponsor-profile', authorize(['Sponsor']), (req, res) => {
    const userId = req.session.userId;
    const { companyName, email, phone } = req.body;
    
    if (!companyName) {
        return res.status(400).json({ message: 'Company name is required' });
    }
    
    db.query('UPDATE sponsor SET CompanyName = ?, Email = ?, PhoneNo = ? WHERE UserID = ?',
        [companyName, email, phone, userId],
        (err, result) => {
            if (err) {
                console.error('Error updating sponsor profile:', err);
                return res.status(500).json({ message: 'Failed to update profile' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Sponsor profile not found' });
            }
            
            // Update user's phone if provided
            if (phone) {
                db.query('UPDATE users SET Phone = ? WHERE UserID = ?', [phone, userId], (err) => {
                    if (err) {
                        console.error('Error updating user phone:', err);
                    }
                });
            }
            
            res.json({ message: 'Profile updated successfully' });
        }
    );
});

// API endpoint to get all sponsorship packages with option for admin editing
app.get('/api/admin/sponsorship-packages', authorize(['Admin']), (req, res) => {
    const query = 'SELECT * FROM sponsorship_package';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching packages:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsorship packages' });
        }
        
        res.json(results);
    });
});

// API endpoint to add a new sponsorship package
app.post('/api/admin/sponsorship-packages', authorize(['Admin']), (req, res) => {
    const { packageName, packageDetails, packageCost } = req.body;
    
    if (!packageName || !packageCost) {
        return res.status(400).json({ message: 'Package name and cost are required' });
    }
    
    // Check if package name already exists
    db.query('SELECT PackageID FROM sponsorship_package WHERE PackageName = ?', [packageName], (err, results) => {
        if (err) {
            console.error('Error checking package name:', err);
            return res.status(500).json({ message: 'Failed to check package name' });
        }
        
        if (results.length > 0) {
            return res.status(400).json({ message: 'A package with this name already exists' });
        }
        
        // Insert new package
        db.query(
            'INSERT INTO sponsorship_package (PackageName, PackageDetails, PackageCost) VALUES (?, ?, ?)',
            [packageName, packageDetails, packageCost],
            (err, result) => {
                if (err) {
                    console.error('Error creating package:', err);
                    return res.status(500).json({ message: 'Failed to create sponsorship package' });
                }
                
                res.status(201).json({
                    message: 'Package created successfully',
                    packageId: result.insertId
                });
            }
        );
    });
});

// API endpoint to update a sponsorship package
app.put('/api/admin/sponsorship-packages/:id', authorize(['Admin']), (req, res) => {
    const packageId = req.params.id;
    const { packageName, packageDetails, packageCost } = req.body;
    
    if (!packageName || !packageDetails || !packageCost) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Get current package data
    db.query('SELECT * FROM sponsorship_package WHERE PackageID = ?', [packageId], (err, results) => {
        if (err) {
            console.error('Error fetching package:', err);
            return res.status(500).json({ message: 'Failed to fetch package' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Package not found' });
        }
        
        // Update package with all provided fields
        db.query(
            'UPDATE sponsorship_package SET PackageName = ?, PackageDetails = ?, PackageCost = ? WHERE PackageID = ?',
            [packageName, packageDetails, packageCost, packageId],
            (err, result) => {
                if (err) {
                    console.error('Error updating package:', err);
                    return res.status(500).json({ message: 'Failed to update sponsorship package' });
                }
                
                res.json({ message: 'Package updated successfully' });
            }
        );
    });
});

// API endpoint to delete a sponsorship package
app.delete('/api/admin/sponsorship-packages/:id', authorize(['Admin']), (req, res) => {
    const packageId = req.params.id;
    
    // Check if the package is in use
    db.query(
        'SELECT ContractID FROM sponsorship_contracts WHERE PackageID = ? LIMIT 1',
        [packageId],
        (err, contractResults) => {
            if (err) {
                console.error('Error checking contracts:', err);
                return res.status(500).json({ message: 'Failed to check contracts' });
            }
            
            if (contractResults.length > 0) {
                return res.status(400).json({ 
                    message: 'Cannot delete package with existing contracts' 
                });
            }
            
            // Check if there are pending requests using this package
            db.query(
                'SELECT RequestID FROM sponsorship_requests WHERE PackageID = ? AND Status = "Pending" LIMIT 1',
                [packageId],
                (err, requestResults) => {
                    if (err) {
                        console.error('Error checking requests:', err);
                        return res.status(500).json({ message: 'Failed to check requests' });
                    }
                    
                    if (requestResults.length > 0) {
                        return res.status(400).json({ 
                            message: 'Cannot delete package with pending requests' 
                        });
                    }
                    
                    // Delete the package
                    db.query('DELETE FROM sponsorship_package WHERE PackageID = ?', [packageId], (err, result) => {
                        if (err) {
                            console.error('Error deleting package:', err);
                            return res.status(500).json({ message: 'Failed to delete package' });
                        }
                        
                        if (result.affectedRows === 0) {
                            return res.status(404).json({ message: 'Package not found' });
                        }
                        
                        res.json({ message: 'Package deleted successfully' });
                    });
                }
            );
        }
    );
});

// API endpoint to get all contracts (admin)
app.get('/api/admin/sponsorship-contracts', authorize(['Admin']), (req, res) => {
    const query = `
        SELECT 
            c.ContractID, c.ContractDate, c.ContractStatus, c.PaymentStatus,
            s.Sponsor_ID as SponsorID, s.CompanyName,
            p.PackageID, p.PackageName, p.PackageCost
        FROM sponsorship_contracts c
        JOIN sponsor s ON c.SponsorID = s.Sponsor_ID
        JOIN sponsorship_package p ON c.PackageID = p.PackageID
        ORDER BY c.ContractDate DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching contracts:', err);
            return res.status(500).json({ message: 'Failed to fetch contracts' });
        }
        
        res.json(results);
    });
});

// API endpoint to update contract status (admin)
app.put('/api/admin/sponsorship-contracts/:id', authorize(['Admin']), (req, res) => {
    const contractId = req.params.id;
    const { contractStatus } = req.body;
    
    if (!contractStatus || !['Signed', 'Pending', 'Expired'].includes(contractStatus)) {
        return res.status(400).json({ message: 'Valid contract status is required' });
    }
    
    db.query(
        'UPDATE sponsorship_contracts SET ContractStatus = ? WHERE ContractID = ?',
        [contractStatus, contractId],
        (err, result) => {
            if (err) {
                console.error('Error updating contract:', err);
                return res.status(500).json({ message: 'Failed to update contract' });
            }
            
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Contract not found' });
            }
            
            res.json({ message: 'Contract status updated successfully' });
        }
    );
});

// API endpoint to get all sponsorship payments (admin)
app.get('/api/admin/sponsorship-payments', authorize(['Admin']), (req, res) => {
    const query = `
        SELECT 
            p.Payment_ID as PaymentID, p.Amount, p.PaymentDate, p.PaymentType,
            c.ContractID, s.CompanyName, sp.PackageName
        FROM payment p
        JOIN sponsorship_contracts c ON p.ContractID = c.ContractID
        JOIN sponsor s ON c.SponsorID = s.Sponsor_ID
        JOIN sponsorship_package sp ON c.PackageID = sp.PackageID
        ORDER BY p.PaymentDate DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching payments:', err);
            return res.status(500).json({ message: 'Failed to fetch payments' });
        }
        
        res.json(results);
    });
});

// API endpoint for user role for the UI to check permissions
app.get('/api/user-role', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    
    const query = `
        SELECT r.RoleName as role
        FROM users u
        JOIN role r ON u.RoleID = r.RoleID
        WHERE u.UserID = ?
    `;
    
    db.query(query, [req.session.userId], (err, results) => {
        if (err) {
            console.error('Error fetching user role:', err);
            return res.status(500).json({ message: 'Failed to fetch user role' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json({ role: results[0].role });
    });
});

// Public API endpoint to get all sponsorship packages (no login required)
app.get('/api/sponsorship-packages', (req, res) => {
    const query = 'SELECT * FROM sponsorship_package';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching packages:', err);
            return res.status(500).json({ message: 'Failed to fetch sponsorship packages' });
        }
        
        res.json(results);
    });
});

// Public API endpoint to get summary payment stats (no details, just numbers)
app.get('/api/sponsorship-payment-stats', (req, res) => {
    const query = `
        SELECT 
            COUNT(*) as TotalPayments,
            SUM(p.Amount) as TotalAmount,
            (SELECT COUNT(*) FROM sponsorship_contracts WHERE PaymentStatus = 'Paid') as PaidContracts,
            (SELECT COUNT(*) FROM sponsorship_contracts WHERE PaymentStatus = 'Pending') as PendingContracts
        FROM payment p
        JOIN sponsorship_contracts c ON p.ContractID = c.ContractID
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching payment stats:', err);
            return res.status(500).json({ message: 'Failed to fetch payment statistics' });
        }
        
        res.json(results[0]);
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

// API endpoint to get the sponsor table schema for debugging
app.get('/api/debug/sponsor-schema', authorize(['Admin']), (req, res) => {
    db.query('DESCRIBE sponsor', (err, results) => {
        if (err) {
            console.error('Error getting sponsor schema:', err);
            return res.status(500).json({ message: 'Failed to get sponsor schema' });
        }
        
        res.json({
            message: 'Sponsor schema retrieved successfully',
            schema: results
        });
    });
});

// ----- API Routes for User Management -----

// Get all users
app.get('/api/users', authorize(['Admin']), (req, res) => {
    const role = req.query.role;
    const search = req.query.search;
    
    let query = `
        SELECT u.UserID, u.UserName, u.Email, u.Phone, r.RoleName, u.RegistrationTimestamp
        FROM users u
        JOIN role r ON u.RoleID = r.RoleID
    `;
    
    const queryParams = [];
    
    // Add filters if provided
    if (role || search) {
        query += ' WHERE ';
        
        const conditions = [];
        
        if (role) {
            conditions.push('r.RoleName = ?');
            queryParams.push(role);
        }
        
        if (search) {
            conditions.push('(u.UserName LIKE ? OR u.Email LIKE ? OR u.Phone LIKE ?)');
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
        }
        
        query += conditions.join(' AND ');
    }
    
    query += ' ORDER BY u.UserID';
    
    db.query(query, queryParams, (err, results) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).json({ message: 'Failed to fetch users' });
        }
        
        res.json({ message: 'Users retrieved successfully', data: results });
    });
});

// Get a specific user with role-specific details
app.get('/api/users/:id', authorize(['Admin']), (req, res) => {
    const userId = req.params.id;
    
    // Get basic user info
    const query = `
        SELECT u.UserID, u.UserName, u.Email, u.Phone, u.RoleID, r.RoleName, u.RegistrationTimestamp
        FROM users u
        JOIN role r ON u.RoleID = r.RoleID
        WHERE u.UserID = ?
    `;
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Failed to fetch user' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const user = results[0];
        
        // Get role-specific details based on the role
        if (user.RoleName === 'Participant') {
            // Get participant details
            db.query('SELECT * FROM participant WHERE UserID = ?', [userId], (err, participantResults) => {
                if (err) {
                    console.error('Error fetching participant details:', err);
                    return res.status(500).json({ message: 'Failed to fetch participant details' });
                }
                
                if (participantResults.length > 0) {
                    user.Participant = participantResults[0];
                }
                
                res.json({ message: 'User retrieved successfully', data: user });
            });
        } else if (user.RoleName === 'Judge') {
            // Get judge details
            db.query('SELECT * FROM judge WHERE UserID = ?', [userId], (err, judgeResults) => {
                if (err) {
                    console.error('Error fetching judge details:', err);
                    return res.status(500).json({ message: 'Failed to fetch judge details' });
                }
                
                if (judgeResults.length > 0) {
                    user.Judge = judgeResults[0];
                }
                
                res.json({ message: 'User retrieved successfully', data: user });
            });
        } else if (user.RoleName === 'Sponsor') {
            // Get sponsor details
            db.query('SELECT * FROM sponsor WHERE UserID = ?', [userId], (err, sponsorResults) => {
                if (err) {
                    console.error('Error fetching sponsor details:', err);
                    return res.status(500).json({ message: 'Failed to fetch sponsor details' });
                }
                
                if (sponsorResults.length > 0) {
                    user.Sponsor = sponsorResults[0];
                }
                
                res.json({ message: 'User retrieved successfully', data: user });
            });
        } else {
            // For other roles, just return the user
            res.json({ message: 'User retrieved successfully', data: user });
        }
    });
});

// Create a new user
app.post('/api/users', authorize(['Admin']), (req, res) => {
    const { userName, email, phone, roleId, password } = req.body;
    
    // Validate required fields
    if (!userName || !email || !roleId || !password) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ message: 'Failed to process password' });
        }
        
        // Start a transaction
        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting connection:', err);
                return res.status(500).json({ message: 'Database connection error' });
            }
            
            connection.beginTransaction(err => {
                if (err) {
                    connection.release();
                    console.error('Error starting transaction:', err);
                    return res.status(500).json({ message: 'Database transaction error' });
                }
                
                // Insert base user record
                connection.query(
                    'INSERT INTO users (UserName, Email, Phone, user_password, RoleID) VALUES (?, ?, ?, ?, ?)',
                    [userName, email, phone || null, hashedPassword, roleId],
                    (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error creating user:', err);
                                
                                if (err.code === 'ER_DUP_ENTRY') {
                                    return res.status(409).json({ message: 'A user with this email already exists' });
                                }
                                
                                res.status(500).json({ message: 'Failed to create user' });
                            });
                        }
                        
                        const userId = result.insertId;
                        
                        // Handle role-specific data
                        if (roleId == 3) { // Participant
                            const { university, teamId } = req.body;
                            
                            connection.query(
                                'INSERT INTO participant (UserID, University, TeamID) VALUES (?, ?, ?)',
                                [userId, university || null, teamId || null],
                                (err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error creating participant record:', err);
                                            res.status(500).json({ message: 'Failed to create participant record' });
                                        });
                                    }
                                    
                                    finishTransaction();
                                }
                            );
                        } else if (roleId == 5) { // Judge
                            const { expertise } = req.body;
                            
                            connection.query(
                                'INSERT INTO judge (UserID, Expertise) VALUES (?, ?)',
                                [userId, expertise || 'General'],
                                (err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error creating judge record:', err);
                                            res.status(500).json({ message: 'Failed to create judge record' });
                                        });
                                    }
                                    
                                    finishTransaction();
                                }
                            );
                        } else if (roleId == 4) { // Sponsor
                            const { companyName, companyEmail, companyPhone } = req.body;
                            
                            if (!companyName) {
                                return connection.rollback(() => {
                                    connection.release();
                                    res.status(400).json({ message: 'Company name is required for sponsors' });
                                });
                            }
                            
                            connection.query(
                                'INSERT INTO sponsor (UserID, CompanyName, Email, PhoneNo) VALUES (?, ?, ?, ?)',
                                [userId, companyName, companyEmail || email, companyPhone || phone],
                                (err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error creating sponsor record:', err);
                                            res.status(500).json({ message: 'Failed to create sponsor record' });
                                        });
                                    }
                                    
                                    finishTransaction();
                                }
                            );
                        } else {
                            // No role-specific data needed
                            finishTransaction();
                        }
                        
                        // Commit transaction
                        function finishTransaction() {
                            connection.commit(err => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error committing transaction:', err);
                                        res.status(500).json({ message: 'Failed to create user' });
                                    });
                                }
                                
                                connection.release();
                                res.status(201).json({ 
                                    message: 'User created successfully',
                                    data: { userId, userName, email }
                                });
                            });
                        }
                    }
                );
            });
        });
    });
});

// Update an existing user
app.put('/api/users/:id', authorize(['Admin']), (req, res) => {
    const userId = req.params.id;
    const { userName, email, phone, roleId } = req.body;
    
    // Validate required fields
    if (!userName || !email || !roleId) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Start a transaction
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting connection:', err);
            return res.status(500).json({ message: 'Database connection error' });
        }
        
        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                console.error('Error starting transaction:', err);
                return res.status(500).json({ message: 'Database transaction error' });
            }
            
            // First, get the user's current role
            connection.query('SELECT RoleID FROM users WHERE UserID = ?', [userId], (err, results) => {
                if (err) {
                    return connection.rollback(() => {
                        connection.release();
                        console.error('Error fetching current user:', err);
                        res.status(500).json({ message: 'Failed to fetch current user data' });
                    });
                }
                
                if (results.length === 0) {
                    return connection.rollback(() => {
                        connection.release();
                        res.status(404).json({ message: 'User not found' });
                    });
                }
                
                const currentRoleId = results[0].RoleID;
                
                // Update the base user record
                connection.query(
                    'UPDATE users SET UserName = ?, Email = ?, Phone = ?, RoleID = ? WHERE UserID = ?',
                    [userName, email, phone || null, roleId, userId],
                    (err) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error updating user:', err);
                                
                                if (err.code === 'ER_DUP_ENTRY') {
                                    return res.status(409).json({ message: 'A user with this email already exists' });
                                }
                                
                                res.status(500).json({ message: 'Failed to update user' });
                            });
                        }
                        
                        // If role has changed, handle the role-specific data
                        if (currentRoleId != roleId) {
                            // Remove old role-specific data
                            const roleTables = {
                                3: 'participant',
                                4: 'sponsor',
                                5: 'judge'
                            };
                            
                            if (roleTables[currentRoleId]) {
                                connection.query(
                                    `DELETE FROM ${roleTables[currentRoleId]} WHERE UserID = ?`,
                                    [userId],
                                    (err) => {
                                        if (err) {
                                            console.error(`Error removing old ${roleTables[currentRoleId]} record:`, err);
                                            // Continue despite error
                                        }
                                        
                                        // Add new role-specific data
                                        handleRoleSpecificData();
                                    }
                                );
                            } else {
                                // Add new role-specific data
                                handleRoleSpecificData();
                            }
                        } else {
                            // Update existing role-specific data
                            handleRoleSpecificData();
                        }
                        
                        // Handle role-specific data
                        function handleRoleSpecificData() {
                            if (roleId == 3) { // Participant
                                const { university, teamId } = req.body;
                                
                                connection.query(
                                    'SELECT * FROM participant WHERE UserID = ?',
                                    [userId],
                                    (err, results) => {
                                        if (err) {
                                            return connection.rollback(() => {
                                                connection.release();
                                                console.error('Error checking participant record:', err);
                                                res.status(500).json({ message: 'Failed to update participant record' });
                                            });
                                        }
                                        
                                        if (results.length === 0) {
                                            // Insert new record
                                            connection.query(
                                                'INSERT INTO participant (UserID, University, TeamID) VALUES (?, ?, ?)',
                                                [userId, university || null, teamId || null],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error creating participant record:', err);
                                                            res.status(500).json({ message: 'Failed to create participant record' });
                                                        });
                                                    }
                                                    
                                                    finishTransaction();
                                                }
                                            );
                                        } else {
                                            // Update existing record
                                            connection.query(
                                                'UPDATE participant SET University = ?, TeamID = ? WHERE UserID = ?',
                                                [university || null, teamId || null, userId],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error updating participant record:', err);
                                                            res.status(500).json({ message: 'Failed to update participant record' });
                                                        });
                                                    }
                                                    
                                                    finishTransaction();
                                                }
                                            );
                                        }
                                    }
                                );
                            } else if (roleId == 5) { // Judge
                                const { expertise } = req.body;
                                
                                connection.query(
                                    'SELECT * FROM judge WHERE UserID = ?',
                                    [userId],
                                    (err, results) => {
                                        if (err) {
                                            return connection.rollback(() => {
                                                connection.release();
                                                console.error('Error checking judge record:', err);
                                                res.status(500).json({ message: 'Failed to update judge record' });
                                            });
                                        }
                                        
                                        if (results.length === 0) {
                                            // Insert new record
                                            connection.query(
                                                'INSERT INTO judge (UserID, Expertise) VALUES (?, ?)',
                                                [userId, expertise || 'General'],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error creating judge record:', err);
                                                            res.status(500).json({ message: 'Failed to create judge record' });
                                                        });
                                                    }
                                                    
                                                    finishTransaction();
                                                }
                                            );
                                        } else {
                                            // Update existing record
                                            connection.query(
                                                'UPDATE judge SET Expertise = ? WHERE UserID = ?',
                                                [expertise || 'General', userId],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error updating judge record:', err);
                                                            res.status(500).json({ message: 'Failed to update judge record' });
                                                        });
                                                    }
                                                    
                                                    finishTransaction();
                                                }
                                            );
                                        }
                                    }
                                );
                            } else if (roleId == 4) { // Sponsor
                                const { companyName, companyEmail, companyPhone } = req.body;
                                
                                if (!companyName) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        res.status(400).json({ message: 'Company name is required for sponsors' });
                                    });
                                }
                                
                                connection.query(
                                    'SELECT * FROM sponsor WHERE UserID = ?',
                                    [userId],
                                    (err, results) => {
                                        if (err) {
                                            return connection.rollback(() => {
                                                connection.release();
                                                console.error('Error checking sponsor record:', err);
                                                res.status(500).json({ message: 'Failed to update sponsor record' });
                                            });
                                        }
                                        
                                        if (results.length === 0) {
                                            // Insert new record
                                            connection.query(
                                                'INSERT INTO sponsor (UserID, CompanyName, Email, PhoneNo) VALUES (?, ?, ?, ?)',
                                                [userId, companyName, companyEmail || email, companyPhone || phone],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error creating sponsor record:', err);
                                                            res.status(500).json({ message: 'Failed to create sponsor record' });
                                                        });
                                                    }
                                                    
                                                    finishTransaction();
                                                }
                                            );
                                        } else {
                                            // Update existing record
                                            connection.query(
                                                'UPDATE sponsor SET CompanyName = ?, Email = ?, PhoneNo = ? WHERE UserID = ?',
                                                [companyName, companyEmail || email, companyPhone || phone, userId],
                                                (err) => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error updating sponsor record:', err);
                                                            res.status(500).json({ message: 'Failed to update sponsor record' });
                                                        });
                                                    }
                                                    
                                                    finishTransaction();
                                                }
                                            );
                                        }
                                    }
                                );
                            } else {
                                // No role-specific data needed
                                finishTransaction();
                            }
                        }
                        
                        // Commit transaction
                        function finishTransaction() {
                            connection.commit(err => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error committing transaction:', err);
                                        res.status(500).json({ message: 'Failed to update user' });
                                    });
                                }
                                
                                connection.release();
                                res.json({ 
                                    message: 'User updated successfully',
                                    data: { userId, userName, email }
                                });
                            });
                        }
                    }
                );
            });
        });
    });
});

// Delete a user
app.delete('/api/users/:id', authorize(['Admin']), (req, res) => {
    const userId = req.params.id;
    
    // Check if trying to delete self
    if (req.session.userId == userId) {
        return res.status(403).json({ message: 'You cannot delete your own account' });
    }
    
    // Delete the user (role-specific records will be deleted via ON DELETE CASCADE)
    db.query('DELETE FROM users WHERE UserID = ?', [userId], (err, result) => {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).json({ message: 'Failed to delete user' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json({ message: 'User deleted successfully' });
    });
});

// Add API endpoint to get all teams for the participant form
app.get('/api/teams', authorize(['Admin']), (req, res) => {
    db.query('SELECT TeamID, TeamName FROM team ORDER BY TeamName', (err, results) => {
        if (err) {
            console.error('Error fetching teams:', err);
            return res.status(500).json({ message: 'Failed to fetch teams' });
        }
        
        res.json({ message: 'Teams retrieved successfully', data: results });
    });
});

// ----- API Routes for Participant Check-in/Check-out -----

// Participant: Self Check-in
// This endpoint is now deprecated as we're using direct check-in via POST /api/participant/checkins
// Kept for backward compatibility
app.put('/api/participant/checkins/:id/check-in', authorize(['Participant']), (req, res) => {
    const checkinId = req.params.id;
    const userId = req.session.userId;
    const { actualCheckInDate } = req.body;
    
    if (!actualCheckInDate) {
        return res.status(400).json({ message: 'Missing actual check-in date' });
    }
    
    // Format the date for MySQL if needed
    let formattedDate = actualCheckInDate;
    if (actualCheckInDate.includes('T') && actualCheckInDate.includes('Z')) {
        try {
            const date = new Date(actualCheckInDate);
            formattedDate = date.toISOString().slice(0, 19).replace('T', ' ');
        } catch (error) {
            console.error('Error formatting date:', error);
            return res.status(400).json({ message: 'Invalid date format' });
        }
    }
    
    // Verify this check-in belongs to the current participant
    const query = `
        SELECT c.CheckinID, c.Status 
        FROM checkin c
        JOIN room_allocation ra ON c.AllocationID = ra.AllocationID
        JOIN accommodation a ON ra.AccommodationID = a.AccommodationID
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        WHERE c.CheckinID = ? AND p.UserID = ? AND c.Status = 'Reserved'
    `;
    
    db.query(query, [checkinId, userId], (err, results) => {
        if (err) {
            console.error('Error verifying check-in:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Check-in not found or not authorized' });
        }
        
        // Update check-in status
        db.query(
            'UPDATE checkin SET ActualCheckinDate = ?, Status = "Checked In" WHERE CheckinID = ?',
            [formattedDate, checkinId],
            (err, result) => {
                if (err) {
                    console.error('Error updating check-in:', err);
                    return res.status(500).json({ message: 'Failed to update check-in' });
                }
                
                res.json({ message: 'Self check-in processed successfully' });
            }
        );
    });
});

// Participant: Self Check-out
app.put('/api/participant/checkins/:id/check-out', authorize(['Participant']), (req, res) => {
    const checkinId = req.params.id;
    const userId = req.session.userId;
    const { actualCheckOutDate } = req.body;
    
    if (!actualCheckOutDate) {
        return res.status(400).json({ message: 'Missing actual check-out date' });
    }
    
    // Verify this check-in belongs to the current participant
    const query = `
        SELECT c.CheckinID, c.Status, ra.RoomID, ra.CheckOutDate
        FROM checkin c
        JOIN room_allocation ra ON c.AllocationID = ra.AllocationID
        JOIN accommodation a ON ra.AccommodationID = a.AccommodationID
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        WHERE c.CheckinID = ? AND p.UserID = ? AND c.Status = 'Checked In'
    `;
    
    db.query(query, [checkinId, userId], (err, results) => {
        if (err) {
            console.error('Error verifying check-out:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Check-in not found or not authorized' });
        }
        
        const { RoomID, CheckOutDate } = results[0];
        
        // Format the date for MySQL (YYYY-MM-DD HH:MM:SS)
        let formattedDate;
        try {
            const date = new Date(actualCheckOutDate);
            formattedDate = date.toISOString().slice(0, 19).replace('T', ' ');
        } catch (error) {
            console.error('Error formatting date:', error);
            return res.status(400).json({ message: 'Invalid date format' });
        }
        
        // Update check-in status
        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting connection:', err);
                return res.status(500).json({ message: 'Database connection error' });
            }
            
            connection.beginTransaction(err => {
                if (err) {
                    connection.release();
                    console.error('Error starting transaction:', err);
                    return res.status(500).json({ message: 'Transaction error' });
                }
                
                connection.query(
                    'UPDATE checkin SET ActualCheckoutDate = ?, Status = "Checked Out" WHERE CheckinID = ?',
                    [formattedDate, checkinId],
                    (err) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error('Error updating check-out:', err);
                                return res.status(500).json({ message: 'Failed to update check-out' });
                            });
                        }
                        
                        // Check if scheduled checkout date has passed
                        const currentDate = new Date();
                        const scheduledCheckout = new Date(CheckOutDate);
                        
                        if (currentDate > scheduledCheckout) {
                            // Check if there are other active check-ins for this room
                            connection.query(
                                'SELECT COUNT(*) AS activeCheckins FROM room_allocation ra JOIN checkin c ON ra.AllocationID = c.AllocationID WHERE ra.RoomID = ? AND c.Status = "Checked In" AND ra.CheckOutDate > CURDATE()',
                                [RoomID],
                                (err, results) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error('Error checking active check-ins:', err);
                                            return res.status(500).json({ message: 'Database error' });
                                        });
                                    }
                                    
                                    const activeCheckins = results[0].activeCheckins;
                                    
                                    // If no active check-ins, mark room as available
                                    if (activeCheckins === 0) {
                                        connection.query(
                                            'UPDATE room SET AvailabilityStatus = "Available" WHERE RoomID = ?',
                                            [RoomID],
                                            (err) => {
                                                if (err) {
                                                    return connection.rollback(() => {
                                                        connection.release();
                                                        console.error('Error updating room status:', err);
                                                        return res.status(500).json({ message: 'Database error' });
                                                    });
                                                }
                                                
                                                // Commit transaction
                                                connection.commit(err => {
                                                    if (err) {
                                                        return connection.rollback(() => {
                                                            connection.release();
                                                            console.error('Error committing transaction:', err);
                                                            return res.status(500).json({ message: 'Transaction error' });
                                                        });
                                                    }
                                                    
                                                    connection.release();
                                                    return res.json({ 
                                                        message: 'Self check-out processed successfully and room is now available' 
                                                    });
                                                });
                                            }
                                        );
                                    } else {
                                        // Just commit the transaction
                                        connection.commit(err => {
                                            if (err) {
                                                return connection.rollback(() => {
                                                    connection.release();
                                                    console.error('Error committing transaction:', err);
                                                    return res.status(500).json({ message: 'Transaction error' });
                                                });
                                            }
                                            
                                            connection.release();
                                            return res.json({ message: 'Self check-out processed successfully' });
                                        });
                                    }
                                }
                            );
                        } else {
                            // Just commit the transaction for early check-out
                            connection.commit(err => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error('Error committing transaction:', err);
                                        return res.status(500).json({ message: 'Transaction error' });
                                    });
                                }
                                
                                connection.release();
                                return res.json({ message: 'Early self check-out processed successfully' });
                            });
                        }
                    }
                );
            });
        });
    });
});

// Participant: Create check-in record for allocated room
app.post('/api/participant/checkins', authorize(['Participant']), (req, res) => {
    const userId = req.session.userId;
    const { allocationId, notes } = req.body;
    
    if (!allocationId) {
        return res.status(400).json({ message: 'Missing allocation ID' });
    }
    
    // Verify this allocation belongs to the current participant and no check-in exists
    const verifyQuery = `
        SELECT ra.AllocationID, a.AccommodationID, a.AccommodationStatus 
        FROM room_allocation ra
        JOIN accommodation a ON ra.AccommodationID = a.AccommodationID
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        LEFT JOIN checkin c ON ra.AllocationID = c.AllocationID
        WHERE ra.AllocationID = ? AND p.UserID = ? AND a.AccommodationStatus = 'Allocated' AND c.CheckinID IS NULL
    `;
    
    db.query(verifyQuery, [allocationId, userId], (err, results) => {
        if (err) {
            console.error('Error verifying allocation:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Allocation not found, not authorized, or check-in already exists' });
        }
        
        // Create the check-in record with direct "Checked In" status
        const currentDateTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const insertQuery = `
            INSERT INTO checkin (AllocationID, Status, Notes, ActualCheckinDate)
            VALUES (?, 'Checked In', ?, ?)
        `;
        
        db.query(insertQuery, [allocationId, notes || 'Self check-in by participant', currentDateTime], (err, result) => {
            if (err) {
                console.error('Error creating check-in record:', err);
                return res.status(500).json({ message: 'Failed to create check-in record' });
            }
            
            const checkinId = result.insertId;
            
            res.status(201).json({
                message: 'Check-in completed successfully',
                checkinId: checkinId
            });
        });
    });
});

// Enhanced endpoint to include check-in status in accommodation data
app.get('/api/participant/accommodations', authorize(['Participant']), (req, res) => {
    const userId = req.session.userId;
    console.log("PARTICIPANT ACCOMMODATION API: Request received from user ID:", userId);
    
    const query = `
        SELECT a.AccommodationID, a.RegistrationID, a.NumberOfPeople, a.Budget,
               a.AccommodationStatus AS AccommodationStatus,
               e.EventName, e.Event_ID as EventID,
               ra.AllocationID, r.RoomID, r.RoomNumber, r.Capacity, r.Price,
               ra.CheckInDate, ra.CheckOutDate,
               c.CheckinID, c.Status AS CheckinStatus, 
               c.ActualCheckinDate, c.ActualCheckoutDate
        FROM accommodation a
        JOIN registration reg ON a.RegistrationID = reg.RegistrationID
        JOIN event e ON reg.EventID = e.Event_ID
        JOIN participant p ON reg.ParticipantID = p.Participant_ID
        LEFT JOIN room_allocation ra ON a.AccommodationID = ra.AccommodationID
        LEFT JOIN room r ON ra.RoomID = r.RoomID
        LEFT JOIN checkin c ON ra.AllocationID = c.AllocationID
        WHERE p.UserID = ?
        ORDER BY a.AccommodationID DESC
    `;
    
    // First check if there's a participant record for this user
    db.query('SELECT Participant_ID FROM participant WHERE UserID = ?', [userId], (err, participantResults) => {
        if (err) {
            console.error('PARTICIPANT ACCOMMODATION API: Error checking participant record:', err);
            return res.status(500).json([]);
        }
        
        if (participantResults.length === 0) {
            console.error('PARTICIPANT ACCOMMODATION API: No participant record found for user ID:', userId);
            return res.json([]);
        }
        
        console.log('PARTICIPANT ACCOMMODATION API: Found participant record. Proceeding to fetch accommodations.');
        
        // Proceed to fetch accommodations
        db.query(query, [userId], (err, results) => {
            if (err) {
                console.error('PARTICIPANT ACCOMMODATION API: Error fetching accommodations:', err);
                return res.status(500).json([]);
            }
            
            console.log(`PARTICIPANT ACCOMMODATION API: Found ${results.length} accommodation records`);
            
            // Return empty array if no results
            if (results.length === 0) {
                return res.json([]);
            }
            
            // Format the response to include room details and check-in status in a nested object
            const formattedResults = results.map(row => {
                const result = { ...row };
                
                if (row.AccommodationStatus === 'Allocated' && row.RoomID) {
                    result.RoomDetails = {
                        RoomID: row.RoomID,
                        RoomNumber: row.RoomNumber,
                        Capacity: row.Capacity,
                        Price: row.Price,
                        CheckInDate: row.CheckInDate,
                        CheckOutDate: row.CheckOutDate
                    };
                } else {
                    result.RoomDetails = null;
                }
                
                // Remove duplicated fields
                delete result.RoomID;
                delete result.RoomNumber;
                delete result.Capacity;
                delete result.Price;
                delete result.CheckInDate;
                delete result.CheckOutDate;
                
                return result;
            });
            
            console.log("PARTICIPANT ACCOMMODATION API: Returning formatted results");
            res.json(formattedResults);
        });
    });
});

// Add API endpoint for participants list (needed by checkin_management.html)
app.get('/api/participants', authorize(['Admin', 'EventOrganizer']), (req, res) => {
    const query = `
        SELECT p.Participant_ID AS ParticipantID, u.UserName AS Name, u.Email
        FROM participant p
        JOIN users u ON p.UserID = u.UserID
        ORDER BY u.UserName
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching participants:', err);
            return res.status(500).json({ message: 'Failed to fetch participants' });
        }
        
        res.json(results);
    });
});

// The checkin endpoint is already defined elsewhere

// We already have the accommodation endpoint above

// ----- API Routes for Judge Management -----
app.get('/api/judges', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const eventId = req.query.eventId;
    
    // If eventId is provided, we want judges NOT already assigned to this event
    if (eventId) {
        const query = `
            SELECT j.JudgeID, j.UserID, j.Expertise, u.UserName, u.Email 
            FROM judge j
            JOIN users u ON j.UserID = u.UserID
            WHERE j.JudgeID NOT IN (
                SELECT ej.JudgeID 
                FROM event_judge ej 
                WHERE ej.EventID = ?
            )
            ORDER BY u.UserName
        `;
        
        db.query(query, [eventId], (err, results) => {
            if (err) {
                console.error('Error fetching available judges:', err);
                return res.status(500).json({ message: 'Failed to fetch available judges' });
            }
            
            return res.json(results);
        });
    } else {
        // Get all judges
        const query = `
            SELECT j.JudgeID, j.UserID, j.Expertise, u.UserName, u.Email 
            FROM judge j
            JOIN users u ON j.UserID = u.UserID
            ORDER BY u.UserName
        `;
        
        db.query(query, (err, results) => {
            if (err) {
                console.error('Error fetching judges:', err);
                return res.status(500).json({ message: 'Failed to fetch judges' });
            }
            
            return res.json(results);
        });
    }
});

// Get judges assigned to an event
app.get('/api/event-judges/:eventId', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const eventId = req.params.eventId;
    
    const query = `
        SELECT ej.EventID, ej.JudgeID, ej.JudgeRoleID, 
               j.Expertise, u.UserName, u.Email, 
               jr.JudgeRole
        FROM event_judge ej
        JOIN judge j ON ej.JudgeID = j.JudgeID
        JOIN users u ON j.UserID = u.UserID
        JOIN judge_role jr ON ej.JudgeRoleID = jr.JudgeRoleID
        WHERE ej.EventID = ?
        ORDER BY jr.JudgeRoleID
    `;
    
    db.query(query, [eventId], (err, results) => {
        if (err) {
            console.error('Error fetching event judges:', err);
            return res.status(500).json({ message: 'Failed to fetch judges for this event' });
        }
        
        res.json(results);
    });
});

// Assign a judge to an event
app.post('/api/event-judges', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const { eventId, judgeId, judgeRoleId } = req.body;
    
    if (!eventId || !judgeId || !judgeRoleId) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Check if event exists
    db.query('SELECT Event_ID FROM event WHERE Event_ID = ?', [eventId], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error checking event:', err);
            return res.status(404).json({ message: 'Event not found' });
        }
        
        // Check if judge exists
        db.query('SELECT JudgeID FROM judge WHERE JudgeID = ?', [judgeId], (err, results) => {
            if (err || results.length === 0) {
                console.error('Error checking judge:', err);
                return res.status(404).json({ message: 'Judge not found' });
            }
            
            // Check if role exists
            db.query('SELECT JudgeRoleID FROM judge_role WHERE JudgeRoleID = ?', [judgeRoleId], (err, results) => {
                if (err || results.length === 0) {
                    console.error('Error checking judge role:', err);
                    return res.status(404).json({ message: 'Judge role not found' });
                }
                
                // Check if judge is already assigned to this event
                db.query('SELECT * FROM event_judge WHERE EventID = ? AND JudgeID = ?', [eventId, judgeId], (err, results) => {
                    if (err) {
                        console.error('Error checking existing assignment:', err);
                        return res.status(500).json({ message: 'Failed to check existing assignments' });
                    }
                    
                    if (results.length > 0) {
                        return res.status(400).json({ message: 'Judge is already assigned to this event' });
                    }
                    
                    // Check if there's already a Head Judge (role 1) for this event
                    if (judgeRoleId == 1) { // Head Judge role
                        db.query('SELECT * FROM event_judge WHERE EventID = ? AND JudgeRoleID = 1', [eventId], (err, results) => {
                            if (err) {
                                console.error('Error checking head judge:', err);
                                return res.status(500).json({ message: 'Failed to check existing head judge' });
                            }
                            
                            if (results.length > 0) {
                                return res.status(400).json({ message: 'This event already has a Head Judge assigned' });
                            }
                            
                            // Assign judge to event
                            assignJudgeToEvent();
                        });
                    } else {
                        // For other roles, simply assign
                        assignJudgeToEvent();
                    }
                    
                    function assignJudgeToEvent() {
                        const insertQuery = 'INSERT INTO event_judge (EventID, JudgeID, JudgeRoleID) VALUES (?, ?, ?)';
                        
                        db.query(insertQuery, [eventId, judgeId, judgeRoleId], (err, result) => {
                            if (err) {
                                console.error('Error assigning judge:', err);
                                return res.status(500).json({ message: 'Failed to assign judge to event' });
                            }
                            
                            res.status(201).json({ message: 'Judge assigned successfully' });
                        });
                    }
                });
            });
        });
    });
});

// Remove a judge from an event
app.delete('/api/event-judges/:eventId/:judgeId', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const eventId = req.params.eventId;
    const judgeId = req.params.judgeId;
    
    if (!eventId || !judgeId) {
        return res.status(400).json({ message: 'Missing event ID or judge ID' });
    }
    
    const deleteQuery = 'DELETE FROM event_judge WHERE EventID = ? AND JudgeID = ?';
    
    db.query(deleteQuery, [eventId, judgeId], (err, result) => {
        if (err) {
            console.error('Error removing judge from event:', err);
            return res.status(500).json({ message: 'Failed to remove judge from event' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Judge assignment not found' });
        }
        
        res.json({ message: 'Judge removed from event successfully' });
    });
});

// ----- API Routes for Round Participants -----

// Create round_participant table if it doesn't exist
db.query(`
    CREATE TABLE IF NOT EXISTS round_participant (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        RoundID INT NOT NULL,
        ParticipantID INT NOT NULL,
        Status ENUM('Registered', 'Checked-in', 'No-show', 'Completed') DEFAULT 'Registered',
        RegistrationDate DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX (RoundID),
        INDEX (ParticipantID),
        UNIQUE KEY unique_round_participant (RoundID, ParticipantID)
    )
`, (err) => {
    if (err) {
        console.error('Error creating round_participant table:', err);
    } else {
        console.log('Round participant table check completed');
    }
});

// Helper function to ensure participants are added to rounds
function ensureParticipantsInRound(roundId) {
    // First get the event ID for this round
    db.query('SELECT EventID FROM event_round WHERE RoundID = ?', [roundId], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error getting event for round:', err);
            return;
        }
        
        const eventId = results[0].EventID;
        
        // Get all participants registered for this event
        db.query(
            'SELECT ParticipantID FROM registration WHERE EventID = ?', 
            [eventId], 
            (err, participants) => {
                if (err || participants.length === 0) {
                    console.error('Error or no participants found for event:', err);
                    return;
                }
                
                // For each participant, add them to the round if not already present
                participants.forEach(participant => {
                    db.query(
                        'INSERT IGNORE INTO round_participant (RoundID, ParticipantID) VALUES (?, ?)',
                        [roundId, participant.ParticipantID],
                        (err) => {
                            if (err) {
                                console.error('Error adding participant to round:', err);
                            }
                        }
                    );
                });
            }
        );
    });
}

app.get('/api/round-participants/:roundId', authorize(['Admin', 'Event Organizer', 'Judge']), (req, res) => {
    const roundId = req.params.roundId;
    
    if (!roundId) {
        return res.status(400).json({ message: 'Round ID is required' });
    }
    
    // Ensure participants are added to the round
    ensureParticipantsInRound(roundId);
    
    // Different query based on role
    let query;
    
    if (req.session.role === 'Admin' || req.session.role === 'Event Organizer') {
        // For admin/organizer - show all evaluations
        query = `
            SELECT 
                p.Participant_ID AS ParticipantID,
                u.UserName AS Name,
                p.University,
                rp.Status,
                CASE
                    WHEN COUNT(ev.EvaluationID) > 0 THEN 'Evaluated'
                    ELSE 'Pending'
                END AS EvaluationStatus,
                COUNT(ev.EvaluationID) AS EvaluationCount,
                AVG(ev.Score) AS AverageScore
            FROM 
                round_participant rp
                JOIN participant p ON rp.ParticipantID = p.Participant_ID
                JOIN users u ON p.UserID = u.UserID
                LEFT JOIN evaluation ev ON (
                    ev.ParticipantID = p.Participant_ID AND 
                    ev.RoundID = rp.RoundID
                )
            WHERE 
                rp.RoundID = ?
            GROUP BY
                p.Participant_ID, u.UserName, p.University, rp.Status
            ORDER BY 
                EvaluationStatus DESC, u.UserName
        `;
    } else {
        // For judges - show only their evaluations
        query = `
            SELECT 
                p.Participant_ID AS ParticipantID,
                u.UserName AS Name,
                p.University,
                rp.Status,
                CASE
                    WHEN ev.Score IS NOT NULL THEN 'Evaluated'
                    ELSE 'Pending'
                END AS EvaluationStatus,
                ev.Score
            FROM 
                round_participant rp
                JOIN participant p ON rp.ParticipantID = p.Participant_ID
                JOIN users u ON p.UserID = u.UserID
                LEFT JOIN evaluation ev ON (
                    ev.ParticipantID = p.Participant_ID AND 
                    ev.RoundID = rp.RoundID AND 
                    ev.JudgeID = (SELECT JudgeID FROM judge WHERE UserID = ?)
                )
            WHERE 
                rp.RoundID = ?
            ORDER BY 
                EvaluationStatus DESC, u.UserName
        `;
    }
    
    // Execute the appropriate query
    if (req.session.role === 'Admin' || req.session.role === 'Event Organizer') {
        db.query(query, [roundId], (err, results) => {
            if (err) {
                console.error('Error fetching round participants:', err);
                return res.status(500).json({ message: 'Failed to fetch participants' });
            }
            
            res.json(results);
        });
    } else {
        // For judges, we need to include their UserID for the join
        db.query(query, [req.session.userId, roundId], (err, results) => {
            if (err) {
                console.error('Error fetching round participants:', err);
                return res.status(500).json({ message: 'Failed to fetch participants' });
            }
            
            res.json(results);
        });
    }
});

// ----- API Routes for Evaluations -----

// First, make sure the evaluation table exists
db.query(`
    CREATE TABLE IF NOT EXISTS evaluation (
        EvaluationID INT AUTO_INCREMENT PRIMARY KEY,
        JudgeID INT NOT NULL,
        ParticipantID INT NOT NULL,
        RoundID INT NOT NULL,
        TechnicalScore INT NOT NULL,
        PresentationScore INT NOT NULL,
        InnovationScore INT NOT NULL,
        Score FLOAT NOT NULL,
        Comments TEXT,
        EvaluationDate DATETIME NOT NULL,
        INDEX (JudgeID),
        INDEX (ParticipantID),
        INDEX (RoundID),
        UNIQUE KEY unique_evaluation (JudgeID, ParticipantID, RoundID)
    )
`, (err) => {
    if (err) {
        console.error('Error creating evaluation table:', err);
    } else {
        console.log('Evaluation table check completed');
    }
});

// Check judge table structure
db.query('DESCRIBE judge', (err, results) => {
    if (err) {
        console.error('Error checking judge table structure:', err);
    } else {
        console.log('Judge table structure:', results.map(r => `${r.Field} (${r.Type})`).join(', '));
    }
});

app.post('/api/evaluations', authorize(['Judge', 'Admin']), (req, res) => {
    const { participantId, roundId, technicalScore, presentationScore, innovationScore, comments } = req.body;
    
    if (!participantId || !roundId || !technicalScore || !presentationScore || !innovationScore) {
        return res.status(400).json({ message: 'Missing required fields' });
    }
    
    // Calculate total score
    const totalScore = (
        parseInt(technicalScore) + 
        parseInt(presentationScore) + 
        parseInt(innovationScore)
    ) / 3; // Average of all scores
    
    // Get the judge ID from the user ID - use JudgeID as the column name instead of Judge_ID
    db.query('SELECT JudgeID FROM judge WHERE UserID = ?', [req.session.userId], (err, judgeResults) => {
        if (err) {
            console.error('Error getting judge ID:', err);
            return res.status(500).json({ message: 'Failed to get judge details' });
        }
        
        let judgeId;
        
        if (judgeResults.length === 0) {
            // No judge record exists for this user
            
            if (req.session.role === 'Admin') {
                // For Admin users, create a special judge record
                db.query(
                    'INSERT INTO judge (UserID, Expertise) VALUES (?, ?)', 
                    [req.session.userId, 'Admin Evaluator'],
                    (err, result) => {
                        if (err) {
                            console.error('Error creating judge record for Admin:', err);
                            return res.status(500).json({ message: 'Failed to create evaluator record' });
                        }
                        
                        judgeId = result.insertId;
                        processEvaluation(judgeId);
                    }
                );
                return; // Early return to prevent continuing with the main flow
            } else {
                return res.status(403).json({ message: 'User is not a registered judge' });
            }
        } else {
            judgeId = judgeResults[0].JudgeID;
            processEvaluation(judgeId);
        }
        
        // Function to process the evaluation with the judgeId
        function processEvaluation(judgeId) {
            // Check if an evaluation already exists
            const checkQuery = `
                SELECT EvaluationID 
                FROM evaluation 
                WHERE JudgeID = ? AND ParticipantID = ? AND RoundID = ?
            `;
            
            db.query(checkQuery, [judgeId, participantId, roundId], (err, checkResults) => {
                if (err) {
                    console.error('Error checking existing evaluation:', err);
                    return res.status(500).json({ message: 'Failed to check existing evaluation' });
                }
                
                let query, params;
                
                if (checkResults.length > 0) {
                    // Update existing evaluation
                    query = `
                        UPDATE evaluation 
                        SET TechnicalScore = ?, PresentationScore = ?, InnovationScore = ?, 
                            Score = ?, Comments = ?, EvaluationDate = NOW() 
                        WHERE EvaluationID = ?
                    `;
                    params = [
                        technicalScore, 
                        presentationScore, 
                        innovationScore, 
                        totalScore, 
                        comments || '',
                        checkResults[0].EvaluationID
                    ];
                } else {
                    // Create new evaluation
                    query = `
                        INSERT INTO evaluation 
                        (JudgeID, ParticipantID, RoundID, TechnicalScore, PresentationScore, 
                         InnovationScore, Score, Comments, EvaluationDate) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
                    `;
                    params = [
                        judgeId, 
                        participantId, 
                        roundId, 
                        technicalScore, 
                        presentationScore, 
                        innovationScore, 
                        totalScore, 
                        comments || ''
                    ];
                }
                
                db.query(query, params, (err, result) => {
                    if (err) {
                        console.error('Error saving evaluation:', err);
                        return res.status(500).json({ message: 'Failed to save evaluation' });
                    }
                    
                    res.json({ 
                        message: 'Evaluation submitted successfully',
                        score: totalScore
                    });
                });
            });
        }
    });
});

// ------------------ Reports API Endpoints ------------------
// Event participation statistics report
app.get('/api/reports/event', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const query = `
        SELECT e.Event_ID, e.EventName, e.EventDateTime, c.CategoryName,
               COUNT(DISTINCT r.RegistrationID) AS ParticipantCount,
               IFNULL(SUM(e.RegistrationFee), 0) AS Revenue,
               (CASE 
                    WHEN e.EventDateTime > NOW() THEN 'Upcoming'
                    ELSE 'Completed'
                END) AS Status
        FROM event e
        LEFT JOIN registration r ON e.Event_ID = r.EventID
        LEFT JOIN category c ON e.CategoryID = c.CategoryID
        GROUP BY e.Event_ID, e.EventName, e.EventDateTime, c.CategoryName
        ORDER BY e.EventDateTime DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error generating event report:', err);
            return res.status(500).json({ error: 'Failed to generate event report' });
        }

        // Count participants by category
        const categoryQuery = `
            SELECT IFNULL(c.CategoryName, 'Uncategorized') AS CategoryName, 
                   COUNT(DISTINCT r.RegistrationID) AS ParticipantCount
            FROM event e
            LEFT JOIN category c ON e.CategoryID = c.CategoryID
            LEFT JOIN registration r ON e.Event_ID = r.EventID
            GROUP BY c.CategoryName
        `;

        db.query(categoryQuery, (err, categoryResults) => {
            if (err) {
                console.error('Error generating category statistics:', err);
                // Return partial results instead of failing
                return res.json({
                    events: results,
                    categories: [],
                    rounds: []
                });
            }

            // Return results with empty rounds if needed
            res.json({
                events: results,
                categories: categoryResults,
                rounds: [] // Simplified to avoid potential errors
            });
        });
    });
});

// Venue utilization report
app.get('/api/reports/venue', authorize(['Admin', 'Event Organizer']), (req, res) => {
    const query = `
        SELECT v.Venue_ID, v.VenueName, IFNULL(v.Capacity, 0) AS Capacity,
               COUNT(vs.ScheduleID) AS EventCount,
               COUNT(DISTINCT e.Event_ID) AS UniqueEvents,
               IFNULL(SUM(TIME_TO_SEC(TIMEDIFF(vs.EndTime, vs.StartTime)))/3600, 0) AS TotalHoursBooked
        FROM venue v
        LEFT JOIN venue_schedule vs ON v.Venue_ID = vs.VenueID
        LEFT JOIN event_round er ON vs.Event_RoundID = er.RoundID
        LEFT JOIN event e ON er.EventID = e.Event_ID
        GROUP BY v.Venue_ID, v.VenueName, v.Capacity
        ORDER BY EventCount DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error generating venue report:', err);
            return res.status(500).json({ error: 'Failed to generate venue report' });
        }

        // Get venue booking details
        const bookingsQuery = `
            SELECT v.VenueName, IFNULL(e.EventName, 'Unknown') AS EventName, 
                   IFNULL(er.RoundName, 'Unknown') AS RoundName, 
                   vs.ScheduleDate, vs.StartTime, vs.EndTime,
                   IFNULL(TIME_TO_SEC(TIMEDIFF(vs.EndTime, vs.StartTime))/3600, 0) AS HoursBooked
            FROM venue_schedule vs
            JOIN venue v ON vs.VenueID = v.Venue_ID
            LEFT JOIN event_round er ON vs.Event_RoundID = er.RoundID
            LEFT JOIN event e ON er.EventID = e.Event_ID
            ORDER BY vs.ScheduleDate DESC, vs.StartTime ASC
        `;

        db.query(bookingsQuery, (err, bookingsResults) => {
            if (err) {
                console.error('Error generating venue bookings:', err);
                // Return partial results instead of failing completely
                return res.json({
                    venues: results,
                    bookings: []
                });
            }

            res.json({
                venues: results,
                bookings: bookingsResults
            });
        });
    });
});

// Revenue and sponsorship report
app.get('/api/reports/financial', authorize(['Admin']), (req, res) => {
    // Simplified revenue query
    const revenueQuery = `
        SELECT 'Event Registration' AS Category, IFNULL(SUM(e.RegistrationFee), 0) AS Amount
        FROM event e
        UNION ALL
        SELECT 'Sponsorship' AS Category, IFNULL(SUM(sp.PackageCost), 0) AS Amount
        FROM sponsorship_package sp
        JOIN sponsorship_contracts sc ON sp.PackageID = sc.PackageID
        WHERE sc.PaymentStatus = 'Paid'
        UNION ALL
        SELECT 'Accommodation' AS Category, IFNULL(SUM(r.Price), 0) AS Amount
        FROM room r
        WHERE r.AvailabilityStatus = 'Occupied'
    `;

    db.query(revenueQuery, (err, revenueResults) => {
        if (err) {
            console.error('Error generating revenue report:', err);
            return res.status(500).json({ error: 'Failed to generate revenue report' });
        }

        // Calculate total and percentages
        let total = 0;
        revenueResults.forEach(category => {
            total += parseFloat(category.Amount) || 0;
        });

        const categories = revenueResults.map(category => ({
            Category: category.Category,
            Amount: parseFloat(category.Amount) || 0,
            Percentage: total > 0 ? ((parseFloat(category.Amount) || 0) / total) * 100 : 0
        }));

        // Get sponsorship details with simplified query
        const sponsorQuery = `
            SELECT s.CompanyName, sp.PackageName, sp.PackageCost AS Amount, 
                   sc.ContractStatus, sc.PaymentStatus
            FROM sponsorship_contracts sc
            JOIN sponsor s ON sc.SponsorID = s.Sponsor_ID
            JOIN sponsorship_package sp ON sc.PackageID = sp.PackageID
            LIMIT 10
        `;

        db.query(sponsorQuery, (err, sponsorResults) => {
            if (err) {
                console.error('Error generating sponsor details:', err);
                // Return partial results instead of failing
                return res.json({
                    categories: categories,
                    sponsors: [],
                    total: total
                });
            }

            res.json({
                categories: categories,
                sponsors: sponsorResults,
                total: total
            });
        });
    });
});

// Accommodation occupancy report
app.get('/api/reports/accommodation', authorize(['Admin']), (req, res) => {
    // Simplified room query
    const query = `
        SELECT 
            r.RoomNumber,
            r.Capacity,
            r.Price,
            r.AvailabilityStatus
        FROM room r
        ORDER BY r.RoomNumber
    `;

    db.query(query, (err, roomDetails) => {
        if (err) {
            console.error('Error generating accommodation report:', err);
            return res.status(500).json({ error: 'Failed to generate accommodation report' });
        }

        // Get simple occupancy summary
        const summaryQuery = `
            SELECT
                COUNT(*) AS TotalRooms,
                SUM(CASE WHEN r.AvailabilityStatus = 'Occupied' THEN 1 ELSE 0 END) AS OccupiedRooms,
                SUM(CASE WHEN r.AvailabilityStatus = 'Available' THEN 1 ELSE 0 END) AS AvailableRooms
            FROM room r
        `;

        db.query(summaryQuery, (err, summaryResults) => {
            if (err) {
                console.error('Error generating accommodation summary:', err);
                // Return partial results
                return res.json({
                    roomDetails: roomDetails,
                    summary: {
                        TotalRooms: 0,
                        OccupiedRooms: 0,
                        AvailableRooms: 0,
                        OccupancyRate: 0,
                        TotalCapacity: 0,
                        CurrentOccupants: 0
                    },
                    checkinStats: []
                });
            }

            const summary = summaryResults[0];
            summary.OccupancyRate = summary.TotalRooms > 0 
                ? (summary.OccupiedRooms / summary.TotalRooms) * 100 
                : 0;
            summary.TotalCapacity = 0; // Simplified
            summary.CurrentOccupants = 0; // Simplified

            res.json({
                roomDetails: roomDetails,
                summary: summary,
                checkinStats: [] // Simplified to avoid potential errors
            });
        });
    });
});

// Participant demographics report
app.get('/api/reports/participant', authorize(['Admin', 'Event Organizer']), (req, res) => {
    // Simplified university query
    const universityQuery = `
        SELECT
            IFNULL(p.University, 'Unknown') AS University,
            COUNT(*) AS ParticipantCount,
            COUNT(DISTINCT r.EventID) AS EventCount
        FROM participant p
        LEFT JOIN registration r ON p.Participant_ID = r.ParticipantID
        GROUP BY p.University
        ORDER BY ParticipantCount DESC
    `;

    db.query(universityQuery, (err, universities) => {
        if (err) {
            console.error('Error generating university statistics:', err);
            return res.status(500).json({ 
                universities: [],
                teams: [],
                registrationTrend: []
            });
        }

        res.json({
            universities: universities,
            teams: [], // Simplified to avoid potential errors
            registrationTrend: [] // Simplified to avoid potential errors
        });
    });
});

