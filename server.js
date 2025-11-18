require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Expo } = require('expo-server-sdk');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer'); 
const serviceAccount = require('./miagao-church-scheduling-firebase-adminsdk-fbsvc-a50a418c10.json'); 

try {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount), // Pass the object here
    });
    console.log("Firebase Admin SDK initialized successfully.");
} catch (error) {
    // This is where you need to see the error if the key is wrong!
    console.error("Failed to initialize Firebase Admin SDK:", error.message);
}
const app = express();
const port = process.env.ENV_PORT || 3000;
const saltRounds = parseInt(process.env.SALT_ROUNDS) || 10;
const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_secret_key';
app.use(cors());
// Set a large limit for JSON payload to handle large Base64 files
app.use(express.json({ limit: '100mb' })); 
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/qr_codes', express.static(path.join(__dirname, 'admin', 'qr_codes')));
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
let expo = new Expo({ accessToken: process.env.EXPO_ACCESS_TOKEN });
pool.getConnection()
    .then(connection => {
        console.log('Connected to MySQL database!');
        connection.release();
    })
    .catch(err => {
    // 🟢 CHANGE: Log the entire error object (err)
    console.error('Error connecting to MySQL:', err); 
    process.exit(1);
});

function generateAuthToken(user) {
    // 1. Define the data (payload) to store inside the token
    const payload = {
        user_id: user.user_id,
        email: user.email,
        user_type: user.user_type, 
    };

    // 2. This is the logic you asked about—it creates the token string!
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); 
}
app.get('/api/test', (req, res) => {
    res.json({ message: 'Server is running!' });
});
let transporter;
try {
    transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT, 10) || 587,
        secure: process.env.EMAIL_PORT === '465', 
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
    console.log("Nodemailer Transporter successfully configured.");
} catch (e) {
    console.error("CRITICAL ERROR: Failed to initialize Nodemailer Transporter. Check your .env EMAIL variables.", e.message);
    // You should probably crash the server here to prevent failed emails later
    // process.exit(1);
}
/**
 * Sends an email notification using Nodemailer.
 * @param {string} to - Recipient email address.
 * @param {string} subject - Email subject line.
 * @param {string} htmlContent - HTML body content.
 */
async function sendEmailNotification(to, subject, htmlContent) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_HOST) {
        console.error("Email is not configured (EMAIL_USER or EMAIL_HOST is missing in .env). Skipping email send.");
        return { success: false, message: 'Email configuration missing.' };
    }
    
    try {
        let info = await transporter.sendMail({
            from: `"${process.env.ADMIN_EMAIL_NAME || 'Church Admin'}" <${process.env.EMAIL_USER}>`,
            to: to,
            subject: subject,
            html: htmlContent,
        });
        console.log("Message sent: %s", info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error("Error sending email:", error);
        if (error.response) {
            console.error("SMTP Response:", error.response);
        }
        return { success: false, error: error.message };
    }
}
/**
 * Formats a date string (from MySQL) into a human-readable format.
 * @param {string} dateString - The date string from the database.
 * @returns {string} - The formatted date (e.g., "October 7, 2025").
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    // Create a Date object from the database string 
    const date = new Date(dateString);
    // Check for invalid date
    if (isNaN(date.getTime())) {
        return 'Invalid Date';
    }
    // Options for a human-readable format
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return date.toLocaleDateString('en-US', options);
}
// ✅ Robust function to convert 12-hour time to 24-hour format
const convertTo24Hour = (time12h) => {
    // Check if the input is already in a valid 24-hour format
    if (typeof time12h === 'string' && time12h.match(/^\d{2}:\d{2}:\d{2}$/)) {
        return time12h;
    }
    // Attempt to match common 12-hour formats, with or without space
    const match = time12h.match(/(\d{1,2}):(\d{2})\s*(am|pm)/i);
    if (!match) {
        console.error(`convertTo24Hour: Invalid time format received: "${time12h}"`);
        return null;
    }
    let [, hours, minutes, ampm] = match;
    hours = parseInt(hours, 10);
    minutes = parseInt(minutes, 10);
    // Correctly handle 12 AM and 12 PM
    if (ampm.toLowerCase() === 'pm' && hours !== 12) {
        hours += 12;
    } else if (ampm.toLowerCase() === 'am' && hours === 12) {
        hours = 0;
    }
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:00`;
};
/**
 * Saves a Base64 string as a file in the uploads directory.
 * @param {string} base64Data - The Base64 string of the file.
 * @param {string} originalFileName - The original file name to guess the extension.
 * @returns {string} - The unique filename saved on the server.
 */
const savebase64File = async (base64Data, originalFileName = '') => {
    if (!base64Data) return null;
    // Determine file extension (basic guess)
    let ext = '.jpg';
    if (originalFileName.toLowerCase().endsWith('.pdf')) {
        ext = '.pdf';
    } else if (originalFileName.toLowerCase().endsWith('.png')) {
        ext = '.png';
    } else if (originalFileName.toLowerCase().endsWith('.jpeg') || originalFileName.toLowerCase().endsWith('.jpg')) {
        ext = '.jpeg';
    }
    const uploadsDir = path.join(__dirname, 'uploads');
    await fs.mkdir(uploadsDir, { recursive: true }); // Ensure the uploads directory exists
    const uniqueFilename = `${crypto.randomUUID()}${ext}`;
    const imagePath = path.join(uploadsDir, uniqueFilename);
    // Convert Base64 string to a Buffer
    const imageBuffer = Buffer.from(base64Data, 'base64');
    await fs.writeFile(imagePath, imageBuffer); // Write the file to disk
    return uniqueFilename; // Return only the filename
};

app.get('/api/booked-times-for-day', async (req, res) => {
    // 1. Get the date from the query parameter (e.g., /api/booked-times-for-day?date=2025-11-28)
    const { date } = req.query; 
    
    if (!date) {
        return res.status(400).json({ message: 'Missing date query parameter.' });
    }
    
    try {
        // 2. Query the calendar table for ALL entries on that specific date.
        // Assuming every entry in 'calendar' means the time slot is taken.
        const query = `
            SELECT 
                TIME_FORMAT(selected_time, '%h:%i %p') AS selected_time
            FROM calendar
            WHERE selected_date = ?
        `;
        
        const [rows] = await pool.query(query.trim(), [date]);
        
        // 3. Map the results to a simple array of time strings: ['8:00 AM', '10:00 AM', ...]
        const bookedTimesArray = rows.map(row => row.selected_time);

        // 4. Send the array back to the mobile app client
        res.json(bookedTimesArray);
    } catch (error) {
        console.error('Error fetching booked times for day:', error);
        res.status(500).json({ 
            message: 'Error fetching booked times', 
            error: error.message 
        });
    }
});
app.post('/api/send-test-email', async (req, res) => {
    const { toEmail, subject, body } = req.body;
    
    if (!toEmail || !subject || !body) {
        return res.status(400).json({ message: 'Missing required fields: toEmail, subject, and body.' });
    }
    const htmlBody = `
        <div style="font-family: sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <h2 style="color: #3f51b5;">Confirmation: Nodemailer Test Success</h2>
            <p>This email was successfully sent from your Node.js server using <strong>Nodemailer</strong> (the robust alternative to PHPMailer).</p>
            <p><strong>Test Message:</strong> ${body}</p>
            <p>If you received this, your SMTP configuration is correct!</p>
            <small>Sent by Miagao Church Scheduling System</small>
        </div>
    `;
    const result = await sendEmailNotification(toEmail, subject, htmlBody);
    if (result.success) {
        res.json({ 
            message: 'Test email sent successfully! Check your inbox.', 
            messageId: result.messageId 
        });
    } else {
        res.status(500).json({ 
            message: 'Failed to send test email. Ensure your EMAIL_HOST, PORT, USER, and PASS are correct in your .env file.', 
            error: result.error 
        });
    }
});
app.post('/api/register', async (req, res) => {
    const { username, email, password, user_type } = req.body;
    
    if (!username || !email || !password || !user_type) {
        return res.status(400).json({ message: 'Missing required fields: username, email, password, user_type' });
    }
    if (!['parishioner', 'priest'].includes(user_type)) {
        return res.status(400).json({ message: 'Invalid user_type. Must be "parishioner" or "priest".' });
    }
    
    let connection;
    try {
        connection = await pool.getConnection();
        const [existingUsers] = await connection.query('SELECT user_id FROM users WHERE username = ? OR email = ?', [username, email]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username or Email is already taken' });
        }
        
        const passwordHash = await bcrypt.hash(password, saltRounds);
        let verificationToken = null;
        let isVerified;
        let responseMessage;

        if (user_type === 'priest') {
            isVerified = 1;
            responseMessage = 'Priest account registered and automatically verified.';
        } else { 
            isVerified = 0;
            verificationToken = crypto.randomUUID();
            responseMessage = 'Parishioner registered successfully! A verification link has been sent to your email.';
        }
        const [result] = await connection.query(
            'INSERT INTO users (username, email, password_hash, user_type, is_verified, verification_token) VALUES (?, ?, ?, ?, ?, ?)',
            [username, email, passwordHash, user_type, isVerified, verificationToken]
        );
        const userId = result.insertId;
        const verificationLink = `${process.env.BASE_URL}/verify?token=${verificationToken}&user=${userId}`;
        const emailSubject = 'Miagao Church Account Verification Required';
        const emailHtml = `
            <p>Hello ${username},</p>
            <p>Thank you for registering. Please click the button below to verify your email address and activate your account:</p>
            <div style="text-align: center; margin: 20px 0;">
                <a href="${verificationLink}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
                    Verify My Email
                </a>
            </div>
            <p>If you did not sign up for this account, please ignore this email.</p>
        `;
        
        const emailResult = await sendEmailNotification(email, emailSubject, emailHtml);
        if (!emailResult.success) {
            console.warn(`[WARNING] Verification email failed for ${email}. Error: ${emailResult.error}`);
        }
        // 5. Respond to client
        res.status(201).json({ 
            user_id: userId, 
            message: `${user_type} registered successfully! A verification link has been sent to your email.`,
            isVerified: false 
        });
    } catch (error) {
        console.error('Error during registration process:', error);
        res.status(500).json({ message: 'An unexpected error occurred', error: error.message });
    } finally {
        if (connection) connection.release();
    }
});
app.get('/verify', async (req, res) => {
    const { token, user } = req.query; 
    if (!token || !user) {
        return res.status(400).send('Invalid verification link: Missing token or user ID.');
    }
    let connection;
    try {
        connection = await pool.getConnection();
        const selectQuery = `
            SELECT user_id, email FROM users 
            WHERE user_id = ? AND verification_token = ? AND is_verified = 0
        `;
        const [users] = await connection.query(selectQuery, [user, token]);
        if (users.length === 0) {
            const [verifiedCheck] = await connection.query('SELECT user_id FROM users WHERE user_id = ? AND is_verified = 1', [user]);
            if (verifiedCheck.length > 0) {
                 return res.send('<h1>Already Verified!</h1><p>Your email was already confirmed. You can now return to the app and log in.</p>');
            }
            return res.status(404).send('Verification failed. Link is invalid or expired.');
        }
        const updateQuery = `
            UPDATE users SET is_verified = 1, verification_token = NULL 
            WHERE user_id = ?
        `;
        await connection.query(updateQuery, [user]);
        // 3. Success response
        res.send('<h1>Email Verified Successfully!</h1><p>Your Miagao Church Scheduling account is now active. You can close this window and log in.</p>');
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).send('A server error occurred during verification.');
    } finally {
        if (connection) connection.release();
    }
});
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Missing required fields: email, password' });
    }
    try {
        const [users] = await pool.query('SELECT user_id, username, email, password_hash, user_type, is_verified FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const user = users[0];
        
        // Check verification status
        if (user.user_type === 'parishioner' && user.is_verified === 0) {
            return res.status(403).json({
                message: 'Account not verified. Please check your email for the verification link.',
                isVerified: false
            });
        }
        
        // Check password match
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // 🔑 CONSISTENT TOKEN GENERATION FOR PRIEST AND PARISHIONER
        const token = generateAuthToken(user); 

        // Send a successful response with user details AND the token
        res.json({
            message: 'Login successful!',
            user: {
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                user_type: user.user_type,
                isVerified: true 
            },
            token: token // 👈 Both roles receive the token here
        });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});
app.get('/api/calendar', async (req, res) => {
    const { userId } = req.query;
    if (!userId) {
        return res.status(400).json({ message: 'Missing userId query parameter.' });
    }
    try {
        const query = `
            SELECT
                calendar_id,
                DATE_FORMAT(selected_date, '%Y-%m-%d') AS selected_date,
                TIME_FORMAT(selected_time, '%h:%i %p') AS selected_time,
                selected_servicetype,
                user_id
            FROM calendar
            WHERE user_id = ?
            ORDER BY selected_date ASC
        `;
        const [rows] = await pool.query(query.trim(), [userId]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching calendar events:', error);
        res.status(500).json({ message: 'Error fetching calendar events', error: error.message });
    }
});
app.get('/api/calendar/:calendar_id', async (req, res) => {
    const { calendar_id } = req.params;
    try {
        const query = `
            SELECT
                calendar_id,
                DATE_FORMAT(selected_date, '%Y-%m-%d') AS selected_date,
                TIME_FORMAT(selected_time, '%h:%i %p') AS selected_time,
                selected_servicetype,
                user_id
            FROM calendar
            WHERE calendar_id = ?
        `;
        const [rows] = await pool.query(query.trim(), [calendar_id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Calendar event not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching single calendar event:', error);
        res.status(500).json({ message: 'Error fetching calendar event', error: error.message });
    }
})

app.get('/api/notifications/priest/:priestId', async (req, res) => {
    const { priestId } = req.params; 
    
    if (!priestId) {
        return res.status(400).json({ message: 'Priest ID is required.' });
    }

    try {
        // 🚀 CRITICAL FIX: LEFT JOIN to schedules and calendar to get status and date/time
        const [rows] = await pool.query(
            `
            SELECT 
                n.notification_id, 
                n.user_id, 
                n.title, 
                n.body AS message, 
                n.is_read, 
                n.created_at, 
                n.schedule_id, 
                n.notification_type,
                
                -- Schedule Status and Event Date/Time (CRITICAL)
                s.status AS schedule_status,
                c.selected_date AS event_date,
                c.selected_time AS event_time 
            FROM notifications AS n
            LEFT JOIN schedules AS s ON n.schedule_id = s.schedule_id
            LEFT JOIN calendar AS c ON s.calendar_id = c.calendar_id
            WHERE n.user_id = ? 
            ORDER BY n.created_at DESC
            `,
            [priestId]
        );
        
        console.log(`[PRIEST NOTIF] Fetched ${rows.length} notifications for priest: ${priestId}`);
        res.json(rows);
    } catch (error) {
        console.error('Database query error (GET Priest notifications):', error);
        res.status(500).json({ message: 'Internal server error while fetching priest notifications.' });
    }
});
app.post('/api/bookings/accept/:scheduleId', async (req, res) => {
    const { scheduleId } = req.params;
    const { priestId, status } = req.body; 

    if (!scheduleId || !priestId || !status) {
        // NOTE: The client-side fix ensures these are sent.
        return res.status(400).json({ message: 'Missing scheduleId, priestId, or status in the request.' });
    }

    if (!['approved', 'pending'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status provided. Must be "approved" or "rejected".' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        // 1. Update the schedules table status
        const [updateResult] = await connection.query(
            'UPDATE schedules SET status = ?, priest_user_id = ? WHERE schedule_id = ?',
            [status, priestId, scheduleId]
        );

        if (updateResult.affectedRows === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Schedule not found or already processed.' });
        }
        await connection.commit();

        // 2. Final success response
        const action = status === 'approved' ? 'approved' : 'pending';

        res.status(200).json({ 
            success: true, 
            message: `Schedule ${scheduleId} successfully ${action}. Parishioner notification skipped as requested.`,
            status: action
        });

    } catch (error) {
        if (connection) await connection.rollback();
        console.error(`Error processing schedule ${scheduleId} acceptance/cancelled:`, error);
        res.status(500).json({ message: `Internal server error during ${status} process.`, error: error.message });
    } finally {
        if (connection) connection.release();
    }
});
app.get('/api/notifications/unread/:priestId', async (req, res) => {
    const { priestId } = req.params;
    let connection;
    try {
        connection = await pool.getConnection();
        const query = `
            SELECT COUNT(*) AS unreadCount
            FROM notifications
            WHERE user_id = ? AND is_read = 0
        `;
        const [rows] = await connection.query(query.trim(), [priestId]);
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching priest unread count:', error);
        res.status(500).json({ message: 'Internal Server Error', error: error.message });
    } finally {
        if (connection) connection.release();
    }
});
app.post('/api/notifications/mark-read/:priestId', async (req, res) => {
    const { priestId } = req.params;

    if (!priestId) {
        return res.status(400).json({ message: 'Priest ID is required.' });
    }

    try {
        // ✅ Updates the 'notifications' table
        const [result] = await pool.query(
            'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0',
            [priestId]
        );

        if (result.affectedRows > 0) {
            console.log(`Marked ${result.affectedRows} notifications as read for priest ${priestId}.`);
        }
        
        res.status(200).json({ message: 'Priest notifications marked as read successfully.' });

    } catch (error) {
        console.error('Database update error (POST read Priest):', error);
        res.status(500).json({ message: 'Internal server error while marking priest notifications as read.' });
    }
});
// Add a new route for marking all parishioner notifications as read
app.post('/api/notifications/parishioner/mark-all-read/:userId', async (req, res) => {
    const { userId } = req.params; 

    try {
        const updateQuery = `
            UPDATE p_notifications
            SET is_read = 1 
            WHERE user_id = ? AND is_read = 0;
        `;
        await pool.query(updateQuery, [userId]);
        res.json({ message: `All Parishioner notifications for user ${userId} marked as read.` });
    } catch (error) {
        console.error('Error marking all parishioner notifications as read:', error);
        res.status(500).json({ message: 'Failed to update parishioner notification status', error: error.message });
    }
});

// New, clear route for Parishioner notifications
app.get('/api/notifications/parishioner/:userId', async (req, res) => {
    const { userId } = req.params; 

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required.' });
    }
    
    try {
        const query = `
            SELECT 
                notification_id, 
                user_id,
                receipt_id, 
                message AS title,
                is_read, 
                created_at 
            FROM p_notifications
            WHERE user_id = ?
            ORDER BY created_at DESC;
        `;
        const [notifications] = await pool.query(query.trim(), [userId]);
        
        // Safety check against MySQL zero-dates (optional but recommended)
        const sanitizedNotifications = notifications.map(n => ({
            ...n,
            created_at: n.created_at && String(n.created_at).startsWith('0000') ? null : n.created_at,
        }));
        
        console.log(`[PARISHIONER NOTIF] Fetched ${sanitizedNotifications.length} notifications for Parishioner ${userId}.`);
        res.json(sanitizedNotifications);
    } catch (error) {
        console.error('Error fetching parishioner notification list:', error);
        res.status(500).json({ message: 'Failed to fetch parishioner notifications', error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Open in browser: http://localhost:${port}/api/test`); // Helpful for quick check
});
app.post('/api/upload-receipt', async (req, res) => {
    const { 
        receiptImage, 
        selectedPaymentAmount,
        fullBookingData 
    } = req.body;
    if (typeof selectedPaymentAmount !== 'number' || selectedPaymentAmount <= 0) {
        return res.status(400).json({ 
            message: 'Invalid or missing payment amount.',
            details: 'The required amount was not correctly transmitted.'
        });
    }
    
    const userId = fullBookingData?.user_id;
    if (!userId || !fullBookingData) {
        return res.status(400).json({
            success: false,
            message: 'Missing required data: userId or fullBookingData.'
        });
    }
    const convertedTime = convertTo24Hour(fullBookingData.selected_time);
    if (!convertedTime) {
      return res.status(400).json({
          success: false,
          message: 'Invalid time format received from the client.'
      });
    }
    let connection;
    // Variables to store file paths
    let receiptFilePath = null;
    let birthCertFilePath = null;
    let marriageCertFilePath = null;
    let deathCertFilePath = null; // <-- ADDED for Burial
    // Removed: let otherCertFilePath = null; 
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const serviceType = fullBookingData.selected_servicetype;
        // Local utility function for DB insertion (YYYY-MM-DD)
        const formatDateToDB = (dateString) => {
            if (!dateString) return null;
            const date = new Date(dateString);
            return isNaN(date.getTime()) ? null : date.toISOString().split('T')[0];
        };
        
        // 1. Insert into calendar table
        const [calendarResult] = await connection.query(
            'INSERT INTO calendar (selected_date, selected_time, selected_servicetype, user_id, payment_amount) VALUES (?, ?, ?, ?, ?)',
            [fullBookingData.selected_date, convertedTime, fullBookingData.selected_servicetype, userId, selectedPaymentAmount] // <-- Added selectedPaymentAmount
        );
        const calendarId = calendarResult.insertId;
        // 2. Insert into the correct service-specific table
        if (serviceType === 'Baptism') {
            const {
                childName, baptismgender, placeOfBirth, dateOfBirth, name_OfFather, name_OfMother, dateOfMarriage, placeOfMarriage, baptismMinister, registryNo, placeIssued, dateIssued, baptismResidence, contact_Person, contact_Num, sponsors, requiredDocuments
            } = fullBookingData;
            
            const birthCertbase64 = requiredDocuments?.birthCertificatebase64;
            const marriageCertbase64 = requiredDocuments?.marriageCertificatebase64;
            
            birthCertFilePath = await savebase64File(birthCertbase64, requiredDocuments?.birthCertificateFileName);
            marriageCertFilePath = await savebase64File(marriageCertbase64, requiredDocuments?.marriageCertificateFileName);
            
            const sponsorsData = sponsors && sponsors.length > 0 ? JSON.stringify(sponsors) : null;
            
            const baptismInsertQuery = `
                INSERT INTO baptism_requests (
                    user_id, calendar_id, name_of_child, child_gender, date_of_birth, place_of_birth, 
                    name_of_father, name_of_mother, date_of_marriage, place_of_marriage, 
                    minister, registry_no, place_issued, date_issued, residence, 
                    contact_person, contact_num, sponsors, 
                    birth_certificate_path, marriage_certificate_path
                ) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            await connection.query(
                baptismInsertQuery,
                [
                    calendarId, childName, baptismgender, formatDateToDB(dateOfBirth), placeOfBirth, 
                    name_OfFather, name_OfMother, formatDateToDB(dateOfMarriage), placeOfMarriage, 
                    baptismMinister, registryNo, placeIssued, formatDateToDB(dateIssued), baptismResidence, 
                    contact_Person, contact_Num, sponsorsData, 
                    // Insert the file paths
                    birthCertFilePath, marriageCertFilePath
                ]
            );
        } else if (serviceType === 'Funeral') {
               const {
    nameOfDead, 
    gender,
    age, 
    status, 
    sacraments, 
    burialMinister, 
    burialResidence, 
    causeOfDeath, 
    dateOfDeath,
    burialLocation, 
    nameOfFather, 
    nameOfMother,
    contactPerson_burial, 
    contactNum_burial,  
    requiredDocuments,
    spouse = null, 
    children = null
} = fullBookingData;
const deathCertbase64 = requiredDocuments?.deathCertificatebase64;
deathCertFilePath = await savebase64File(deathCertbase64, requiredDocuments?.deathCertificateFileName);
const spouseData = spouse ? JSON.stringify(spouse) : null;
const childrenData = children ? JSON.stringify(children) : null;
const burialInsertQuery = `
    INSERT INTO burial_requests (
        user_id, calendar_id, name_of_dead, gender, age, status, name_of_father, name_of_mother, spouse, children,
        residence, sacraments, minister, date_of_death, cause_of_death, burial_location, 
        contact_person, contact_num, death_certificate_path
    ) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`; 
await connection.query(
    burialInsertQuery,
    [
        calendarId, 
        nameOfDead, 
        gender, age, 
        status, 
        nameOfFather, nameOfMother, spouseData, childrenData,
        burialResidence, sacraments, burialMinister, 
        formatDateToDB(dateOfDeath), causeOfDeath, burialLocation, 
        contactPerson_burial, contactNum_burial, 
        deathCertFilePath
    ]
);
            
        } else if (serviceType === 'Special Masses') {
    const {
        massServiceType,
        description,
        contactPerson,
        contactNum
    } = fullBookingData;
    const specialMassInsertQuery = `
        INSERT INTO special_mass_requests (
            user_id, calendar_id, service_type, description, contact_person, contact_num
        ) 
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    await connection.query(
        specialMassInsertQuery,
        [
            userId,
            calendarId,
            massServiceType, 
            description,
            contactPerson,
            contactNum
        ]
    );
} else {
    await connection.rollback();
    return res.status(400).json({ success: false, message: 'Invalid service type provided.' });
}
        if (receiptImage) {
            receiptFilePath = await savebase64File(receiptImage); 
        }
        let receiptId = null; 
        if (receiptFilePath) {
            const [receiptResult] = await connection.query(
                'INSERT INTO receipts (calendar_id, user_id, image_path, status) VALUES (?, ?, ?, ?)',
                [calendarId, userId, receiptFilePath, 'Pending']
            );
            receiptId = receiptResult.insertId; 
        }
        await connection.commit();
        res.status(201).json({
            success: true,
            message: 'Booking request and required documents uploaded successfully!',
            calendarId: calendarId
        });
    } catch (error) {
        if (connection) {
            await connection.rollback();
        }
        console.error('Error during booking and document upload (Check your server logs for the stack trace!):', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while processing your request.',
            error: error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});
app.get('/api/status/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        const query = `
            SELECT
                s.schedule_id AS id,
                s.status,
                u.user_id,
                u.username,
                DATE_FORMAT(c.selected_date, '%Y-%m-%d') AS selected_date,
                TIME_FORMAT(c.selected_time, '%h:%i %p') AS selected_time,
                c.selected_servicetype
            FROM schedules AS s
            JOIN users AS u ON s.user_id = u.user_id
            JOIN calendar AS c ON s.calendar_id = c.calendar_id
            WHERE s.user_id = ?
            ORDER BY c.selected_date DESC;
        `;
        const [rows] = await pool.query(query.trim(), [userId]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching schedules:', error);
        res.status(500).json({ message: 'Error fetching schedules', error: error.message });
    }
});
app.get('/api/special-masses', async (req, res) => {
    console.log('GET /api/special-masses endpoint hit.');
    try {
        const [rows] = await pool.query(
            'SELECT request_id, service_type, description, contact_person, contact_num, email FROM special_mass_requests'
        );
        res.status(200).json(rows);
    } catch (error) {
        console.error('Error fetching special masses:', error);
        res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
});
app.post('/api/save-priest-token', async (req, res) => {
    const { userId, expoPushToken } = req.body; 
    
    // 1. CONFIRM DATA RECEIVED 
    console.log('Received priestId:', userId);
    console.log('Received expoPushToken:', expoPushToken);
    
    if (!userId || !expoPushToken) {
         return res.status(400).json({ message: 'Missing userId or expoPushToken.' });
    }
    
    try {
        // 2. Query remains the same, updating the expoPushToken column based on the user_id
        await pool.query(
            'UPDATE users SET expoPushToken = ? WHERE user_id = ?',
            [expoPushToken, userId] 
        );
        res.status(200).json({ message: 'Push token saved successfully for user.' });
    } catch (error) {
        console.error('SQL EXECUTION FAILED:', error.message); 
        res.status(500).json({ message: 'Failed to save push token.', error: error.message });
    }
});
app.post('/api/assign-schedule', async (req, res) => {
    const { scheduleId, priestId } = req.body; 
    let connection;
    
    if (!scheduleId || !priestId) {
        return res.status(400).json({ message: 'Missing scheduleId or priestId.' });
    }

    try {
        connection = await pool.getConnection();

        // 1. Get the priest's Expo Push Token AND email
        const [tokenRows] = await connection.query('SELECT expoPushToken, email FROM users WHERE user_id = ?', [priestId]);
        const priestData = tokenRows[0];
        const priestExpoToken = priestData ? priestData.expoPushToken : null;
        const priestEmail = priestData ? priestData.email : null; // Get the email

        // 2. Get the schedule details
        const scheduleQuery = `
            SELECT
                s.calendar_id,
                c.selected_servicetype,
                c.selected_date,
                c.selected_time
            FROM schedules AS s
            JOIN calendar AS c ON s.calendar_id = c.calendar_id
            WHERE s.schedule_id = ?
        `;
        
        const [scheduleRows] = await connection.query(scheduleQuery.trim(), [scheduleId]);
        
        if (scheduleRows.length === 0) {
            return res.status(404).json({ message: 'Schedule ID not found.' });
        }
        
        const scheduleDetails = scheduleRows[0];
        const calendarId = scheduleDetails.calendar_id;
        
        const formattedDate = formatDate(scheduleDetails.selected_date); 
        const formattedTime = scheduleDetails.selected_time;
        const serviceType = scheduleDetails.selected_servicetype;

        // --- Notification Content ---
        const notificationTitle = 'You have a new schedule assignment!';
        const notificationBody = `You have been assigned to officiate a ${serviceType} on ${formattedDate} at ${formattedTime}.`;
        
        const emailHtml = `
            <p>Dear Priest,</p>
            <p>You have been assigned a new service:</p>
            <ul>
                <li><strong>Service Type:</strong> ${serviceType}</li>
                <li><strong>Date:</strong> ${formattedDate}</li>
                <li><strong>Time:</strong> ${formattedTime}</li>
            </ul>
            <p>Please check your admin panel for full request details (documents, contacts, etc.).</p>
            <p>Thank you.</p>
        `;
        if (priestExpoToken) { // We can still check if a token exists, but we don't need Expo.isExpoPushToken
    
    // 🛑 START: NEW FIREBASE ADMIN SDK CODE 
    const message = {
        token: priestExpoToken, // Expo tokens are compatible with FCM
        
        // 1. The main visible notification content
        notification: {
            title: notificationTitle,
            body: notificationBody,
        },
        
        // 2. CRITICAL: ANDROID CONFIGURATION FOR HIGH PRIORITY AND CHANNEL
        android: {
            // Set high priority to help ensure the notification is delivered quickly
            priority: 'high', 
            notification: {
                // *** THIS IS THE FIX ***
                channelId: 'high-priority-channel', 
                // Set the priority to 'max' to trigger a heads-up/banner notification
                priority: 'max', 
                sound: 'default', 
            },
        },
        
        // 3. Data payload (for handling in the app)
        data: {
            calendarId: calendarId.toString(),
            type: 'new_schedule',
            selected_time: formattedTime,
            selected_date: formattedDate
        }
    };

    try {
        // Send the message using the Firebase Admin SDK
        const response = await admin.messaging().send(message); 
        console.log(`[SUCCESS] Firebase FCM sent for schedule ${scheduleId}. Response:`, response);
    } catch (error) {
        console.error(`[FAILURE] Error sending Firebase FCM notification for schedule ${scheduleId}:`, error);
    }
        } else {
            console.log(`No valid Expo push token found for priest ${priestId}. Push Notification skipped.`);
        }
        
        // 4. Attempt to send Email Notification (New logic using Nodemailer)
        if (priestEmail) {
            const emailResult = await sendEmailNotification(
                priestEmail, 
                notificationTitle, 
                emailHtml
            );
            if (emailResult.success) {
                console.log(`[SUCCESS] Email sent to priest ${priestId} (${priestEmail}).`);
            } else {
                console.error(`[FAILURE] Email failed to send to priest ${priestId}: ${emailResult.error}`);
            }
        } else {
            console.log(`No email found for priest ${priestId}. Email notification skipped.`);
        }

        // 5. Update the schedules table with the assigned priestId (The core assignment logic)
        await connection.query('UPDATE schedules SET priest_user_id = ?, status = ? WHERE schedule_id = ?', [priestId, 'approved', scheduleId]);

        // 6. Respond to the client
        res.status(200).json({ 
            success: true, 
            message: 'Schedule assignment completed. Notifications (Push and Email) attempted.', 
            scheduleId: scheduleId 
        });
    } catch (error) {
        console.error('Error processing schedule assignment and notification:', error);
        res.status(500).json({ message: 'An error occurred during the assignment process.', error: error.message });
    } finally {
        if (connection) connection.release();
    }
});
app.post('/api/save-parishioner-token', async (req, res) => {
    // NOTE: The client (LoginScreen.js) sends 'parishionerId', not 'userId' for this endpoint.
    const { parishionerId, expoPushToken } = req.body; 

    // 1. CONFIRM DATA RECEIVED 
    console.log('Received parishionerId:', parishionerId);
    console.log('Received expoPushToken:', expoPushToken);

    if (!parishionerId || !expoPushToken) {
        // Send status 400 for a bad request (missing data)
        return res.status(400).json({ message: 'Missing parishionerId or expoPushToken.' });
    }

    try {
        // 2. Use the same logic as the priest route: update the expoPushToken column based on the user_id (parishionerId)
        await pool.query(
            'UPDATE users SET expoPushToken = ? WHERE user_id = ?',
            [expoPushToken, parishionerId] // parishionerId is used as the user_id for the WHERE clause
        );
        
        // 3. Send success response
        res.status(200).json({ message: 'Push token saved successfully for parishioner.' });

    } catch (error) {
        console.error('SQL EXECUTION FAILED:', error.message);
        // Send status 500 for a server/database error
        res.status(500).json({ message: 'Failed to save push token.', error: error.message });
    }
});

app.get('/api/schedules/:priestId', async (req, res) => {
    const priestId = parseInt(req.params.priestId); 
    
    console.log('--- SERVER RECEIVES PRIEST ID:', priestId); 

    if (isNaN(priestId)) { 
        console.error('ERROR: Invalid Priest ID format received:', req.params.priestId);
        return res.status(400).json({ message: 'Invalid Priest ID format.' });
    }
    
    let connection;
    try {
        connection = await pool.getConnection();
        
        const scheduleQuery = `
            SELECT
                s.schedule_id AS id,
                c.selected_servicetype AS services,
                DATE_FORMAT(c.selected_date, '%Y-%m-%d') AS date,
                TIME_FORMAT(c.selected_time, '%h:%i %p') AS time,
                s.status,
                s.priest,
                
                -- SPECIAL MASSES Fields
                smr.service_type AS mass_type,
                smr.description,

                -- BAPTISM Fields
                br.name_of_child,
                br.child_gender,
                br.sponsors,
                br.birth_certificate_path,
                br.marriage_certificate_path,
                fr.death_certificate_path,
                
                -- FUNERAL Fields (Kept separate for now, assuming Funeral is a different service)
                fr.name_of_dead AS name_of_dead,
                fr.gender AS gender,
                fr.age AS age,
                fr.cause_of_death AS cause_of_death

            FROM schedules AS s
            INNER JOIN calendar AS c ON s.calendar_id = c.calendar_id
            -- LEFT JOIN to service-specific tables
            LEFT JOIN special_mass_requests AS smr ON c.calendar_id = smr.calendar_id AND c.selected_servicetype = 'Special Masses'
            LEFT JOIN baptism_requests AS br ON c.calendar_id = br.calendar_id AND c.selected_servicetype = 'Baptism'
            LEFT JOIN burial_requests AS fr ON c.calendar_id = fr.calendar_id AND c.selected_servicetype = 'Funeral'
            
            WHERE s.priest_user_id = ? 
            AND s.status = 'approved'
            ORDER BY c.selected_date ASC;
        `;
        const [scheduleRows] = await connection.query(scheduleQuery.trim(), [priestId]);

        // 3. Debugging the final result for confirmation
        console.log(`[CALENDAR DEBUG] Schedules for Priest ${priestId}: ${scheduleRows.length} found.`);
        if (scheduleRows.length > 0) {
            // Find a Burial event to show
            const burialEvent = scheduleRows.find(row => row.services === 'Burial');
            if (burialEvent) {
                console.log(`[CALENDAR DEBUG] Found Burial Details:`, {
                    id: burialEvent.id,
                    services: burialEvent.services,
                    name_of_dead: burialEvent.name_of_dead,
                    death_certificate_path: burialEvent.death_certificate_path,
                });
            }
        }
        
        res.json(scheduleRows);
    } catch (error) {
        console.error('Error fetching priest schedules:', error);
        res.status(500).json({ message: 'Internal Server Error', error: error.message });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

app.get('/api/latest-qrcode', async (req, res) => {
    try {
        // *** MODIFICATION HERE: SELECT 'filepath' (your column) AS 'image_path' (the expected key) ***
        const query = `
            SELECT
    filepath AS image_path,
    upload_timestamp
FROM qr_codes
WHERE qr_id = 1  -- Find the single active record
LIMIT 1
        `;

        const [rows] = await pool.query(query.trim());

        if (rows.length === 0) {
            console.log("[LATEST QR CODE] No QR codes found in the database.");
            return res.status(404).json({ 
                success: false, 
                message: 'No QR code found.',
                qrCodeUrl: null
            });
        }

        const qrCodeFilePath = rows[0].image_path; 
const uploadTimestamp = rows[0].upload_timestamp; 

const cacheBuster = uploadTimestamp.getTime(); // Get milliseconds from the Date object
const fixedHost = 'https://api.miagaochurchscheduling.online'; // <-- Use the IP from your mobile app
<<<<<<< HEAD
        const baseUrl = `${fixedHost}`;
=======
        const baseUrl = `http://${fixedHost}`;
>>>>>>> ac5de81d5b7e3e4638c888458a5906e558a236cb
const fullQrCodeUrl = `${baseUrl}/${qrCodeFilePath}?v=${cacheBuster}`; 

console.log(`[LATEST QR CODE] Found path: ${qrCodeFilePath}. Full URL: ${fullQrCodeUrl}`);

res.json({
    success: true,
    qrCodeUrl: fullQrCodeUrl
});

    } catch (error) {
        console.error('Error fetching latest QR code:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to retrieve latest QR code URL from the database.', 
            error: error.message 
        });
    }
});

app.get('/api/schedules/calendar', async (req, res) => {
    const rawUserId = req.query.user_id;

    if (!rawUserId) {
        return res.status(401).json({ message: "User ID is required for fetching events." });
    }
    
    // Safety check (parseInt with radix 10)
    const userId = parseInt(rawUserId, 10); 

    try {
        const query = `
    SELECT 
        s.schedule_id AS id, 
        DATE_FORMAT(c.selected_date, '%Y-%m-%d') AS selected_date, 
        c.selected_servicetype,
        c.selected_time,
        CAST(s.status AS CHAR) AS status,  
        s.user_id,
        c.calendar_id 
    FROM 
        schedules s 
    INNER JOIN 
        calendar c ON s.calendar_id = c.calendar_id
    WHERE 
        s.user_id = ? 
        AND DATE(c.selected_date) >= CURDATE() 
    ORDER BY 
        c.selected_date, c.selected_time;
`;
        const [results] = await db.query(query, [userId]); 

        // This will now send ALL upcoming schedules (Pending, Approved, Cancelled) to the client
        res.status(200).json(results); 
    } catch (error) {
        console.error("Database error fetching calendar events:", error);
        res.status(500).json({ message: "Failed to fetch schedules from database." });
    }
});
// --- CRITICAL: 404 Catch-All Middleware (Must be after all app.get/app.post) ---
app.use((req, res, next) => {
    // If the client tried to hit an API endpoint, respond with JSON 404
    if (req.url.startsWith('/api/')) {
        console.warn(`[404 WARNING] API route not found: ${req.method} ${req.url}`);
        return res.status(404).json({
            message: 'API Endpoint not found. Check the URL for typos in the frontend!',
            requestedUrl: req.url
        });
    }
    // Otherwise, continue to the default Express HTML 404
    next();
});

// The Global Express Error Handler (for internal 500 errors)
app.use((err, req, res, next) => {
    console.error('--- UNHANDLED EXPRESS ERROR CATCH-ALL ---');
    console.error(err.stack); // This should be logging any internal server 500 errors!
    
    // Check if the request was an API call
    if (req.url.startsWith('/api/')) {
        // Send JSON 500 error
        res.status(500).json({
            message: 'A critical internal server error occurred during request processing.',
            error: err.message,
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
        });
    } else {
        // Send HTML 500 error for non-API routes (like /verify)
        res.status(500).send('<h1>Server Error</h1><p>Something went wrong on the server.</p>');
    }
});
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
