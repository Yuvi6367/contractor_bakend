require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());



// --- CASHFREE CONFIG ---
// --- PASTE THIS INSTEAD ---
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_ENV = 'TEST'; // Change to 'PROD' when live
const CASHFREE_URL = CASHFREE_ENV === 'PROD' 
    ? 'https://api.cashfree.com/pg/orders' 
    : 'https://sandbox.cashfree.com/pg/orders';


mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB error:", err));

// Replace your existing UserSchema with this one
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    lang: { type: String, default: 'hi' },
    
    // Subscription Fields
    createdAt: { type: Date, default: Date.now }, // Trial starts here
    subscriptionExpiresAt: { type: Date, default: null } // Date when paid plan ends
});

const SiteSchema = new mongoose.Schema({
    userId: String,
    id: Number,
    name: String,
    loc: String
});

const WorkerSchema = new mongoose.Schema({
    userId: String,
    id: Number,
    siteId: Number,
    name: String,
    role: String,
    wage: Number
});

const AttendanceSchema = new mongoose.Schema({
    userId: String,
    key: String,
    status: String,
    ot: Number,
    note: String,
    payment: Number,
    paymentMode: String // ADDED: 'cash' or 'online'
});

const TransactionSchema = new mongoose.Schema({
    userId: String,
    id: Number,
    siteId: Number,
    workerId: Number,
    type: String,
    amount: Number,
    desc: String,
    date: String,
    mode: String // ADDED: To track transaction type
});

const User = mongoose.model('User', UserSchema);
const Site = mongoose.model('Site', SiteSchema);
const Worker = mongoose.model('Worker', WorkerSchema);
const Attendance = mongoose.model('Attendance', AttendanceSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'zentrox_secret_key_123'; 

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};
// --- SUBSCRIPTION HELPER ---
// Add this function before your routes
// --- SUBSCRIPTION HELPER (Updated for Existing Users) ---
const getSubscriptionStatus = (user) => {
    const now = new Date();
    
    // 1. Handle Existing Users who don't have 'createdAt'
    // If createdAt is missing, we treat them as if they signed up TODAY.
    // This gives all your current loyal users a fresh 30-day free trial.
    const signupDate = user.createdAt ? new Date(user.createdAt) : new Date();

    const trialEnds = new Date(signupDate);
    trialEnds.setDate(trialEnds.getDate() + 30); // 30 Day Trial

    // 2. Check Status
    const isTrialActive = now < trialEnds;
    const isPaidActive = user.subscriptionExpiresAt && new Date(user.subscriptionExpiresAt) > now;

    return {
        isActive: isTrialActive || isPaidActive,
        type: isPaidActive ? 'PRO' : (isTrialActive ? 'TRIAL' : 'EXPIRED'),
        daysLeft: isPaidActive 
            ? Math.ceil((new Date(user.subscriptionExpiresAt) - now) / (1000 * 60 * 60 * 24))
            : (isTrialActive ? Math.ceil((trialEnds - now) / (1000 * 60 * 60 * 24)) : 0)
    };
};
// --- ROUTES ---

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, lang } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, password: hashedPassword, lang: lang || 'en' });
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: "Username likely taken" });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Wrong password" });
    const token = jwt.sign({ id: user._id, name: user.username }, JWT_SECRET);
    res.json({ token });
});

// --- UPDATED DATA ROUTE ---
// Replace your existing app.get('/api/data'...) with this:
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);
        
        // 1. Calculate Status
        const subStatus = getSubscriptionStatus(user);

        const sites = await Site.find({ userId });
        const workers = await Worker.find({ userId });
        const attendanceList = await Attendance.find({ userId });
        const transactions = await Transaction.find({ userId });

const attendanceObj = {};
        attendanceList.forEach(a => {
            // FIX: Added 'paymentMode: a.paymentMode'
            attendanceObj[a.key] = { 
                status: a.status, 
                ot: a.ot, 
                note: a.note, 
                payment: a.payment,
                paymentMode: a.paymentMode 
            };
        });

        res.json({ 
            user: { lang: user.lang, sub: subStatus }, 
            sites, 
            workers, 
            attendance: attendanceObj, 
            transactions 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- NEW CASHFREE ROUTES ---
// Add these new routes for payment handling

// 1. Create Order
app.post('/api/create-order', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);
        const orderId = `ORDER_${userId}_${Date.now()}`;

        const payload = {
            order_id: orderId,
            order_amount: 99.00,
            order_currency: "INR",
            customer_details: {
                customer_id: userId,
                customer_phone: "9999999999", // Ideally ask user for this, but fixed for now is okay
                customer_name: user.username
            },
            order_meta: {
                return_url: "https://contractorpro.onrender.com/index.html?payment_status=check" // Your live URL
            }
        };

        const response = await axios.post(CASHFREE_URL, payload, {
            headers: {
                'x-client-id': CASHFREE_APP_ID,
                'x-client-secret': CASHFREE_SECRET_KEY,
                'x-api-version': '2022-09-01',
                'Content-Type': 'application/json'
            }
        });

        res.json({ payment_session_id: response.data.payment_session_id, order_id: orderId });

    } catch (error) {
        console.error("Cashfree Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: "Payment creation failed" });
    }
});

// 2. Verify Payment (Called after success)
app.post('/api/verify-payment', authenticateToken, async (req, res) => {
    const { orderId } = req.body;
    try {
        // Call Cashfree to check status
        const response = await axios.get(`${CASHFREE_URL}/${orderId}`, {
            headers: {
                'x-client-id': CASHFREE_APP_ID,
                'x-client-secret': CASHFREE_SECRET_KEY,
                'x-api-version': '2022-09-01'
            }
        });

        if (response.data.order_status === 'PAID') {
            // Add 30 Days to subscription
            const userId = req.user.id;
            const user = await User.findById(userId);
            
            let newExpiry = new Date();
            // If already active, add to existing expiry
            if (user.subscriptionExpiresAt && new Date(user.subscriptionExpiresAt) > new Date()) {
                newExpiry = new Date(user.subscriptionExpiresAt);
            }
            newExpiry.setDate(newExpiry.getDate() + 30);

            await User.findByIdAndUpdate(userId, { subscriptionExpiresAt: newExpiry });
            res.json({ success: true, newExpiry });
        } else {
            res.status(400).json({ error: "Payment not verified" });
        }
    } catch (error) {
        res.status(500).json({ error: "Verification failed" });
    }
});

app.post('/api/user/lang', authenticateToken, async (req, res) => {
    const { lang } = req.body;
    await User.findByIdAndUpdate(req.user.id, { lang });
    res.json({ success: true });
});

app.post('/api/sites', authenticateToken, async (req, res) => {
    await Site.create({ ...req.body, userId: req.user.id });
    res.json({ success: true });
});

app.post('/api/workers', authenticateToken, async (req, res) => {
    await Worker.create({ ...req.body, userId: req.user.id });
    res.json({ success: true });
});

// Delete Worker Route (Clean up everything)
app.delete('/api/workers/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        await Worker.deleteOne({ id: id, userId: userId });
        // Delete Attendance
        await Attendance.deleteMany({ userId: userId, key: { $regex: `-${id}$` } });
        // Delete related Transactions
        await Transaction.deleteMany({ userId: userId, workerId: id });

        res.json({ success: true });
    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).json({ error: "Could not delete worker" });
    }
});

app.post('/api/attendance', authenticateToken, async (req, res) => {
    const { key, data } = req.body;
    const userId = req.user.id;
    let att = await Attendance.findOne({ key, userId });
    if (att) { Object.assign(att, data); await att.save(); } 
    else { await Attendance.create({ ...data, key, userId }); }
    res.json({ success: true });
});

app.post('/api/attendance/delete-status', authenticateToken, async (req, res) => {
    const { key } = req.body;
    await Attendance.updateOne({ key, userId: req.user.id }, { $unset: { status: "", ot: "" } });
    res.json({ success: true });
});

// --- NEW SYNCED PAYMENT ROUTES (Solves Problem 2) ---

// 1. ADD Payment (Adds to Attendance AND Transaction)
// 1. ADD Payment (Adds to Attendance AND Transaction)
// 2. UPDATE '/api/pay/add' ROUTE
app.post('/api/pay/add', authenticateToken, async (req, res) => {
    // Added 'mode' to request body
    const { date, workerId, siteId, amount, name, mode } = req.body; 
    const userId = req.user.id;
    const key = `${date}-${workerId}`;

    try {
        // A. Update Attendance (Save paymentMode)
        let att = await Attendance.findOne({ key, userId });
        if (att) { 
            att.payment = amount; 
            att.paymentMode = mode; // <--- Save Mode
            await att.save(); 
        } else { 
            await Attendance.create({ userId, key, payment: amount, paymentMode: mode }); 
        }

        // B. Create Transaction (Save mode)
        const txId = Date.now();
        await Transaction.create({
            userId,
            id: txId,
            siteId,
            workerId,
            type: 'debit',
            amount,
            desc: `Payment to ${name}`,
            date,
            mode: mode // <--- Save Mode
        });

        res.json({ success: true, txId });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: e.message }); 
    }
});
// 3. DELETE Payment (Removes from Attendance AND Deletes Transaction)
app.post('/api/pay/delete', authenticateToken, async (req, res) => {
    const { date, workerId } = req.body;
    const userId = req.user.id;
    const key = `${date}-${workerId}`;

    try {
        // A. Remove payment field from Attendance
        await Attendance.updateOne({ key, userId }, { $unset: { payment: "" } });

        // B. Delete the Transaction associated with this payment
        // We look for a debit transaction for this worker on this specific date
        await Transaction.deleteMany({ userId, workerId, date, type: 'debit' });

        res.json({ success: true });
    } catch (e) { 
        console.error("Delete Payment Error:", e);
        res.status(500).json({ error: e.message }); 
    }
});
// 2. UPDATE Payment (Updates Attendance AND Transaction)
app.post('/api/pay/update', authenticateToken, async (req, res) => {
    const { date, workerId, amount } = req.body;
    const userId = req.user.id;
    const key = `${date}-${workerId}`;

    try {
        // A. Update Attendance
        await Attendance.updateOne({ key, userId }, { $set: { payment: amount } });

        // B. Update Transaction (Find by date + workerId)
        // We look for a debit transaction for this worker on this date
        await Transaction.updateMany(
            { userId, workerId, date, type: 'debit' },
            { $set: { amount: amount } }
        );

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- EXISTING TRANSACTION ROUTES ---

app.post('/api/transactions', authenticateToken, async (req, res) => {
    // Normal manual transactions
    await Transaction.create({ ...req.body, userId: req.user.id });
    res.json({ success: true });
});

// UPDATE Site Name
app.post('/api/sites/update', authenticateToken, async (req, res) => {
    const { id, name, loc } = req.body;
    const userId = req.user.id;
    try {
        await Site.updateOne({ id, userId }, { $set: { name, loc } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE Site (And all related data)
app.post('/api/sites/delete', authenticateToken, async (req, res) => {
    const { id } = req.body;
    const userId = req.user.id;
    try {
        // 1. Delete the Site
        await Site.deleteOne({ id, userId });
        
        // 2. Delete all Workers on this site
        // First find them so we can delete their attendance
        const workers = await Worker.find({ siteId: id, userId });
        const workerIds = workers.map(w => w.id);

        // Delete Workers
        await Worker.deleteMany({ siteId: id, userId });

        // 3. Delete Attendance for those workers
        // Regex to match keys ending in "-workerID"
        // This is complex, easier to just delete by userId if we had siteId in attendance, 
        // but since we don't, we iterate.
        for(let wid of workerIds) {
            await Attendance.deleteMany({ userId, key: { $regex: `-${wid}$` } });
        }

        // 4. Delete Transactions for this Site
        await Transaction.deleteMany({ siteId: id, userId });

        res.json({ success: true });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: e.message }); 
    }
});
// UPDATE: Delete Transaction (Syncs back to Attendance)
// UPDATE: Delete Transaction (Syncs back to Attendance)
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    // FIX: Convert params.id to a Number
    const txId = Number(req.params.id); 
    const userId = req.user.id;

    console.log(`[DELETE TX] Attempting to delete TxID: ${txId} for User: ${userId}`);

    try {
        // 1. Find the transaction first
        const tx = await Transaction.findOne({ id: txId, userId });
        
        if (!tx) {
            console.log("[DELETE TX] Transaction not found in DB.");
        } else {
            console.log(`[DELETE TX] Found Tx. WorkerId: ${tx.workerId}, Date: ${tx.date}`);
            
            // 2. If it's linked to a worker, remove the payment badge from Attendance
            if (tx.workerId && tx.date) {
                const key = `${tx.date}-${tx.workerId}`;
                console.log(`[DELETE TX] Removing Attendance Payment for Key: ${key}`);
                
                const updateRes = await Attendance.updateOne({ key, userId }, { $unset: { payment: "" } });
                console.log(`[DELETE TX] Attendance Update Result:`, updateRes);
            } else {
                console.log("[DELETE TX] Transaction has no workerId or date. Skipping Attendance sync.");
            }
        }

        // 3. Delete the transaction
        await Transaction.deleteOne({ id: txId, userId });
        res.json({ success: true });
    } catch (e) { 
        console.error("[DELETE TX] Error:", e);
        res.status(500).json({ error: e.message }); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
