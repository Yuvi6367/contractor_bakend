require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB error:", err));

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    lang: { type: String, default: 'hi' }
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
    key: String, // Format: "YYYY-MM-DD-workerId"
    status: String,
    ot: Number,
    note: String,
    payment: Number
});

const TransactionSchema = new mongoose.Schema({
    userId: String,
    id: Number,
    siteId: Number,
    workerId: Number, // ADDED: To link transaction to a worker
    type: String,
    amount: Number,
    desc: String,
    date: String
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

app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);
        const sites = await Site.find({ userId });
        const workers = await Worker.find({ userId });
        const attendanceList = await Attendance.find({ userId });
        const transactions = await Transaction.find({ userId });

        const attendanceObj = {};
        attendanceList.forEach(a => {
            attendanceObj[a.key] = { status: a.status, ot: a.ot, note: a.note, payment: a.payment };
        });

        res.json({ 
            user: { lang: user.lang }, 
            sites, workers, attendance: attendanceObj, transactions 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
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
app.post('/api/pay/add', authenticateToken, async (req, res) => {
    const { date, workerId, siteId, amount, name } = req.body;
    const userId = req.user.id;
    const key = `${date}-${workerId}`;

    try {
        // A. Update Attendance
        let att = await Attendance.findOne({ key, userId });
        if (att) { 
            att.payment = amount; 
            await att.save(); 
        } else { 
            await Attendance.create({ userId, key, payment: amount }); 
        }

        // B. Create Transaction
        const txId = Date.now();
        await Transaction.create({
            userId,
            id: txId,  // <--- FIXED: changed 'kxId' to 'txId'
            siteId,
            workerId,
            type: 'debit',
            amount,
            desc: `Payment to ${name}`,
            date
        });

        res.json({ success: true, txId });
    } catch (e) { 
        console.error(e); // Added logging so you can see errors in terminal
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
