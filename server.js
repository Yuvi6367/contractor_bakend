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

// --- 1. UPDATED USER SCHEMA ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    lang: { type: String, default: 'hi' } // Default to Hindi ('hi') or English ('en')
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
    payment: Number
});

const TransactionSchema = new mongoose.Schema({
    userId: String,
    id: Number,
    siteId: Number,
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
        const { username, password, lang } = req.body; // Accept lang on register
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

// --- 2. UPDATED DATA FETCH ---
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        // Fetch User settings too
        const user = await User.findById(userId);
        
        const sites = await Site.find({ userId });
        const workers = await Worker.find({ userId });
        const attendanceList = await Attendance.find({ userId });
        const transactions = await Transaction.find({ userId });

        const attendanceObj = {};
        attendanceList.forEach(a => {
            attendanceObj[a.key] = { status: a.status, ot: a.ot, note: a.note, payment: a.payment };
        });

        // Send 'lang' in the response
        res.json({ 
            user: { lang: user.lang }, 
            sites, workers, attendance: attendanceObj, transactions 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 3. NEW LANGUAGE UPDATE ROUTE ---
app.post('/api/user/lang', authenticateToken, async (req, res) => {
    const { lang } = req.body;
    await User.findByIdAndUpdate(req.user.id, { lang });
    res.json({ success: true });
});

// ... (Keep existing write routes: sites, workers, attendance, transactions) ...

app.post('/api/sites', authenticateToken, async (req, res) => {
    await Site.create({ ...req.body, userId: req.user.id });
    res.json({ success: true });
});
app.post('/api/workers', authenticateToken, async (req, res) => {
    await Worker.create({ ...req.body, userId: req.user.id });
    res.json({ success: true });
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
app.post('/api/attendance/delete-payment', authenticateToken, async (req, res) => {
    const { key } = req.body;
    await Attendance.updateOne({ key, userId: req.user.id }, { $unset: { payment: "" } });
    res.json({ success: true });
});
app.post('/api/transactions', authenticateToken, async (req, res) => {
    await Transaction.create({ ...req.body, userId: req.user.id });
    res.json({ success: true });
});
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    await Transaction.deleteOne({ id: req.params.id, userId: req.user.id });
    res.json({ success: true });
});

        // --- ADD THIS TO server.js ---

// Delete Worker Route
app.delete('/api/workers/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        // Delete the Worker
        await Worker.deleteOne({ id: id, userId: userId });
        
        // Also Delete their Attendance (Cleanup)
        // Note: We use regex to find keys ending in "-workerId"
        await Attendance.deleteMany({ userId: userId, key: { $regex: `-${id}$` } });

        res.json({ success: true });
    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).json({ error: "Could not delete worker" });
    }
});
async function shareOnWhatsapp() {
            const w = appData.workers[workerIndex];
            
            // 1. Populate the Report Card
            document.getElementById('rcName').innerText = w.name;
            const mName = currentMonthDate.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
            document.getElementById('rcMonth').innerText = mName;
            document.getElementById('rcDue').innerText = document.getElementById('sumDue').innerText;

            const list = document.getElementById('rcBody');
            list.innerHTML = '';

            const daysInMonth = new Date(currentMonthDate.getFullYear(), currentMonthDate.getMonth() + 1, 0).getDate();
            
            // Loop through days to build the table rows
            for (let day = 1; day <= daysInMonth; day++) {
                const monthStr = String(currentMonthDate.getMonth() + 1).padStart(2, '0');
                const isoDate = `${currentMonthDate.getFullYear()}-${monthStr}-${String(day).padStart(2, '0')}`;
                const key = `${isoDate}-${workerId}`;
                const log = appData.attendance[key];

                if (log && (log.status || log.payment)) {
                    const row = document.createElement('div');
                    row.style.cssText = "display:flex; padding:5px; border-bottom:1px solid #ccc; font-size:0.9rem;";
                    
                    let statusTxt = log.status || '-';
                    let extraTxt = log.ot ? `(+${log.ot}h)` : '';
                    if(log.payment) extraTxt += ` Paid ${log.payment}`;

                    row.innerHTML = `
                        <div style="width:30%; font-weight:700;">${day}</div>
                        <div style="width:40%; text-align:center;">${statusTxt}</div>
                        <div style="width:30%; text-align:right;">${extraTxt}</div>
                    `;
                    list.appendChild(row);
                }
            }

            // 2. Generate Image
            try {
                const canvas = await html2canvas(document.getElementById('reportCard'));
                
                canvas.toBlob(async (blob) => {
                    const file = new File([blob], "Worker_Report.png", { type: "image/png" });

                    // 3. Try Native Share (Mobile)
                    if (navigator.share) {
                        try {
                            await navigator.share({
                                files: [file],
                                title: 'Worker Report',
                                text: `Attendance for ${w.name}`
                            });
                        } catch (err) {
                            console.log("Share failed or cancelled", err);
                        }
                    } else {
                        // 4. Fallback for Desktop (Download)
                        const link = document.createElement('a');
                        link.download = `Report_${w.name}.png`;
                        link.href = canvas.toDataURL();
                        link.click();
                        alert("Image downloaded! You can now send it on WhatsApp.");
                    }
                });
            } catch (err) {
                alert("Could not generate image: " + err);
            }
        }
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
