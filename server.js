const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ethara-teamsync-secure-jwt-key-2026';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'frontend/login.html')));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('✅ MongoDB Connected');
        seedUsers();
    })
    .catch(err => console.log('❌ MongoDB Error:', err));

// ====================== MODELS ======================
const User = mongoose.model('User', new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'member'], default: 'member' }
}));

const Project = mongoose.model('Project', new mongoose.Schema({
    name: { type: String, required: true },
    createdBy: String,
    members: { type: [String], default: [] },
    createdAt: { type: Date, default: Date.now }
}));

const Task = mongoose.model('Task', new mongoose.Schema({
    title: { type: String, required: true },
    assignedTo: String,
    status: { type: String, enum: ['Pending', 'In Progress', 'Done'], default: 'Pending' },
    projectId: String,
    dueDate: Date,
    createdAt: { type: Date, default: Date.now }
}));

// ====================== MIDDLEWARE ======================
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access token required" });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin access only" });
    next();
};

const isProjectMember = (project, email) => (project.members || []).includes(email);

// ====================== SEED USERS ======================
async function seedUsers() {
    const users = [
        { email: "admin@ethara.ai", password: "admin123", role: "admin" },
        { email: "avinash@ethara.ai", password: "avin123", role: "member" },
        { email: "rohit@ethara.ai", password: "rohit123", role: "member" }
    ];
    await Promise.all(users.map(async (u) => {
        const hashed = bcrypt.hashSync(u.password, 10);
        await User.findOneAndUpdate({ email: u.email }, { email: u.email, password: hashed, role: u.role }, { upsert: true });
    }));
    console.log('🌱 Users seeded with hashed passwords');
}

// ====================== ROUTES ======================
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, email: user.email, role: user.role });
});

// REGISTER ROUTE (Signup)
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    try {
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ error: "User already exists" });

        const hashed = bcrypt.hashSync(password, 10);
        const user = new User({
            email,
            password: hashed,
            role: "member"   // ← Make sure role is always sent
        });
        await user.save();

        const token = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

        res.json({
            success: true,
            token,
            email: user.email,
            role: user.role   // ← Critical: Send role
        });
    } catch (e) {
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/user', authenticateToken, isAdmin, async (req, res) => {
    const { name } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "Name required" });
    const email = `${name.trim().toLowerCase()}@ethara.ai`;
    const hashed = bcrypt.hashSync("1234", 10);
    await User.findOneAndUpdate({ email }, { email, password: hashed, role: "member" }, { upsert: true });
    res.json({ success: true, email, password: "1234" });
});

app.get('/projects', authenticateToken, async (req, res) => {
    const projects = await Project.find({ $or: [{ createdBy: req.user.email }, { members: req.user.email }] });
    res.json(projects);
});

app.post('/project', authenticateToken, async (req, res) => {
    const { name } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "Project name required" });
    const existing = await Project.findOne({ name: name.trim() });
    if (existing) return res.status(400).json({ error: "Project with this name already exists" });
    const project = new Project({
        name: name.trim(),
        createdBy: req.user.email,
        members: [req.user.email]
    });
    await project.save();
    res.json(project);
});

app.get('/project/:id', authenticateToken, async (req, res) => {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: "Project not found" });
    if (!isProjectMember(project, req.user.email) && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Unauthorized" });
    }
    res.json(project);
});

app.put('/project/:id/members', authenticateToken, isAdmin, async (req, res) => {
    const updatedMembers = Array.from(new Set(req.body.members || []));
    const project = await Project.findByIdAndUpdate(req.params.id, { members: updatedMembers }, { new: true });
    res.json(project);
});

app.delete('/project/:id/members/:memberName', authenticateToken, isAdmin, async (req, res) => {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ error: "Project not found" });
    project.members = (project.members || []).filter(m => m.toLowerCase() !== req.params.memberName.toLowerCase());
    await project.save();
    res.json({ success: true, members: project.members });
});

app.post('/task', authenticateToken, async (req, res) => {
    const { title, assignedTo, projectId, dueDate } = req.body;
    if (!title || !assignedTo || !projectId) return res.status(400).json({ error: "Missing fields" });
    const project = await Project.findById(projectId);
    if (!project || (!isProjectMember(project, req.user.email) && req.user.role !== 'admin')) {
        return res.status(403).json({ error: "Unauthorized" });
    }
    const task = new Task({
        title: title.trim(),
        assignedTo: assignedTo.trim(),
        projectId,
        dueDate: dueDate ? new Date(dueDate) : undefined
    });
    await task.save();
    res.json(task);
});

app.get('/tasks/:projectId', authenticateToken, async (req, res) => {
    const project = await Project.findById(req.params.projectId);
    if (!project || (!isProjectMember(project, req.user.email) && req.user.role !== 'admin')) {
        return res.status(403).json({ error: "Unauthorized" });
    }
    const tasks = await Task.find({ projectId: req.params.projectId });
    res.json(tasks);
});

app.put('/task/:id', authenticateToken, async (req, res) => {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ error: "Task not found" });
    const project = await Project.findById(task.projectId);
    if (!project || (!isProjectMember(project, req.user.email) && req.user.role !== 'admin')) {
        return res.status(403).json({ error: "Unauthorized" });
    }
    if (req.user.role !== 'admin' && task.assignedTo !== req.user.email) {
        return res.status(403).json({ error: "Not authorized" });
    }
    const updated = await Task.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    res.json(updated);
});

app.delete('/task/:id', authenticateToken, isAdmin, async (req, res) => {
    const task = await Task.findById(req.params.id);
    if (task) {
        const project = await Project.findById(task.projectId);
        if (!project || (!isProjectMember(project, req.user.email) && req.user.role !== 'admin')) {
            return res.status(403).json({ error: "Unauthorized" });
        }
    }
    await Task.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});