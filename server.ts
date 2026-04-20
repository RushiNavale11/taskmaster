import express from 'express';
import cors from 'cors';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const MONGODB_URI = process.env.MONGODB_URI;

// --- MongoDB Schemas ---
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });

const TaskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String, default: '' },
  status: { type: String, enum: ['Pending', 'In-Progress', 'Completed'], default: 'Pending' },
}, { timestamps: true });

const UserModel = mongoose.models.User || mongoose.model('User', UserSchema);
const TaskModel = mongoose.models.Task || mongoose.model('Task', TaskSchema);

async function connectToDatabase() {
  if (!MONGODB_URI) {
    console.warn('⚠️ MONGODB_URI is not defined. Application will fail on database operations.');
    return;
  }
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
  }
}

async function startServer() {
  await connectToDatabase();
  
  const app = express();
  app.use(cors());
  app.use(express.json());

  // --- Auth Middleware ---
  const authenticate = (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });
    
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Invalid token' });
    }
  };

  // --- AUTH ROUTES ---
  app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

    try {
      const existingUser = await UserModel.findOne({ username });
      if (existingUser) return res.status(409).json({ error: 'User already exists' });

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new UserModel({ username, password: hashedPassword });
      await newUser.save();

      const token = jwt.sign({ id: newUser._id, username: newUser.username }, JWT_SECRET);
      res.json({ token, user: { id: newUser._id, username: newUser.username } });
    } catch (err: any) {
      res.status(500).json({ error: 'Server error during registration' });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
      const user = await UserModel.findOne({ username });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
      res.json({ token, user: { id: user._id, username: user.username } });
    } catch (err) {
      res.status(500).json({ error: 'Server error during login' });
    }
  });

  // --- TASK ROUTES ---
  app.get('/api/tasks', authenticate, async (req: any, res) => {
    try {
      const filter: any = { userId: req.user.id };
      if (req.query.status) filter.status = req.query.status;

      const sortBy = (req.query.sortBy as string) || 'createdAt';
      const order = sortBy === 'title' ? 1 : -1;
      
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 5;
      const skip = (page - 1) * limit;

      const tasks = await TaskModel.find(filter)
        .sort({ [sortBy]: order })
        .skip(skip)
        .limit(limit);

      const total = await TaskModel.countDocuments(filter);

      // Map _id to id for frontend compatibility
      const mappedTasks = tasks.map((t: any) => ({
        ...t.toObject(),
        id: t._id.toString()
      }));

      res.json({ tasks: mappedTasks, total, page, limit });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch tasks' });
    }
  });

  app.post('/api/tasks', authenticate, async (req: any, res) => {
    const { title, description, status } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    try {
      const newTask = new TaskModel({
        userId: req.user.id,
        title,
        description: description || '',
        status: status || 'Pending'
      });
      await newTask.save();
      res.json({ ...newTask.toObject(), id: newTask._id.toString() });
    } catch (err) {
      res.status(500).json({ error: 'Failed to create task' });
    }
  });

  app.put('/api/tasks/:id', authenticate, async (req: any, res) => {
    const { id } = req.params;
    const { title, description, status } = req.body;
    
    try {
      const task = await TaskModel.findOneAndUpdate(
        { _id: id, userId: req.user.id },
        { $set: { ...(title && { title }), ...(description !== undefined && { description }), ...(status && { status }) } },
        { new: true }
      );
      
      if (!task) return res.status(404).json({ error: 'Task not found' });
      res.json({ ...task.toObject(), id: task._id.toString() });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update task' });
    }
  });

  app.delete('/api/tasks/:id', authenticate, async (req: any, res) => {
    const { id } = req.params;
    try {
      const result = await TaskModel.findOneAndDelete({ _id: id, userId: req.user.id });
      if (!result) return res.status(404).json({ error: 'Task not found' });
      res.status(204).end();
    } catch (err) {
      res.status(500).json({ error: 'Failed to delete task' });
    }
  });

  // --- VITE MIDDLEWARE ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server started on http://localhost:${PORT}`);
  });
}

startServer();
