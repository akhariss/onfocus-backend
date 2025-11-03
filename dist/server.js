// src/server.ts
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import z from 'zod';
dotenv.config();
const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'onfocus-secret';
app.use(cors());
app.use(express.json());
// === AUTH ===
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
});
app.post('/api/v1/auth/register', async (req, res) => {
    try {
        const { email, password } = registerSchema.parse(req.body);
        const hashed = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({ data: { email, password: hashed } });
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token });
    }
    catch (e) {
        res.status(400).json({ error: e.message });
    }
});
app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { email, password } = registerSchema.parse(req.body);
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token });
    }
    catch (e) {
        res.status(400).json({ error: e.message });
    }
});
// === TASKS ===
app.get('/api/v1/tasks', async (req, res) => {
    // TODO: tambahkan auth middleware di versi lengkap
    const tasks = await prisma.task.findMany();
    res.json(tasks);
});
app.post('/api/v1/tasks', async (req, res) => {
    const { title, deadline, priority = 'medium', estimatedSessions = 1 } = req.body;
    const task = await prisma.task.create({
        data: {
            userId: 'temp-user-id', // nanti ganti pakai auth
            title,
            deadline: deadline ? new Date(deadline) : null,
            priority,
            estimatedSessions,
        },
    });
    res.status(201).json(task);
});
// === JALANKAN SERVER ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Server jalan di http://localhost:${PORT}`);
});
