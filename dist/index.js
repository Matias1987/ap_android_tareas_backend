"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const client_1 = require("@prisma/client");
const app = (0, express_1.default)(), db = new client_1.PrismaClient(), secret = process.env.JWT_SECRET;
if (!secret)
    throw new Error("JWT_SECRET es requerido");
app.use((0, cors_1.default)());
app.use(express_1.default.json());
function auth(req, res, next) {
    try {
        const token = (req.headers.authorization || "").replace(/^Bearer\s+/, "");
        if (!token)
            throw new Error("Token ausente");
        const payload = jsonwebtoken_1.default.verify(token, secret);
        if (typeof payload === "string" ||
            typeof payload.id !== "string" ||
            !Object.values(client_1.Role).includes(payload.role))
            throw new Error("Token inválido");
        req.session = payload;
        next();
    }
    catch {
        return res.status(401).json({ error: "Sesión inválida" });
    }
}
function admin(req, res, next) {
    if (req.session?.role !== client_1.Role.ADMIN)
        return res.status(403).json({ error: "Se requiere administrador" });
    next();
}
function overdueWhere() {
    return {
        status: { in: [client_1.TaskStatus.PENDING, client_1.TaskStatus.IN_PROGRESS] },
        dueAt: { lt: new Date() },
    };
}
app.get("/health", (_req, res) => res.json({ ok: true }));
app.post("/auth/login", async (req, res) => {
    const user = await db.user.findUnique({
        where: { email: String(req.body.email || "").toLowerCase() },
    });
    if (!user ||
        !user.active ||
        !(await bcryptjs_1.default.compare(String(req.body.password || ""), user.passwordHash)))
        return res.status(401).json({ error: "Credenciales inválidas" });
    const token = jsonwebtoken_1.default.sign({ id: user.id, role: user.role }, secret, {
        expiresIn: "12h",
    });
    res.json({
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
});
app.get("/tasks", auth, async (req, res) => {
    const u = req.session;
    const where = u.role === client_1.Role.ADMIN ? {} : { assignments: { some: { userId: u.id } } };
    if (req.query.status === "OVERDUE")
        Object.assign(where, overdueWhere());
    else if (req.query.status)
        where.status = String(req.query.status);
    const tasks = await db.task.findMany({
        where,
        include: {
            creator: { select: { id: true, name: true } },
            assignments: { include: { user: { select: { id: true, name: true } } } },
        },
        orderBy: { dueAt: "asc" },
    });
    res.json(tasks.map((t) => t.dueAt &&
        t.dueAt < new Date() &&
        (t.status === client_1.TaskStatus.PENDING || t.status === client_1.TaskStatus.IN_PROGRESS)
        ? { ...t, status: client_1.TaskStatus.OVERDUE }
        : t));
});
app.post("/tasks", auth, admin, async (req, res) => {
    const { title, description = "", priority = "NORMAL", dueAt, assigneeIds = [], } = req.body;
    if (!title)
        return res.status(400).json({ error: "El título es obligatorio" });
    const task = await db.task.create({
        data: {
            title,
            description,
            priority: priority,
            dueAt: dueAt ? new Date(dueAt) : null,
            creatorId: req.session.id,
            assignments: {
                create: assigneeIds.map((userId) => ({ userId })),
            },
        },
        include: { assignments: true },
    });
    await db.activity.create({
        data: {
            action: "TASK_CREATED",
            actorId: req.session.id,
            taskId: task.id,
        },
    });
    res.status(201).json(task);
});
app.patch("/tasks/:id", auth, async (req, res) => {
    const u = req.session;
    const task = await db.task.findUnique({
        where: { id: req.params.id },
        include: { assignments: true },
    });
    if (!task)
        return res.sendStatus(404);
    if (u.role !== client_1.Role.ADMIN && !task.assignments.some((a) => a.userId === u.id))
        return res.sendStatus(403);
    const allowed = u.role === client_1.Role.ADMIN ? req.body : { status: req.body.status };
    const completedAt = allowed.status === client_1.TaskStatus.COMPLETED
        ? new Date()
        : allowed.status && allowed.status !== client_1.TaskStatus.COMPLETED
            ? null
            : undefined;
    const updated = await db.task.update({
        where: { id: task.id },
        data: { ...allowed, completedAt },
    });
    await db.activity.create({
        data: {
            action: "TASK_UPDATED",
            actorId: u.id,
            taskId: task.id,
            details: JSON.stringify(allowed),
        },
    });
    res.json(updated);
});
app.delete("/tasks/:id", auth, admin, async (req, res) => {
    await db.task.update({
        where: { id: req.params.id },
        data: { status: client_1.TaskStatus.CANCELLED },
    });
    await db.activity.create({
        data: {
            action: "TASK_CANCELLED",
            actorId: req.session.id,
            taskId: req.params.id,
        },
    });
    res.sendStatus(204);
});
app.get("/users", auth, admin, async (_req, res) => res.json(await db.user.findMany({
    select: {
        id: true,
        name: true,
        email: true,
        role: true,
        active: true,
        createdAt: true,
    },
    orderBy: { name: "asc" },
})));
app.post("/users", auth, admin, async (req, res) => {
    const { name, email, password, role = "USER" } = req.body;
    if (!name || !email || !password)
        return res
            .status(400)
            .json({ error: "Nombre, email y contraseña son obligatorios" });
    const user = await db.user.create({
        data: {
            name,
            email: String(email).toLowerCase(),
            passwordHash: await bcryptjs_1.default.hash(password, 12),
            role,
        },
    });
    res
        .status(201)
        .json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
    });
});
app.patch("/users/:id", auth, admin, async (req, res) => {
    const { password, ...data } = req.body;
    const user = await db.user.update({
        where: { id: req.params.id },
        data: {
            ...data,
            ...(password ? { passwordHash: await bcryptjs_1.default.hash(password, 12) } : {}),
        },
    });
    res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
    });
});
app.get("/activity", auth, admin, async (_req, res) => res.json(await db.activity.findMany({
    include: { task: { select: { id: true, title: true } } },
    orderBy: { createdAt: "desc" },
    take: 200,
})));
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`OpDelSol API en puerto ${port}`));
