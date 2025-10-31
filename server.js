import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.get("/", (req, res) => {
  res.send("Welcome to the Task Management API");
});

const PORT = 5000;
const JWT_SECRET = "supersecretkey";

// ===== In-memory users & tasks =====
let users = [
  { id: 1, email: "admin@test.com", password: bcrypt.hashSync("admin123", 10), firstName: "Admin", role: "admin" },
  { id: 2, email: "user@test.com", password: bcrypt.hashSync("user123", 10), firstName: "User", role: "user" }
];

let tasks = [
  { id: 1, userId: 1, title: "Admin Task", description: "Admin only task", completed: false },
  { id: 2, userId: 2, title: "User Task", description: "Regular user task", completed: false }
];

// ===== Helper: auth middleware =====
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "No token, unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: "Invalid or expired token" });
  }
}

// ===== Helper: role check =====
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ message: "Access denied" });
  next();
}

// ===== Auth Routes =====
app.post("/register", async (req, res) => {
  const { email, password, firstName, role } = req.body;
  if (users.find(u => u.email === email)) return res.status(400).json({ message: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, email, password: hashed, firstName, role: role || "user" };
  users.push(newUser);
  res.json({ message: "Registered successfully", user: { id: newUser.id, email: newUser.email } });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, { httpOnly: true, sameSite: "Strict", secure: false });
  res.json({ message: "Login successful" });
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out successfully" });
});

// ===== Protected Routes =====
app.get("/profile", authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  res.json({ user: { id: user.id, email: user.email, firstName: user.firstName, role: user.role } });
});

app.get("/tasks", authMiddleware, (req, res) => {
  const userTasks = tasks.filter(t => t.userId === req.user.id);
  res.json(userTasks);
});

app.post("/tasks", authMiddleware, (req, res) => {
  const { title, description } = req.body;
  const newTask = { id: tasks.length + 1, userId: req.user.id, title, description, completed: false, createdAt: new Date() };
  tasks.push(newTask);
  res.json({ message: "Task added", task: newTask });
});

app.delete("/tasks/:id", authMiddleware, (req, res) => {
  const taskId = parseInt(req.params.id);
  const task = tasks.find(t => t.id === taskId && t.userId === req.user.id);
  if (!task) return res.status(403).json({ message: "Not authorized or task not found" });
  tasks = tasks.filter(t => t.id !== taskId);
  res.json({ message: "Task deleted" });
});

// ===== Admin Routes =====
app.get("/admin/users", authMiddleware, adminOnly, (req, res) => res.json(users));
app.get("/admin/tasks", authMiddleware, adminOnly, (req, res) => res.json(tasks));

// ===== Server Start =====
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));