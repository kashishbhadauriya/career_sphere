import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Groq from "groq-sdk";

// Robust path resolution for ES Modules on Vercel
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

/* ================= ENV ================= */
const {
  MONGO_URI,
  JWT_SECRET,
  GROQ_API_KEY,
  PORT = 3000,
  NODE_ENV = "development",
} = process.env;

if (!MONGO_URI || !JWT_SECRET || !GROQ_API_KEY) {
  console.error("❌ Missing environment variables");
  process.exit(1);
}

/* ================= AI ================= */
const groq = new Groq({ apiKey: GROQ_API_KEY });

/* ================= SECURITY ================= */
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/login", authLimiter);
app.use("/signup", authLimiter);

/* ================= MIDDLEWARE ================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* ================= DATABASE ================= */
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err);
    process.exit(1);
  });

/* ================= MODELS ================= */
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  college_name: String,
  course: String,
  password: String,
});

const AssessmentSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  answers: Object,
  roadmapDuration: Number,
  aiAnalysis: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Assessment = mongoose.model("Assessment", AssessmentSchema);

/* ================= AUTH HELPERS ================= */
function signToken(user) {
  return jwt.sign(
    { _id: user._id, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function isAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/");

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie("token");
    return res.redirect("/");
  }
}

/* ================= ROUTES ================= */

/* Login */
app.get("/", (req, res) => {
  res.render("login", { error: null });
});

/* Signup */
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, college_name, course, password } = req.body;

    if (await User.findOne({ email })) {
      return res.render("signup", { error: "Email already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      phone,
      college_name,
      course,
      password: hashed,
    });

    res.cookie("token", signToken(user), {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.redirect("/dashboard");
  } catch {
    res.render("signup", { error: "Signup failed" });
  }
});

/* Login POST */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.render("login", { error: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.render("login", { error: "Wrong password" });

    res.cookie("token", signToken(user), {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.redirect("/dashboard");
  } catch {
    res.render("login", { error: "Login error" });
  }
});

/* Dashboard */
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

/* Assessment */
app.get("/assessment", isAuthenticated, (req, res) => {
  res.render("assessment");
});

app.post("/assessment", isAuthenticated, async (req, res) => {
  try {
    const { roadmapDuration, ...answers } = req.body;

    if (!roadmapDuration) {
      return res.render("assessment-result", {
        analysis: "Please select roadmap duration.",
      });
    }

    const compacted = Object.entries(answers)
      .filter(([_, v]) => v && String(v).trim() !== "")
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");

    if (!compacted) {
      return res.render("assessment-result", {
        analysis: "Please answer at least one question.",
      });
    }

    const prompt = `
You are an expert career mentor.
Based on the user's answers, create a clear, practical, and actionable ${roadmapDuration}-month career roadmap.
IMPORTANT RULES:
- Use simple and professional language.
- Do not use emojis.
- Do not use markdown formatting.
- Keep points short and practical.
- Make every month action-based.
- Avoid long paragraphs.

Format your response EXACTLY in this structure:
CAREER DIRECTION:
2-3 lines explaining recommended career path.
STRENGTHS:
- Point 1
- Point 2
- Point 3
IMPROVEMENT AREAS:
- Point 1
- Point 2
- Point 3
MONTHLY ACTION PLAN:
Month 1:
- Task 1
- Task 2
- Task 3
(Continue until ${roadmapDuration} months)
KEY PROJECTS TO BUILD:
Project 1:
Name:
What it does:Tech Stack:Why it matters:
CERTIFICATIONS TO CONSIDER:
- Certification 1
SKILLS TO FOCUS ON:
Technical:
- Skill 1
Soft Skills:
- Skill 1
INTERNSHIP STRATEGY:
- Step 1
FINAL ADVICE:
Short and realistic career advice.
User Answers:
${compacted}
`;
    const completion = await groq.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
    });

    const analysis = completion.choices[0]?.message?.content || "AI could not generate a response.";

    await Assessment.create({
      userId: req.user._id,
      answers,
      roadmapDuration: Number(roadmapDuration),
      aiAnalysis: analysis,
    });

    res.render("assessment-result", { analysis });
  } catch (err) {
    console.error("Assessment error:", err);
    res.render("assessment-result", {
      analysis: "AI failed. Please try again later.",
    });
  }
});

/* Resume Builder Form */
app.get("/resume", isAuthenticated, (req, res) => {
  res.render("resume");
});

/* Generate and Display Resume */
app.post("/generateresume", isAuthenticated, (req, res) => {
  // Ensure 'resume' is never undefined even if the body is empty
  const resumeData = req.body || {}; 
  res.render("generateresume", { resume: resumeData });
});

/* Logout */
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

/* ================= SERVER ================= */
if (NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`🚀 Local Server running on port ${PORT}`);
  });
}

export default app;
