import dotenv from "dotenv";
dotenv.config();
console.log({
  MONGO_URI: !!process.env.MONGO_URI,
  JWT_SECRET: !!process.env.JWT_SECRET,
  GROQ_API_KEY: !!process.env.GROQ_API_KEY,
});

import express from "express";
import mongoose from "mongoose";
import path from "path";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import Groq from "groq-sdk";

const app = express();
const __dirname = path.resolve();

const {
  MONGO_URI,
  JWT_SECRET,
  GROQ_API_KEY,
  PORT = 3000,
} = process.env;

if (!MONGO_URI || !JWT_SECRET || !GROQ_API_KEY) {
  console.error("❌ Missing environment variables");
  process.exit(1);
}

const groq = new Groq({
  apiKey: GROQ_API_KEY,
});

/*   MIDDLEWARE*/
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/*  DATABASE */
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error:", err);
    process.exit(1);
  });

/* schema for signup*/
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  college_name: String,
  course: String,
  password: String,
});

/* schema for assessment*/
const AssessmentSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  answers: Object,
  roadmapDuration: Number,
  aiAnalysis: String,
  createdAt: { type: Date, default: Date.now },
});


const User = mongoose.model("User", UserSchema);
const Assessment = mongoose.model("Assessment", AssessmentSchema);


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
    return res.redirect("/");
  }
}

function compactAnswers(obj) {
  return Object.entries(obj)
    .filter(([_, v]) => v && String(v).trim() !== "")
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

/* get login*/
app.get("/", (req, res) => res.render("login", { error: null }));


/* get signup*/
app.get("/signup", (req, res) => res.render("signup", { error: null }));

/* post signup */
app.post("/signup", async (req, res) => {
  const { name, email, phone, college_name, course, password } = req.body;

  try {
    if (await User.findOne({ email }))
      return res.render("signup", { error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      phone,
      college_name,
      course,
      password: hashed,
    });

    res.cookie("token", signToken(user), { httpOnly: true });
    res.redirect("/dashboard");
  } catch {
    res.render("signup", { error: "Signup failed" });
  }
});

/* post */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.render("login", { error: "User not found" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.render("login", { error: "Wrong password" });

    res.cookie("token", signToken(user), { httpOnly: true });
    res.redirect("/dashboard");
  } catch {
    res.render("login", { error: "Login error" });
  }
});

/*  DASHBOARD */
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

/*  ASSESSMENT */
app.get("/assessment", isAuthenticated, (req, res) => {
  res.render("assessment");
});
app.post("/assessment", isAuthenticated, async (req, res) => {
  try {
    const { roadmapDuration, ...answers } = req.body;

    if (!roadmapDuration) {
      return res.render("assessment-result", {
        analysis: "⚠ Please select a roadmap duration.",
      });
    }
    const compacted = Object.entries(answers)   //it is used to trim the answer in array format basically its makes the answer compactAnswers and convert it like key-value format..and remove the empty answers then convert it to string
      .filter(([_, v]) => v && String(v).trim() !== "")
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");

    if (!compacted) {
      return res.render("assessment-result", {
        analysis: "⚠ Please answer at least one question.",
      });
    }
    const prompt = `
You are a career guidance AI.

User wants a ${roadmapDuration}-month career roadmap.

TASK:
- Analyze the user's answers
- Suggest suitable careers
- Create a roadmap strictly for ${roadmapDuration} months
- Use simple language
- No emojis
- No markdown symbols

STRUCTURE YOUR RESPONSE LIKE THIS:

PERSONALITY SUMMARY
(2–3 lines)

STRENGTHS
- point 1
- point 2

WEAK AREAS
- point 1
- point 2

SOME PROJECTS IDEAS ACCORDING TO USER PROFILE
1. Project name – short description
2. Project name – short description
3. Project name – short description

CAREER OPTIONS
1. Career name – short reason
2. Career name – short reason
3. Career name – short reason

${roadmapDuration}-MONTH ROADMAP
Split into phases with:
- Time period
- What to learn
- What to practice

FINAL ADVICE
2–3 motivating lines.

User Answers:
${compacted}
`;

  
    const completion = await groq.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
    });

    const analysis =
      completion.choices[0]?.message?.content ||
      "AI could not generate a response.";


    await Assessment.create({
      userId: req.user._id,
      answers,
      roadmapDuration: Number(roadmapDuration),
      aiAnalysis: analysis,
    });

    
    res.render("assessment-result", { analysis });

  } catch (err) {
    console.error("Assessment Error:", err);
    res.render("assessment-result", {
      analysis: "⚠ AI failed. Please try again later.",
    });
  }
});


/*  LOGOUT  */
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

/*  SERVER*/
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
}); 