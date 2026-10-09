require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 60 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["ADMIN", "USER"], default: "USER" },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

const apiSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  slug: { type: String, required: true, unique: true, trim: true, lowercase: true, maxlength: 80 },
  jsonData: { type: mongoose.Schema.Types.Mixed, required: true },
  published: { type: Boolean, default: false },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  updatedAt: { type: Date, default: Date.now }
});
apiSchema.index({ owner: 1, updatedAt: -1 });
const ApiDocument = mongoose.model("ApiDocument", apiSchema);

app.use(session({
  name: "jsonapi.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-session-secret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/json_api_platform" }),
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.baseUrl = PUBLIC_BASE_URL;
  res.locals.success = req.session.success || null;
  res.locals.error = req.session.error || null;
  delete req.session.success;
  delete req.session.error;
  next();
});

function flash(req, type, message) { req.session[type] = message; }
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "ADMIN") return res.status(403).render("error", { title: "Access denied", message: "Administrator access is required." });
  next();
}
function validSlug(slug) {
  return typeof slug === "string" && /^[a-z0-9][a-z0-9-]{1,79}$/.test(slug);
}
function parseJsonInput(raw) {
  const parsed = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object") throw new Error("JSON must be an object or array.");
  return parsed;
}
function safeReturn(res, path) { return res.redirect(path); }

app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.render("login", { error: null });
});
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
app.post("/login", loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).render("login", { error: "Invalid username or password." });
    }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = { id: String(user._id), username: user.username, role: user.role };
      req.session.save(err2 => err2 ? next(err2) : res.redirect("/dashboard"));
    });
  } catch (err) { next(err); }
});
app.post("/logout", requireLogin, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("jsonapi.sid");
    res.redirect("/login?logout=1");
  });
});

app.get("/", (req, res) => res.redirect(req.session.user ? "/dashboard" : "/login"));

app.get("/dashboard", requireLogin, async (req, res, next) => {
  try {
    const apis = await ApiDocument.find({ owner: req.session.user.id }).sort({ updatedAt: -1 }).lean();
    res.render("dashboard", { apis });
  } catch (err) { next(err); }
});

app.get("/apis/new", requireLogin, (req, res) => {
  res.render("api-form", { pageTitle: "Create API", action: "/apis", api: { name: "", slug: "", jsonText: '[\n  {\n    "id": 1,\n    "name": "Example"\n  }\n]', published: false }, error: null });
});

app.post("/apis", requireLogin, async (req, res, next) => {
  const form = { name: String(req.body.name || "").trim(), slug: String(req.body.slug || "").trim().toLowerCase(), jsonText: String(req.body.jsonText || ""), published: req.body.published === "on" };
  try {
    if (!form.name || form.name.length > 120) throw new Error("Enter an API name (maximum 120 characters).");
    if (!validSlug(form.slug)) throw new Error("Slug must be 2–80 lowercase letters, numbers or hyphens, starting with a letter or number.");
    const jsonData = parseJsonInput(form.jsonText);
    const created = await ApiDocument.create({ name: form.name, slug: form.slug, jsonData, published: form.published, owner: req.session.user.id });
    flash(req, "success", "API created successfully.");
    res.redirect("/dashboard");
  } catch (err) {
    if (err.code === 11000) form.error = "That slug is already in use. Choose another.";
    const message = err.code === 11000 ? "That slug is already in use. Choose another." : err.message;
    res.status(400).render("api-form", { pageTitle: "Create API", action: "/apis", api: form, error: message });
  }
});

app.get("/apis/:id/edit", requireLogin, async (req, res, next) => {
  try {
    const api = await ApiDocument.findOne({ _id: req.params.id, owner: req.session.user.id }).lean();
    if (!api) return res.status(404).render("error", { title: "Not found", message: "API not found." });
    res.render("api-form", { pageTitle: "Edit API", action: `/apis/${api._id}`, api: { ...api, jsonText: JSON.stringify(api.jsonData, null, 2) }, error: null });
  } catch (err) { next(err); }
});

app.post("/apis/:id", requireLogin, async (req, res, next) => {
  const form = { name: String(req.body.name || "").trim(), slug: String(req.body.slug || "").trim().toLowerCase(), jsonText: String(req.body.jsonText || ""), published: req.body.published === "on" };
  try {
    const api = await ApiDocument.findOne({ _id: req.params.id, owner: req.session.user.id });
    if (!api) return res.status(404).render("error", { title: "Not found", message: "API not found." });
    if (!form.name || form.name.length > 120) throw new Error("Enter an API name (maximum 120 characters).");
    if (!validSlug(form.slug)) throw new Error("Slug must be 2–80 lowercase letters, numbers or hyphens, starting with a letter or number.");
    const jsonData = parseJsonInput(form.jsonText);
    api.name = form.name; api.slug = form.slug; api.jsonData = jsonData;
    api.published = form.published; api.updatedAt = new Date();
    await api.save();
    flash(req, "success", "API updated successfully.");
    res.redirect("/dashboard");
  } catch (err) {
    if (err.code === 11000) err.message = "That slug is already in use. Choose another.";
    res.status(400).render("api-form", { pageTitle: "Edit API", action: `/apis/${req.params.id}`, api: { ...form }, error: err.message });
  }
});

app.post("/apis/:id/delete", requireLogin, async (req, res, next) => {
  try {
    const deleted = await ApiDocument.findOneAndDelete({ _id: req.params.id, owner: req.session.user.id });
    if (!deleted) return res.status(404).render("error", { title: "Not found", message: "API not found." });
    flash(req, "success", "API deleted.");
    res.redirect("/dashboard");
  } catch (err) { next(err); }
});

// Public, read-only JSON endpoint. No public POST/PUT/PATCH/DELETE routes.
const publicApiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
app.get("/public-api/:slug", publicApiLimiter, async (req, res, next) => {
  try {
    const api = await ApiDocument.findOne({ slug: req.params.slug.toLowerCase(), published: true }).lean();
    if (!api) return res.status(404).json({ error: "Published API not found" });
    res.set("Cache-Control", "no-store");
    res.type("application/json").send(JSON.stringify(api.jsonData, null, 2));
  } catch (err) { next(err); }
});

// Admin-only account creation; no self-registration route.
app.get("/admin/users", requireLogin, requireAdmin, async (req, res, next) => {
  try {
    const users = await User.find({}, "username role createdAt").sort({ createdAt: -1 }).lean();
    res.render("users", { users, error: null, form: { username: "" } });
  } catch (err) { next(err); }
});
app.post("/admin/users", requireLogin, requireAdmin, async (req, res, next) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  try {
    if (!/^[a-zA-Z0-9_.-]{3,60}$/.test(username)) throw new Error("Username must be 3–60 letters, numbers, dots, underscores or hyphens.");
    if (password.length < 8) throw new Error("Password must be at least 8 characters.");
    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({ username, passwordHash, role: "USER" });
    flash(req, "success", "User created. Share the credentials privately.");
    res.redirect("/admin/users");
  } catch (err) {
    const users = await User.find({}, "username role createdAt").sort({ createdAt: -1 }).lean();
    res.status(400).render("users", { users, form: { username }, error: err.code === 11000 ? "That username already exists." : err.message });
  }
});

// Simple JSON API errors; avoid exposing internal stack traces to clients.
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  if (req.path.startsWith("/public-api/")) return res.status(500).json({ error: "Internal server error" });
  res.status(500).render("error", { title: "Something went wrong", message: "The server could not complete this request." });
});

async function start() {
  const uri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/json_api_platform";
  await mongoose.connect(uri);
  const adminUsername = process.env.ADMIN_USERNAME || "admin";
  const adminPassword = process.env.ADMIN_PASSWORD || "ChangeMe123!";
  const existingAdmin = await User.findOne({ username: adminUsername });
  if (!existingAdmin) {
    await User.create({ username: adminUsername, passwordHash: await bcrypt.hash(adminPassword, 12), role: "ADMIN" });
    console.log(`Initial admin created: ${adminUsername}. Password comes from ADMIN_PASSWORD in .env.`);
  }
  app.listen(PORT, () => console.log(`JSON API Platform running at http://localhost:${PORT}`));
}
start().catch(err => { console.error("Startup failed. Check MongoDB and .env settings.", err.message); process.exit(1); });
