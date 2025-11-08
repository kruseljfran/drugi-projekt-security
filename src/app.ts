import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import path from "path";
import dotenv from "dotenv";
import { pool } from "./db";

dotenv.config();

declare module "express-session" {
  interface SessionData {
    xssvuln?: boolean;
    csrfvuln?: boolean;
    user?: string;
    role?: string;
    csrfToken?: string;
    email?: string;
  }
}

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

app.use(
  session({
    secret: process.env.SECRET_KEY || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      // omogucava ranjivost
      httpOnly: false,
      secure: false,
      sameSite: "lax"
    },
  })
);

// session memory za komentare
type Comment = { id: number; author: string; text: string };
const comments: Comment[] = [];
let nextCommentId = 1;

// ukljucivanje i iskljucivanje
app.use((req: Request, res: Response, next: NextFunction) => {
  if (typeof req.session.xssvuln === "undefined") req.session.xssvuln = true;
  if (typeof req.session.csrfvuln === "undefined") req.session.csrfvuln = true;
  next();
});

app.get("/", (req: Request, res: Response) => {

  res.render("index", {
    xssvuln: req.session.xssvuln,
    csrfvuln: req.session.csrfvuln,
    user: req.session.user,
  });
});

app.post("/toggle", (req: Request, res: Response) => {
  req.session.xssvuln = req.body.xssvuln === "on";
  req.session.csrfvuln = req.body.csrfvuln === "on";
  if (!req.session.csrfvuln && !req.session.csrfToken) {
    req.session.csrfToken = Math.random().toString(36).slice(2);
  }
  res.redirect("/");
});

// ociti komentare
app.post("/clear-comments", (req: Request, res: Response) => {
  comments.length = 0; // isprazni komentare
  nextCommentId = 1;
  res.clearCookie("insecure_demo");
  res.redirect("/");
});

app.get("/login", (req: Request, res: Response) => {
  res.render("login", { message: "" });
});

app.post("/login", async (req: Request, res: Response) => {
  const { username = "", password = "" } = req.body;
  try {
    const q = "SELECT username, role FROM users WHERE username = $1 AND password = $2 LIMIT 1";
    const r = await pool.query(q, [username, password]);
    const user = r.rows[0];
    if (user) {
      req.session.user = user.username;
      req.session.role = user.role;
      // postavi email od session username u session memory
      if (!req.session.email) req.session.email = `${user.username}@example.com`;
      res.render("login_result", { user: user.username });
    } else {
      res.render("login", { message: "Login failed" });
    }
  } catch (e) {
    console.error("Login error:", e);
    res.render("login", { message: "Error during login" });
  }
});

app.get("/logout", (req: Request, res: Response) => {
  res.clearCookie("insecure_demo");
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// XSS stored
app.get("/comments", (req: Request, res: Response) => {
  res.render("comments", {
    comments,
    xssvuln: req.session.xssvuln,
    user: req.session.user || "anonymous",
  });
});

app.post("/comments", (req: Request, res: Response) => {
  const author = req.session.user || req.body.author || "anon";
  const text = req.body.text || "";
  comments.push({ id: nextCommentId++, author, text });
  res.redirect("/comments");
});

// CSRF
app.get("/profile", (req: Request, res: Response) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  if (!req.session.csrfvuln) {
    if (!req.session.csrfToken) {
      req.session.csrfToken = Math.random().toString(36).slice(2);
    }
  }

  res.render("profile", {
    user: req.session.user,
    email: req.session.email || "user@example.com",
    csrfvuln: req.session.csrfvuln,
    csrfToken: req.session.csrfToken || "",
  });
});

app.post("/change-email", (req: Request, res: Response) => {
  if (!req.session.user) return res.status(401).send("Login required");

  const csrfvuln = req.session.csrfvuln;
  if (!csrfvuln) {
    // siguran, treba token
    const token = req.body.csrfToken;
    if (!token || token !== req.session.csrfToken) {
      return res.status(403).send("Invalid CSRF token");
    }
  }
const newEmail = req.body.email || "";
req.session.email = newEmail;

const nextUrl = typeof req.body.next === "string" ? req.body.next : "";
if (nextUrl && nextUrl.startsWith("/")) {
  return res.redirect(nextUrl);
}

res.redirect("/profile");
});

app.get("/attacker", (req: Request, res: Response) => {
  res.render("attacker");
});

const port = parseInt(process.env.PORT || "5000");
app.listen(port, () => {
  console.log(`Listening on http://localhost:${port} (port ${port})`);
});
