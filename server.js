
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const crypto = require("crypto");
const path = require("path");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: "12mb" }));
app.use(express.static(path.join(__dirname, "public")));

const URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

async function db(table, options = {}) {
  if (!URL || !KEY) throw Error("Supabase environment variables missing");

  const response = await fetch(
    `${URL}/rest/v1/${table}${options.query ? "?" + options.query : ""}`,
    {
      method: options.method || "GET",
      headers: {
        apikey: KEY,
        Authorization: `Bearer ${KEY}`,
        "Content-Type": "application/json",
        Prefer: options.prefer || "return=representation"
      },
      ...(options.body !== undefined
        ? { body: JSON.stringify(options.body) }
        : {})
    }
  );

  const text = await response.text();
  let data = text ? JSON.parse(text) : null;

  if (!response.ok) {
    console.error("Supabase error:", data);
    throw Error(data?.message || `Supabase HTTP ${response.status}`);
  }

  return data;
}

const clean = v => String(v ?? "").trim();
const enc = v => encodeURIComponent(String(v));
const validUsername = u => /^[A-Za-z0-9_.-]{3,32}$/.test(u);

const send = (ws, data) => {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
};

const online = username =>
  [...wss.clients].some(c =>
    c.username === username && c.readyState === WebSocket.OPEN
  );

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt:${salt}:${hash}`;
}

function checkPassword(password, stored) {
  try {
    const [scheme, salt, hash] = stored.split(":");
    if (scheme !== "scrypt") return false;
    const actual = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(hash, "hex");
    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function users() {
  return await db("users", {
    query: "select=username,display_name,bio,avatar&order=created_at.asc"
  }) || [];
}

function publicUser(u) {
  return {
    username: u.username,
    name: u.display_name || u.username,
    bio: u.bio || "",
    avatar: u.avatar || "",
    online: online(u.username)
  };
}

async function broadcastUsers() {
  try {
    const list = (await users()).map(publicUser);
    wss.clients.forEach(c => send(c, { type: "users", users: list }));
  } catch (e) {
    console.error("Users broadcast:", e.message);
  }
}

app.get("/api/health", async (req, res) => {
  try {
    await db("users", { query: "select=username&limit=1" });
    await db("messages", { query: "select=id&limit=1" });
    res.json({ ok: true, database: "supabase", connected: true });
  } catch (e) {
    res.status(503).json({
      ok: false,
      database: "supabase",
      connected: false,
      error: e.message
    });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    res.json((await users()).map(publicUser));
  } catch (e) {
    console.error(e);
    res.status(503).json({ error: "خطا در اتصال به دیتابیس کاربران." });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const username = clean(req.body.username);
    const password = String(req.body.password || "");

    if (!validUsername(username)) {
      return res.json({ error: "نام کاربری باید ۳ تا ۳۲ کاراکتر انگلیسی باشد." });
    }

    if (password.length < 4) {
      return res.json({ error: "رمز حداقل ۴ کاراکتر باشد." });
    }

    const existing = await db("users", {
      query: `select=username&username=ilike.${enc(username)}&limit=1`
    });

    if (existing.length) {
      return res.json({ error: "این نام کاربری وجود دارد." });
    }

    await db("users", {
      method: "POST",
      body: {
        username,
        password_hash: hashPassword(password),
        display_name: username,
        bio: "",
        avatar: ""
      }
    });

    res.json({ success: true, username });
    broadcastUsers();
  } catch (e) {
    console.error("Register:", e.message);
    res.status(503).json({
      error: "ثبت‌نام ناموفق بود. تنظیمات Supabase و جدول users را بررسی کن."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = clean(req.body.username);
    const password = String(req.body.password || "");

    const rows = await db("users", {
      query: `select=username,password_hash&username=ilike.${enc(username)}&limit=1`
    });

    const user = rows[0];

    if (!user || !checkPassword(password, user.password_hash)) {
      return res.json({ error: "نام کاربری یا رمز اشتباه است." });
    }

    res.json({ success: true, username: user.username });
  } catch (e) {
    console.error("Login:", e.message);
    res.status(503).json({ error: "ورود انجام نشد؛ اتصال دیتابیس را بررسی کن." });
  }
});

app.get("/api/messages", async (req, res) => {
  try {
    const a = clean(req.query.a);
    const b = clean(req.query.b);

    if (!a || !b) return res.json([]);

    const query =
      "select=id,sender_username,receiver_username,message_text,image_data,audio_data,reactions,created_at,is_read" +
      `&or=(and(sender_username.eq.${enc(a)},receiver_username.eq.${enc(b)}),and(sender_username.eq.${enc(b)},receiver_username.eq.${enc(a)}))` +
      "&order=created_at.asc&limit=500";

    const rows = await db("messages", { query });

    res.json(rows.map(m => ({
      id: m.id,
      from: m.sender_username,
      to: m.receiver_username,
      text: m.message_text || "",
      image: m.image_data || "",
      audio: m.audio_data || "",
      reactions: m.reactions || {},
      time: m.created_at,
      read: !!m.is_read
    })));
  } catch (e) {
    console.error("Messages:", e.message);
    res.status(503).json({ error: "دریافت پیام‌ها ناموفق بود." });
  }
});

app.post("/api/messages", async (req, res) => {
  try {
    const from = clean(req.body.from);
    const to = clean(req.body.to);
    const text = clean(req.body.text);
    const image = String(req.body.image || "");
    const audio = String(req.body.audio || "");

    if (!from || !to) return res.json({ error: "مخاطب انتخاب نشده." });
    if (!text && !image && !audio) return res.json({ error: "پیام خالی است." });
    if (image.length > 3000000) return res.json({ error: "عکس خیلی بزرگ است." });
    if (audio.length > 8000000) return res.json({ error: "ویس خیلی بزرگ است." });

    const found = await db("users", {
      query: `select=username&or=(username.eq.${enc(from)},username.eq.${enc(to)})`
    });

    const names = new Set(found.map(u => u.username));
    if (!names.has(from)) return res.json({ error: "فرستنده پیدا نشد." });
    if (!names.has(to)) return res.json({ error: "مخاطب پیدا نشد." });

    const inserted = await db("messages", {
      method: "POST",
      body: {
        id: Date.now().toString(36) + crypto.randomBytes(8).toString("hex"),
        sender_username: from,
        receiver_username: to,
        message_text: text,
        image_data: image,
        audio_data: audio,
        reactions: {},
        is_read: false
      }
    });

    const m = inserted[0];
    const message = {
      id: m.id,
      from: m.sender_username,
      to: m.receiver_username,
      text: m.message_text || "",
      image: m.image_data || "",
      audio: m.audio_data || "",
      reactions: m.reactions || {},
      time: m.created_at,
      read: !!m.is_read
    };

    wss.clients.forEach(c => {
      if (c.username === from || c.username === to) {
        send(c, { type: "message", message });
      }
    });

    res.json({ success: true, message });
  } catch (e) {
    console.error("Send message:", e.message);
    res.status(503).json({ error: "ذخیره پیام ناموفق بود." });
  }
});

app.post("/api/read", async (req, res) => {
  try {
    const from = clean(req.body.from);
    const to = clean(req.body.to);

    await db("messages", {
      method: "PATCH",
      query: `sender_username=eq.${enc(from)}&receiver_username=eq.${enc(to)}`,
      body: { is_read: true },
      prefer: "return=minimal"
    });

    res.json({ success: true });
    wss.clients.forEach(c => send(c, { type: "read", from, to }));
  } catch (e) {
    console.error(e);
    res.status(503).json({ error: "ذخیره وضعیت خوانده‌شدن ناموفق بود." });
  }
});

app.post("/api/react", async (req, res) => {
  try {
    const id = clean(req.body.id);
    const emoji = String(req.body.emoji || "");
    const username = clean(req.body.username);

    const rows = await db("messages", {
      query: `select=id,reactions&id=eq.${enc(id)}&limit=1`
    });

    if (!rows.length) return res.json({ error: "پیام پیدا نشد." });

    const reactions = rows[0].reactions || {};

    for (const key of Object.keys(reactions)) {
      reactions[key] = (reactions[key] || []).filter(u => u !== username);
      if (!reactions[key].length) delete reactions[key];
    }

    if (emoji && emoji !== "none") {
      reactions[emoji] = reactions[emoji] || [];
      if (!reactions[emoji].includes(username)) reactions[emoji].push(username);
    }

    await db("messages", {
      method: "PATCH",
      query: `id=eq.${enc(id)}`,
      body: { reactions },
      prefer: "return=minimal"
    });

    res.json({ success: true });
    wss.clients.forEach(c => send(c, { type: "reaction", id, reactions }));
  } catch (e) {
    console.error(e);
    res.status(503).json({ error: "ذخیره واکنش ناموفق بود." });
  }
});

app.get("/api/profile", async (req, res) => {
  try {
    const username = clean(req.query.username);
    const rows = await db("users", {
      query: `select=username,display_name,bio,avatar&username=eq.${enc(username)}&limit=1`
    });

    const u = rows[0];
    if (!u) return res.status(404).json({ error: "کاربر پیدا نشد." });

    res.json({
      username: u.username,
      name: u.display_name || u.username,
      bio: u.bio || "",
      avatar: u.avatar || ""
    });
  } catch (e) {
    console.error(e);
    res.status(503).json({ error: "دریافت پروفایل ناموفق بود." });
  }
});

app.post("/api/profile", async (req, res) => {
  try {
    const username = clean(req.body.username);
    const name = clean(req.body.name);
    const bio = String(req.body.bio || "").slice(0, 200);
    const avatar = String(req.body.avatar || "");

    if (avatar.length > 1800000) return res.json({ error: "عکس خیلی بزرگ است." });

    const rows = await db("users", {
      method: "PATCH",
      query: `username=eq.${enc(username)}`,
      body: { display_name: name || username, bio, avatar }
    });

    res.json({ success: true });
    broadcastUsers();
  } catch (e) {
    console.error(e);
    res.status(503).json({ error: "ذخیره پروفایل ناموفق بود." });
  }
});

wss.on("connection", ws => {
  ws.on("message", async raw => {
    try {
      const data = JSON.parse(raw);
      if (data.type !== "auth") return;

      const username = clean(data.username);
      const rows = await db("users", {
        query: `select=username&username=eq.${enc(username)}&limit=1`
      });

      if (!rows.length) return;
      ws.username = rows[0].username;
      broadcastUsers();
    } catch (e) {
      console.error("WebSocket:", e.message);
    }
  });

  ws.on("close", broadcastUsers);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Karen Messenger V4.1.1 listening on ${PORT}`);
  if (!URL || !KEY) console.error("Supabase environment variables missing!");
});
