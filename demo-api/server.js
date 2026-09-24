// Sandboxed demo target for SentinelAPI.
// Contains DELIBERATELY seeded vulnerabilities so the scanner has something to find,
// alongside a few correctly-secured endpoints that act as false-positive controls.
//
// SAFETY: bind to localhost only, never expose this process publicly.

import express from "express";
import { users, orders, documents } from "./data.js";

const app = express();
app.use(express.json());

const HOST = "127.0.0.1";
const PORT = process.env.PORT || 4000;

// --- auth helpers -----------------------------------------------------------
function userFromToken(req) {
  const auth = req.header("authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  return users.find((u) => u.apiToken === token) || null;
}

function requireAuth(req, res, next) {
  const user = userFromToken(req);
  if (!user) return res.status(401).json({ error: "unauthorized" });
  req.user = user;
  next();
}

// --- auth endpoints ---------------------------------------------------------

// SEEDED FLAW: no rate limiting on login — allows unlimited credential guessing.
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  res.json({ token: user.apiToken });
});

// --- orders -----------------------------------------------------------------

// SEEDED FLAW (BOLA / IDOR): returns any order by id without checking ownership.
// Also leaks the full card number (excessive data exposure).
app.get("/orders/:id", requireAuth, (req, res) => {
  const order = orders.find((o) => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ error: "not found" });
  res.json(order);
});

// CONTROL (secure): correctly scopes the list to the caller.
app.get("/my/orders", requireAuth, (req, res) => {
  const mine = orders
    .filter((o) => o.ownerId === req.user.id)
    .map(({ card, ...safe }) => safe);
  res.json(mine);
});

// --- users ------------------------------------------------------------------

// SEEDED FLAW (excessive data exposure): returns password, ssn and apiToken.
app.get("/users/:id", requireAuth, (req, res) => {
  const user = users.find((u) => u.id === Number(req.params.id));
  if (!user) return res.status(404).json({ error: "not found" });
  res.json(user);
});

// CONTROL (secure): returns a whitelisted, non-sensitive projection.
app.get("/profile", requireAuth, (req, res) => {
  const { id, username, email, role } = req.user;
  res.json({ id, username, email, role });
});

// --- documents --------------------------------------------------------------

// SEEDED FLAW (missing auth): no requireAuth middleware — anyone can read any doc.
app.get("/documents/:id", (req, res) => {
  const doc = documents.find((d) => d.id === req.params.id);
  if (!doc) return res.status(404).json({ error: "not found" });
  res.json(doc);
});

// --- health -----------------------------------------------------------------
app.get("/health", (req, res) => res.json({ status: "ok" }));

app.listen(PORT, HOST, () => {
  console.log(`[demo-api] sandboxed vulnerable target on http://${HOST}:${PORT}`);
  console.log(`[demo-api] seeded logins: alice/alice-password, bob/bob-password, admin/admin-password`);
});
