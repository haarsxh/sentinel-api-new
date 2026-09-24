// Minimal static server for the findings dashboard (no dependencies).
// Serves report/index.html and report/data/*.json.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, extname, normalize } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 4100;
const TYPES = { ".html": "text/html", ".json": "application/json", ".js": "text/javascript", ".css": "text/css" };

const server = createServer(async (req, res) => {
  let rel = decodeURIComponent(req.url.split("?")[0]);
  if (rel === "/") rel = "/index.html";
  const filePath = resolve(ROOT, "." + normalize(rel));
  if (!filePath.startsWith(ROOT)) { res.writeHead(403).end("forbidden"); return; }
  try {
    const body = await readFile(filePath);
    res.writeHead(200, { "content-type": TYPES[extname(filePath)] || "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[report] dashboard on http://127.0.0.1:${PORT}`);
});
