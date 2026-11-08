// Local dev server: serves public/ and runs api/*.js like Vercel does. Usage: node server.js
const http = require("http"), fs = require("fs"), path = require("path");
require("./lib/env").loadEnv();
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };
const PORT = Number(process.env.PORT || 3000);
http.createServer(async (req, res) => {
  const u0 = new URL(req.url, "http://localhost"); const u = { pathname: decodeURIComponent(u0.pathname), query: Object.fromEntries(u0.searchParams) };
  if (u.pathname.startsWith("/api/")) {
    const name = path.basename(u.pathname);
    const file = path.join(__dirname, "api", name + ".js");
    if (name.startsWith("_") || !fs.existsSync(file)) { res.writeHead(404); return res.end("not found"); }
    let raw = ""; for await (const c of req) raw += c;
    req.query = u.query; try { req.body = raw ? JSON.parse(raw) : {}; } catch { req.body = null; }
    res.status = (c) => { res.statusCode = c; return res; };
    res.json = (o) => { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(o)); };
    if (req.body === null) return res.status(400).json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    try { return await require(file)(req, res); } catch (e) { return res.status(500).json({ error: e.message }); }
  }
  const f = path.join(__dirname, "public", u.pathname === "/" ? "index.html" : path.normalize(u.pathname));
  if (!f.startsWith(path.join(__dirname, "public")) || !fs.existsSync(f)) { res.writeHead(404); return res.end("not found"); }
  res.writeHead(200, { "Content-Type": TYPES[path.extname(f)] || "application/octet-stream" }); fs.createReadStream(f).pipe(res);
}).listen(PORT, () => console.log(`AccessPilot on http://localhost:${PORT}  (MCP over HTTP: POST /api/mcp)`));
