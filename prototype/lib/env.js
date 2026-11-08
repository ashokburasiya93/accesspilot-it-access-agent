// Loads KEY=value pairs from a local .env (this folder, else the project root two levels up). Never overrides real env vars.
const fs = require("fs"), path = require("path");
function loadEnv() {
  for (const f of [path.join(__dirname, "..", ".env"), path.join(__dirname, "..", "..", "..", ".env")]) if (fs.existsSync(f)) {
    for (const line of fs.readFileSync(f, "utf8").split(/\r?\n/)) { const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/); if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, ""); }
    return f;
  }
  return null;
}
module.exports = { loadEnv };
