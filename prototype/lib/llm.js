// Model calls. Primary Groq, then a second Groq model (separate free quota), then OpenRouter. No keys in code.
const PROVIDERS = [
  { name: "Groq", url: "https://api.groq.com/openai/v1/chat/completions", key: () => process.env.GROQ_API_KEY, model: process.env.GROQ_MODEL || "openai/gpt-oss-120b" },
  { name: "Groq", url: "https://api.groq.com/openai/v1/chat/completions", key: () => process.env.GROQ_API_KEY, model: process.env.GROQ_FALLBACK_MODEL || "openai/gpt-oss-20b" },
  { name: "OpenRouter", url: "https://openrouter.ai/api/v1/chat/completions", key: () => process.env.OPENROUTER_API_KEY, model: process.env.OPENROUTER_MODEL || "google/gemma-4-31b-it:free" },
];

const offline = () => process.env.ACCESSPILOT_OFFLINE === "1" || !PROVIDERS.some((p) => p.key());

async function callLLM(messages, opts = {}) {
  const errors = [];
  for (const p of PROVIDERS) for (let attempt = 0; attempt < 2; attempt++) {
    if (!p.key()) { errors.push(`${p.name}: no API key`); break; }
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), opts.timeout || 20000);
    try {
      const body = { model: p.model, messages, temperature: 0, max_tokens: opts.max_tokens || 600 };
      if (p.name === "Groq" && /gpt-oss/.test(p.model)) body.reasoning_effort = "low";
      if (opts.json && p.name === "Groq") body.response_format = { type: "json_object" };
      const res = await fetch(p.url, { method: "POST", signal: ctrl.signal, headers: { "Content-Type": "application/json", Authorization: `Bearer ${p.key()}`, "HTTP-Referer": "https://accesspilot.vercel.app", "X-Title": "AccessPilot" }, body: JSON.stringify(body) });
      const txt = await res.text();
      if (!res.ok) {
        errors.push(`${p.name} ${p.model}: HTTP ${res.status} ${txt.slice(0, 200)}`);
        const m = txt.match(/try again in ([\d.]+)(ms|s)/i); const ra = Number(res.headers.get("retry-after"));
        const waitMs = m ? Number(m[1]) * (m[2].toLowerCase() === "ms" ? 1 : 1000) : isFinite(ra) && ra > 0 ? ra * 1000 : null;
        if (res.status === 429 && attempt === 0 && waitMs != null && waitMs <= (opts.maxWaitMs || 8000)) { await new Promise((r) => setTimeout(r, waitMs + 250)); continue; }
        break;
      }
      const j = JSON.parse(txt);
      const content = (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || "";
      if (!content.trim()) { errors.push(`${p.name} ${p.model}: empty reply`); break; }
      return { provider: p.name, model: p.model, content, usage: j.usage || {}, errors };
    } catch (e) { errors.push(`${p.name} ${p.model}: ${e.name === "AbortError" ? "timeout" : e.message}`); break; }
    finally { clearTimeout(t); }
  }
  const err = new Error("All model providers failed"); err.details = errors; throw err;
}

module.exports = { callLLM, PROVIDERS, offline };
