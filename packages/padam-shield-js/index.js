// Локальный middleware @padam/shield для Node.js / LangChain.js / Vercel AI SDK (Zero-Telemetry)
const UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/u;
const SENSITIVE_PATH_RE = /(?:^|[/\\])(?:\.env(?:\.[a-z0-9_-]+)?|id_(?:rsa|ed25519)|\.aws[/\\]credentials|wallet\.json|secrets?\.(?:json|yaml|yml))$/i;
const DANGEROUS_SHELL_RE = /(?:\brm\s+-[a-z]*r[a-z]*f\s+(?:\/|~|\$HOME)|\/dev\/tcp\/|\bnc(?:at)?\s+[^\n]*-e\s+|curl\s+[^\n|]+\|\s*(?:sh|bash))/i;
const EVM_UNLIMITED_APPROVE_RE = /^0x095ea7b3[0-9a-f]{64}f{32,64}$/i;
const EVM_DANGEROUS_SELECTORS = new Set(["a22cb465", "f2fde38b", "3659cfe6", "715018a6"]);
const SECRET_RE = /(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----)/;

export class PadamShieldBlockedError extends Error {
  constructor(message, verdict) {
    super(message);
    this.name = "PadamShieldBlockedError";
    this.verdict = verdict;
  }
}

export class PadamShieldMiddleware {
  constructor(options = {}) {
    this.allowedDomains = new Set((options.allowedDomains || []).map((d) => String(d).toLowerCase()));
    this.allowedWallets = new Set((options.allowedWallets || []).map((w) => String(w).toLowerCase()));
    this.localApiUrl = options.localApiUrl || "";
    this.apiToken = options.apiToken || "";
    this.sessionTaints = new Set();
  }

  inspectInput(text) {
    const raw = String(text || "");
    const reasons = [];
    if (UNICODE_TAG_RE.test(raw)) reasons.push("hidden_unicode_or_bidi");
    if (/(?:ignore\s+previous\s+instructions|reveal\s+your\s+system\s+prompt|забудь\s+все\s+прежние\s+инструкции)/i.test(raw)) {
      reasons.push("prompt_injection_detected");
    }
    return { allowed: reasons.length === 0, blocked: reasons.length > 0, reasons };
  }

  inspectToolCall(toolName, { target = "", payload = "" } = {}) {
    const tool = String(toolName || "");
    const tgt = String(target || "");
    const body = String(payload || "");
    const combined = `${tgt}\n${body}`;
    const reasons = [];

    if (SENSITIVE_PATH_RE.test(tgt) || SENSITIVE_PATH_RE.test(body)) {
      this.sessionTaints.add("TAINT_SENSITIVE_READ");
    }
    if (this.sessionTaints.has("TAINT_SENSITIVE_READ") && /(?:fetch|http|curl|email|slack|webhook|post)/i.test(tool)) {
      const hostMatch = tgt.match(/https?:\/\/([^/:]+)/i);
      const host = hostMatch ? hostMatch[1].toLowerCase() : "";
      if (!host || !this.allowedDomains.has(host)) {
        reasons.push("taint_exfiltration_blocked");
      }
    }
    if (SECRET_RE.test(combined)) reasons.push("secret_exfiltration_blocked");
    if (DANGEROUS_SHELL_RE.test(combined)) reasons.push("dangerous_shell_command");

    const hexMatches = combined.match(/\b0x[a-fA-F0-9]{72,}\b/g) || [];
    for (const h of hexMatches) {
      const sel = h.slice(2, 10).toLowerCase();
      if (EVM_UNLIMITED_APPROVE_RE.test(h)) reasons.push("evm_unlimited_token_approval");
      else if (EVM_DANGEROUS_SELECTORS.has(sel)) reasons.push(`evm_dangerous_selector_0x${sel}`);
    }

    return {
      allowed: reasons.length === 0,
      blocked: reasons.length > 0,
      activeTaints: [...this.sessionTaints],
      reasons,
    };
  }

  wrapTool(toolName, fn) {
    return async (input) => {
      const target = typeof input === "string" ? input : String(input?.target || input?.url || input?.path || "");
      const payload = typeof input === "string" ? input : JSON.stringify(input || {});
      const v = this.inspectToolCall(toolName, { target, payload });
      if (v.blocked) {
        throw new PadamShieldBlockedError(`@padam/shield blocked ${toolName}: ${v.reasons.join(", ")}`, v);
      }
      return fn(input);
    };
  }
}
