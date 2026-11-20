# Security Policy — CODE Eternal LLC

**Organization:** CODE Eternal LLC (New Mexico, USA · Entity ID `0008138873`)  
**Founder & Sole Owner:** Maksim Galatin (`Maksim Halatsin`)  
**Security Contact:** `contact@codeofdigitaleternity.com` · `codeofdigitaleternity@gmail.com`

---

## Reporting a Vulnerability

Please report security issues **privately before public disclosure** to **`contact@codeofdigitaleternity.com`** (subject: `SECURITY: <repo-or-site>`) or via GitHub Private Vulnerability Reporting on the specific repository.

Include:
1. Affected repository, package version (`pip show padam-nocturne`), or public URL/endpoint.
2. Minimal reproducible steps (using synthetic test data/tokens only).
3. Impact assessment (secret leak, injection bypass, SSRF, signature forgery, key recovery, etc.).

**Rules of Engagement (Safe Harbor):**
- Test only against your own local copies (`PADAM NOCTURNE`) or non-destructive unauthenticated checks; never access, exfiltrate, or modify other users' data.
- Wait for a coordinated patch release before public write-ups.

## Scope & Architecture Boundaries

- **Local Open-Source Core ([`padam-nocturne`](https://github.com/MaksimGalatin/padam-nocturne)):** `AGPL-3.0-only`, single local SQLite file, 128-bit memory data fencing, pre-disk DLP masking, Ed25519/X-Wing/AES-256-GCM encryption, crypto-shredding (`forget`), Merkle L3 proofs (`Arweave` + `Solana` + `Bitcoin OTS`). See [`SECURITY.md`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/SECURITY.md) and [`docs/SECURITY_REVIEW.md`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/docs/SECURITY_REVIEW.md).
- **Hosted Cloud Services (`aifa.works`, `codeofdigitaleternity.com`, `aifa.digital`, `radiocode.space`):** Commercial SaaS endpoints, unified Neon PostgreSQL + Cloudflare R2 storage, and hosted MCP policy documented in [`aifa-memory-mcp/HOSTED-POLICY.md`](https://github.com/MaksimGalatin/aifa-memory-mcp/blob/main/HOSTED-POLICY.md).
- **PADAM Agentic Shield:** Passive read-only SRI/CSP/Magecart & MCP config auditor. Callers must only scan targets they own or have explicit written authorization to assess.
