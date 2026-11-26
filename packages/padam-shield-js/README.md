# @padam/shield

Local, zero-telemetry middleware for Node.js, LangChain.js, and Vercel AI SDK implementing PADAM Agentic Shield controls:

- **Ring 1**: Hidden Unicode tag (`U+E00xx`) / Bidi override detection & prompt-injection pre-filter
- **Ring 2**: Session Taint Tracking (`TAINT_SENSITIVE_READ` blocks exfiltration to untrusted domains)
- **Ring 3**: Secret DLP, dangerous shell blocking, and EVM calldata ABI checks (`approve(MAX_UINT256)`, `setApprovalForAll`, `transferOwnership`)

```js
import { PadamShieldMiddleware } from "@padam/shield";

const shield = new PadamShieldMiddleware({ allowedDomains: ["aifa.works"] });
const safeFetch = shield.wrapTool("fetch", async (args) => fetch(args.url));
```
