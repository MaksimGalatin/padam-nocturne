export interface ShieldVerdict {
  allowed: boolean;
  blocked: boolean;
  reasons: string[];
  activeTaints?: string[];
}

export interface PadamShieldOptions {
  allowedDomains?: string[];
  allowedWallets?: string[];
  localApiUrl?: string;
  apiToken?: string;
}

export declare class PadamShieldBlockedError extends Error {
  readonly verdict: ShieldVerdict;
  constructor(message: string, verdict: ShieldVerdict);
}

export declare class PadamShieldMiddleware {
  constructor(options?: PadamShieldOptions);
  inspectInput(text: string): ShieldVerdict;
  inspectToolCall(toolName: string, args?: { target?: string; payload?: string }): ShieldVerdict;
  wrapTool<T, R>(toolName: string, fn: (input: T) => Promise<R> | R): (input: T) => Promise<R>;
}
