#!/usr/bin/env node
"use strict";

const { spawnSync, spawn } = require("child_process");

function hasCmd(cmd) {
  const probe = process.platform === "win32" ? "where" : "which";
  const r = spawnSync(probe, [cmd], { stdio: "ignore" });
  return r.status === 0;
}

function resolveLaunch() {
  const args = process.argv.slice(2);
  if (hasCmd("padam-mcp")) {
    return { cmd: "padam-mcp", args };
  }
  if (hasCmd("uvx")) {
    return { cmd: "uvx", args: ["--from", "padam-nocturne", "padam-mcp", ...args] };
  }
  const py = hasCmd("python3") ? "python3" : "python";
  return { cmd: py, args: ["-m", "padam.mcp_server", ...args] };
}

const target = resolveLaunch();
const child = spawn(target.cmd, target.args, { stdio: "inherit" });
child.on("exit", (code) => process.exit(code == null ? 1 : code));
child.on("error", (err) => {
  process.stderr.write("Failed to launch PADAM MCP: " + err.message + "\n");
  process.exit(1);
});
