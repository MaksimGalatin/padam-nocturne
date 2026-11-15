const vscode = require("vscode");
const { execFile } = require("child_process");

function activate(context) {
  if (vscode.lm && typeof vscode.lm.registerMcpServerDefinitionProvider === "function") {
    const provider = vscode.lm.registerMcpServerDefinitionProvider("padam-nocturne", {
      provideMcpServerDefinitions: async () => [
        new vscode.McpStdioServerDefinition("PADAM NOCTURNE", "padam-mcp", [])
      ]
    });
    context.subscriptions.push(provider);
  }

  const cmd = vscode.commands.registerCommand("padam.openStudio", () => {
    execFile("padam", ["studio", "--no-browser"], (err, stdout) => {
      if (err) {
        vscode.window.showErrorMessage("PADAM Studio start failed: " + err.message);
        return;
      }
      vscode.window.showInformationMessage("PADAM Studio ready: " + String(stdout || "").trim());
    });
  });
  context.subscriptions.push(cmd);
}

function deactivate() {}

module.exports = { activate, deactivate };
