// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { exec } from 'child_process';

/**
 * @param {vscode.ExtensionContext} context
 */
export function activate(context: vscode.ExtensionContext) {
  let disposable: vscode.Disposable = vscode.commands.registerCommand(
    'trae-opener.openInTrae', 
    function (fileUri: vscode.Uri | undefined) {
      // 获取当前选中的目录路径
      const path: string | undefined = fileUri 
        ? fileUri.fsPath 
        : vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

      if (!path) {
        vscode.window.showErrorMessage('无法获取有效路径');
        return;
      }

      // 执行trae命令
      exec(`trae "${path}"`, (error, stdout, stderr) => {
        if (error) {
          vscode.window.showErrorMessage(`无法使用Trae打开目录: ${error.message}`);
          return;
        }
        if (stderr) {
          vscode.window.showWarningMessage(`Trae警告: ${stderr}`);
          return;
        }
        vscode.window.showInformationMessage(`已在Trae中打开目录: ${path}`);
      });
    });

  context.subscriptions.push(disposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
