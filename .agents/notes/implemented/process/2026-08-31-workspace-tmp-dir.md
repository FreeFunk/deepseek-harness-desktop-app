# Agent Note: 工作区间规范

状态：implemented

English | [中文](#中文)

## 中文

所有临时脚本、批处理文件、调试输出、中间产物统一存放在仓库根目录下的
`tmp/` 子目录（例如 `D:\code\my-tool-code\deepseek-harness-desktop-app\tmp\`），
**不要** 放在以下位置：

- `C:\Users\<user>\AppData\Local\Temp\`（PowerShell `$env:TEMP`）
- `C:\Windows\Temp\`
- `/tmp/`（Linux 服务器系统目录）
- `/var/tmp/`

如果仓库根没有 `tmp/` 子目录，先创建再使用。

理由：

1. **可清理性**：工作目录可与仓库其他产物一起清理；系统 Temp 会随系统清理
   机制删除，容易丢上下文
2. **可见性**：临时脚本与代码变更在同一文件系统下，便于关联
3. **路径稳定**：跨机器、跨会话使用同一相对路径，避免 `$env:TEMP\xxx\` 这种
   用户专属路径
4. **可纳入 `.gitignore`**：仓库根 `.gitignore` 应已包含 ` `tmp/`，避免误提交

适用对象：本地开发、AI agent、CI 助手生成的任何 `.sh`、`.py`、`.js`、
`.ps1`、`.patch`、`.bundle` 等临时文件。