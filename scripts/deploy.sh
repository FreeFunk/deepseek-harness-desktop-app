#!/bin/bash
# DeepSeek Harness 部署脚本（含认证代理）
# 用法: bash deploy.sh

set -e

echo "=== DeepSeek Harness 部署开始 ==="

# 1. 安装 pnpm
if ! command -v pnpm &> /dev/null; then
  echo ">>> 安装 pnpm..."
  corepack enable pnpm
fi

# 2. 停止旧服务
echo ">>> 停止旧服务..."
pkill -f "dsh web" || true
pkill -f "node scripts/start-auth.mjs" || true
sleep 2

# 3. 克隆/更新代码
REPO_DIR="/root/deepseek-harness"
if [ -d "$REPO_DIR/.git" ]; then
  echo ">>> 更新代码..."
  cd "$REPO_DIR"
  git fetch origin
  git reset --hard origin/main
else
  echo ">>> 克隆代码..."
  git clone git@github.com:FreeFunk/deepseek-harness-desktop-app.git "$REPO_DIR"
  cd "$REPO_DIR"
fi

# 4. 安装依赖并构建
echo ">>> 安装依赖..."
pnpm install

echo ">>> 构建项目..."
pnpm run build

# 5. 设置环境变量
export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}"
export AUTH_PORT=3080
export AUTH_HOST=0.0.0.0
export BACKEND_URL=http://127.0.0.1:3099
export AUTH_DB_PATH=/root/.dsh/auth.db
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"

# 6. 启动 harness 后端
echo ">>> 启动 harness 后端 (端口 3099)..."
nohup pnpm dsh web --host 127.0.0.1 --port 3099 > /tmp/dsh-web.log 2>&1 &
echo "Harness PID: $!"

# 7. 等待后端就绪
echo ">>> 等待后端就绪..."
for i in {1..30}; do
  if curl -s http://127.0.0.1:3099 > /dev/null 2>&1; then
    echo "后端已就绪"
    break
  fi
  sleep 1
done

# 8. 启动认证代理
echo ">>> 启动认证代理 (端口 3080)..."
nohup node scripts/start-auth.mjs > /tmp/dsh-auth.log 2>&1 &
echo "Auth PID: $!"

echo "=== 部署完成 ==="
echo "认证代理: http://$(hostname -I | awk '{print $1}'):3080"
echo "后端:      http://127.0.0.1:3099"
echo "登录账号:  ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}"
echo ""
echo "查看日志:"
echo "  认证代理: tail -f /tmp/dsh-auth.log"
echo "  后端:     tail -f /tmp/dsh-web.log"