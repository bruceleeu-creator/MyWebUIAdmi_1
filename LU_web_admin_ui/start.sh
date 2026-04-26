#!/bin/bash
# QuantClaw 网络扫描服务启动脚本

cd "$(dirname "$0")"

echo "📡 正在启动 QuantClaw Network Scanner..."
echo ""

# 检查依赖
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "📦 正在安装依赖..."
    pip install -r requirements.txt -q
fi

# 检查 nmap
if command -v nmap &> /dev/null; then
    echo "✅ nmap 已安装 (扫描速度更快)"
else
    echo "⚠️  nmap 未安装，将使用 ARP 扫描 (可能需要 root 权限)"
fi

echo ""
LOCAL_IP=$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("8.8.8.8", 80))
    print(s.getsockname()[0])
except Exception:
    print("127.0.0.1")
finally:
    s.close()
PY
)

echo "🌐 服务地址: http://localhost:8001"
echo "📱 手机访问: http://${LOCAL_IP}:8001"
echo ""
echo "按 Ctrl+C 停止服务"
echo ""

# 使用 root 权限运行（ARP 扫描需要）
exec python3 main.py
