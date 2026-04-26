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
echo "🌐 服务地址: http://localhost:8000"
echo "📱 手机访问: http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "按 Ctrl+C 停止服务"
echo ""

# 使用 root 权限运行（ARP 扫描需要）
exec python3 main.py
