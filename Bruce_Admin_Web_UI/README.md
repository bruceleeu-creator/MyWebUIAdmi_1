# QuantClaw Network Scanner

局域网设备扫描服务，自动发现 Quant 设备（Raspberry Pi）。

## 快速开始

```bash
# 创建虚拟环境
python -m venv .venv

# 安装依赖
.venv\Scripts\pip install -r requirements.txt

# 启动服务
.venv\Scripts\python main.py
```

访问 **http://localhost:8001**

## 功能

- 扫描局域网设备
- 自动识别 Quant/Raspberry Pi 设备
- 显示 IP、MAC、主机名

## API

| 接口 | 说明 |
|------|------|
| `GET /` | Web 界面 |
| `GET /api/scan` | 扫描设备 |
| `GET /api/info` | 本机信息 |

## 跨平台

- **Linux/macOS**: 支持 nmap 和 ARP 扫描
- **Windows**: 支持 ARP 扫描（已适配）
