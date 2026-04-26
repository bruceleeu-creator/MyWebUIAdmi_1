# QuantClaw Network Scanner

QuantClaw 的发现与配网页面，运行在 Mac 端 `http://localhost:8001`，负责两条链路：

- Wi-Fi / 局域网自动发现 QuantClaw 设备
- USB-C 直连 Raspberry Pi 后，自动检测 `9.9.9.x` 网段并跳转到 `http://quantclaw.local`

## 快速开始

```bash
pip install -r requirements.txt
python main.py
# 或
bash start.sh
```

打开 [http://localhost:8001](http://localhost:8001)。

## 现在这套东西到底在做什么

这个仓库不是单纯的“扫网页”，而是一个零接触配网入口：

- Mac 端页面负责轮询 USB 直连状态，每 10 秒检测一次
- 如果 Mac 因 USB Gadget DHCP 拿到 `9.9.9.x` 地址，页面顶部显示“USB 直连: 已连接”
- 如果 RPi 上的 Web 服务也可达，横幅会自动弹出，点击“连接设备”直接进入设备页
- 如果没有 USB 直连，页面仍然会继续走局域网扫描和自动发现

## API

| 接口 | 说明 |
|------|------|
| `GET /` | 返回前端页面 |
| `GET /api/info` | 返回当前主机 IP、网关、主机名 |
| `GET /api/scan` | 扫描当前局域网设备 |
| `GET /api/auto-detect` | 快速识别局域网中的 QuantClaw |
| `GET /api/probe` | 通过 mDNS / 直连 IP 快速探测设备 |
| `GET /api/usb-detect` | 检测 USB 直连链路是否建立，以及设备 Web 页面是否已就绪 |
| `POST /api/usb-provision` | 通过 USB 直连向设备提交 Wi‑Fi 配网请求 |

### `/api/usb-detect` 响应语义

- `connected=true`：Mac 已经看到 USB 网络接口，并拿到了 `9.9.9.x` 地址
- `ready=true`：RPi 上的 Web 服务也已经能访问
- `usb_devices[].url`：前端应该跳转的目标地址，优先使用 `http://quantclaw.local`

### `/api/usb-provision`

请求体：

```json
{
  "ssid": "Office-5G",
  "password": "your-password",
  "security": "WPA2",
  "hidden": false,
  "country": "CN"
}
```

Mac 端会自动把这个请求转发到 USB 直连设备上的配网接口。

## USB 直连实现

### Mac 端

`main.py` 负责：

1. 读取本机网络接口
2. 找到 `9.9.9.x` 子网接口
3. 探测 `9.9.9.1:80`
4. 解析 `quantclaw.local`
5. 只有在 Web 服务真的可访问时，才把横幅切到“可连接”状态

`templates/index.html` 负责：

1. 页面加载时自动调用 `/api/usb-detect`
2. 每 10 秒轮询一次
3. 检测到 USB 链路后把顶部状态卡切成绿色
4. 检测到设备 Web 服务后自动弹出“连接设备”横幅
5. 显示 USB 配网表单，让用户直接填写 Wi‑Fi 名称和密码

### RPi 端

`deploy/usb-gadget-setup.sh` 现在负责完整落地这条链：

1. 写入 `dtoverlay=dwc2,dr_mode=peripheral`
2. 把 `modules-load=dwc2,libcomposite` 写入 `cmdline.txt`
3. 配置 configfs USB Gadget（ECM + RNDIS）
4. 给 `usb0` 配 `9.9.9.1/24`
5. 启动 `dnsmasq`，给 Mac 分配 `9.9.9.10-100`
6. 启动 `avahi-daemon`，发布 `quantclaw.local`
7. 安装并启用 `qcg-init.service`，保证重启后自动恢复 USB Gadget
8. 如果设备上已有 QuantClaw Web 程序，则启用 `quantclaw-web.service`
9. 安装并启用 `quantclaw-provision-agent.service`，在 `:8081` 暴露 USB 配网接口

## RPi 部署

在支持 USB Device Mode 的树莓派上执行：

```bash
sudo bash deploy/usb-gadget-setup.sh
```

说明：

- 需要使用支持 OTG / Peripheral 的 USB 口和板型
- 如果硬件没有暴露 UDC，脚本会直接失败，而不是假装配置成功
- 首次写入 boot 配置后，通常需要重启一次

## 验证步骤

### Mac 侧

1. 用 USB-C 把 RPi 连到 Mac
2. 在 macOS 的 `System Settings -> Network` 确认出现新接口
3. 确认 Mac 拿到 `9.9.9.x` 地址
4. 打开 `http://localhost:8001`
5. 顶部应显示绿色“USB 直连: 已连接”
6. 横幅弹出后点击“连接设备”，应跳转到 `http://quantclaw.local`
7. 在 USB 配网卡片中填写 SSID / 密码并提交，页面应显示设备返回的连接结果

### RPi 侧

```bash
systemctl is-enabled qcg-init
systemctl is-enabled quantclaw-web
systemctl is-enabled quantclaw-provision-agent
systemctl status dnsmasq
systemctl status avahi-daemon
ip addr show usb0
```

## 文件结构

| 路径 | 用途 |
|------|------|
| `main.py` | FastAPI 服务，包含局域网发现和 USB 检测逻辑 |
| `scripts/quantclaw_provision_agent.py` | RPi 侧 USB 配网 agent，提供 `/api/provision/wifi` |
| `scripts/mock_quant_device.py` | 本地模拟 QuantClaw 设备，方便浏览器调试 USB 配网流程 |
| `templates/index.html` | 前端页面和 USB 轮询逻辑 |
| `deploy/usb-gadget-setup.sh` | RPi 侧 USB Gadget 一键部署脚本 |
| `start.sh` | 本地启动脚本 |
| `requirements.txt` | Python 依赖 |

## 已知前提

- `quantclaw.local` 依赖 RPi 的 mDNS 正常工作
- Mac 端是否自动弹出“信任/网络接口”提示，受 macOS 版本影响
- USB 线必须支持数据，不是纯供电线

## 本地模拟测试

如果手头暂时没有接上真机，可以先用本地 mock 设备验证前端流程：

```bash
python3 scripts/mock_quant_device.py
QUANTCLAW_SIMULATE_USB=1 QUANTCLAW_SIMULATED_DEVICE_URL=http://127.0.0.1:8090 python3 main.py
```
