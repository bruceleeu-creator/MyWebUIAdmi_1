#!/bin/bash
set -euo pipefail

GADGET_DIR="/sys/kernel/config/usb_gadget/quantclaw"
GADGET_IP="9.9.9.1"
GADGET_CIDR="24"
HOST_IP_START="9.9.9.10"
HOST_IP_END="9.9.9.100"
GADGET_HOSTNAME="${QCG_HOSTNAME:-quantclaw}"
USB_IFACE="usb0"
SCRIPT_DEST="/usr/local/sbin/qcg-init"
QCG_SERVICE="/etc/systemd/system/qcg-init.service"
WEB_SERVICE="/etc/systemd/system/quantclaw-web.service"
PROVISION_AGENT_DEST="/usr/local/sbin/quantclaw-provision-agent.py"
PROVISION_AGENT_SERVICE="/etc/systemd/system/quantclaw-provision-agent.service"
QUANTCLAW_BIN="${QUANTCLAW_BIN:-/home/quant/quantclaw}"
MODE="${1:-install}"
CONFIG_FILE=""
CMDLINE_FILE=""

log() { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { log "ERROR: $*"; exit 1; }

must_be_root() {
    if [ "$(id -u)" != "0" ]; then
        log "需要 root 权限，正在用 sudo 重新执行..."
        exec sudo bash "$0" "$@"
    fi
}

pick_boot_files() {
    if [ -f /boot/firmware/config.txt ]; then
        CONFIG_FILE="/boot/firmware/config.txt"
        CMDLINE_FILE="/boot/firmware/cmdline.txt"
    elif [ -f /boot/config.txt ]; then
        CONFIG_FILE="/boot/config.txt"
        CMDLINE_FILE="/boot/cmdline.txt"
    else
        fail "未找到 /boot/config.txt 或 /boot/firmware/config.txt"
    fi

    if [ ! -f "$CMDLINE_FILE" ]; then
        fail "未找到 $CMDLINE_FILE"
    fi
}

append_unique_line() {
    local file="$1"
    local line="$2"
    if grep -q "^${line}$" "$file" 2>/dev/null; then
        log "  ${line} 已存在"
        return
    fi
    echo "$line" >> "$file"
    log "  已写入 ${file}: ${line}"
}

remove_matching_lines() {
    local file="$1"
    local pattern="$2"
    if [ ! -f "$file" ]; then
        return
    fi

    local temp_file
    temp_file="$(mktemp)"
    grep -vE "$pattern" "$file" > "$temp_file" || true
    cat "$temp_file" > "$file"
    rm -f "$temp_file"
}

ensure_cmdline_param() {
    local file="$1"
    local param="$2"
    if grep -qE "(^| )${param}($| )" "$file"; then
        log "  ${param} 已存在"
        return
    fi

    local current
    current="$(cat "$file")"
    printf "%s %s\n" "$current" "$param" > "$file"
    log "  已写入 ${file}: ${param}"
}

strip_cmdline_param_prefix() {
    local file="$1"
    local prefix="$2"
    [ -f "$file" ] || return

    python3 - "$file" "$prefix" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
prefix = sys.argv[2]
content = path.read_text(encoding="utf-8").strip()
tokens = [token for token in content.split() if not token.startswith(prefix)]
path.write_text(" ".join(tokens) + "\n", encoding="utf-8")
PY
}

enable_boot_config() {
    log "Step 1: 启用 USB Gadget 启动配置..."
    pick_boot_files
    remove_matching_lines "$CONFIG_FILE" '^dtoverlay=dwc2.*$'
    append_unique_line "$CONFIG_FILE" "dtoverlay=dwc2,dr_mode=peripheral"
    strip_cmdline_param_prefix "$CMDLINE_FILE" "modules-load="
    ensure_cmdline_param "$CMDLINE_FILE" "modules-load=dwc2,libcomposite"
}

ensure_hostname() {
    log "Step 2: 配置 mDNS 主机名..."

    local current=""
    if command -v hostnamectl >/dev/null 2>&1; then
        current="$(hostnamectl --static 2>/dev/null || true)"
    fi
    if [ -z "$current" ] && [ -f /etc/hostname ]; then
        current="$(tr -d ' \n' < /etc/hostname)"
    fi

    if [ "$current" != "$GADGET_HOSTNAME" ]; then
        if command -v hostnamectl >/dev/null 2>&1; then
            hostnamectl set-hostname "$GADGET_HOSTNAME"
        else
            echo "$GADGET_HOSTNAME" > /etc/hostname
            hostname "$GADGET_HOSTNAME"
        fi
    fi
    if [ -f /etc/hosts ]; then
        if grep -qE '^127\.0\.1\.1[[:space:]]+' /etc/hosts; then
            sed -i -E 's/^(127\.0\.1\.1[[:space:]]+).*/\1'"${GADGET_HOSTNAME}"'/' /etc/hosts
        else
            echo "127.0.1.1 ${GADGET_HOSTNAME}" >> /etc/hosts
        fi
    fi
    log "  主机名已是 ${GADGET_HOSTNAME} (mDNS: ${GADGET_HOSTNAME}.local)"
}

install_runtime_packages() {
    log "Step 3: 检查运行依赖..."

    local packages=()
    command -v dnsmasq >/dev/null 2>&1 || packages+=("dnsmasq")
    command -v avahi-daemon >/dev/null 2>&1 || packages+=("avahi-daemon")

    if [ "${#packages[@]}" -eq 0 ]; then
        log "  dnsmasq 和 avahi-daemon 已安装"
        return
    fi

    apt-get update -qq
    apt-get install -y -qq "${packages[@]}"
    log "  已安装: ${packages[*]}"
}

load_modules() {
    log "Step 4: 加载内核模块..."
    modprobe libcomposite || fail "无法加载 libcomposite"
    modprobe dwc2 || fail "无法加载 dwc2"
    modprobe usb_f_ecm || fail "无法加载 usb_f_ecm"
    modprobe usb_f_rndis || log "  usb_f_rndis 未加载，Windows 兼容模式将不可用"
    modprobe u_ether || fail "无法加载 u_ether"
}

ensure_udc_available() {
    if [ ! -d /sys/class/udc ] || [ -z "$(ls -A /sys/class/udc 2>/dev/null)" ]; then
        fail "当前硬件未暴露 UDC，无法启用 USB Device Mode。请确认使用支持 OTG/Peripheral 的 USB 口和板型。"
    fi
}

setup_configfs() {
    log "Step 5: 配置 USB Gadget (configfs)..."

    if [ ! -d /sys/kernel/config/usb_gadget ]; then
        mount -t configfs none /sys/kernel/config
    fi

    if [ -d "$GADGET_DIR" ]; then
        if [ -f "$GADGET_DIR/UDC" ]; then
            echo "" > "$GADGET_DIR/UDC" 2>/dev/null || true
        fi
        find "$GADGET_DIR" -depth -type l -exec rm -f {} \; 2>/dev/null || true
        find "$GADGET_DIR" -depth -type d -exec rmdir {} \; 2>/dev/null || true
        [ ! -d "$GADGET_DIR" ] || fail "无法清理旧的 USB gadget: $GADGET_DIR"
    fi

    mkdir -p "$GADGET_DIR"
    cd "$GADGET_DIR"

    echo "0x1d6b" > idVendor
    echo "0x0104" > idProduct
    echo "0x0100" > bcdDevice
    echo "0x0200" > bcdUSB
    echo "0xEF" > bDeviceClass
    echo "0x02" > bDeviceSubClass
    echo "0x01" > bDeviceProtocol

    mkdir -p strings/0x409
    local serial_suffix
    serial_suffix="$(awk '/Serial/ {print $3}' /proc/cpuinfo | tail -1)"
    [ -n "$serial_suffix" ] || serial_suffix="0000"
    echo "${GADGET_HOSTNAME}-${serial_suffix: -4}" > strings/0x409/serialnumber
    echo "QuantClaw" > strings/0x409/manufacturer
    echo "QuantClaw USB Provisioning" > strings/0x409/product

    mkdir -p configs/c.1/strings/0x409
    echo "RNDIS/ECM Config" > configs/c.1/strings/0x409/configuration
    echo 250 > configs/c.1/MaxPower

    mkdir -p functions/ecm.usb0
    echo "9a:9b:9c:9d:9e:01" > functions/ecm.usb0/host_addr
    echo "9a:9b:9c:9d:9e:02" > functions/ecm.usb0/dev_addr
    ln -sf functions/ecm.usb0 configs/c.1/

    mkdir -p functions/rndis.usb0
    echo "9a:9b:9c:9d:9e:01" > functions/rndis.usb0/host_addr
    echo "9a:9b:9c:9d:9e:03" > functions/rndis.usb0/dev_addr
    ln -sf functions/rndis.usb0 configs/c.1/

    local udc_name
    udc_name="$(ls /sys/class/udc | head -1)"
    [ -n "$udc_name" ] || fail "未找到可绑定的 UDC"
    echo "$udc_name" > UDC

    cd /
    log "  Gadget 已绑定到 UDC: ${udc_name}"
}

detect_usb_iface() {
    local iface=""

    for candidate in usb0 usb1; do
        if [ -d "/sys/class/net/${candidate}" ]; then
            echo "$candidate"
            return
        fi
    done

    for candidate in /sys/class/net/*; do
        [ -e "$candidate" ] || continue
        iface="$(basename "$candidate")"
        [ "$iface" = "lo" ] && continue

        local address
        address="$(cat "$candidate/address" 2>/dev/null || true)"
        if echo "$address" | grep -qi "^9a:9b:9c:9d:9e:"; then
            echo "$iface"
            return
        fi
    done

    echo "usb0"
}

setup_network() {
    log "Step 6: 配置 USB 网络接口..."

    USB_IFACE="$(detect_usb_iface)"
    ip link set "$USB_IFACE" up
    ip addr replace "${GADGET_IP}/${GADGET_CIDR}" dev "$USB_IFACE"
    log "  接口: ${USB_IFACE}"
    log "  静态地址: ${GADGET_IP}/${GADGET_CIDR}"
}

setup_dhcp() {
    log "Step 7: 配置 DHCP/DNS (dnsmasq)..."

    cat > /etc/dnsmasq.d/quantclaw-usb.conf <<EOF
interface=${USB_IFACE}
bind-interfaces
dhcp-authoritative
dhcp-range=${HOST_IP_START},${HOST_IP_END},255.255.255.0,24h
dhcp-option=3,${GADGET_IP}
dhcp-option=6,${GADGET_IP}
address=/${GADGET_HOSTNAME}.local/${GADGET_IP}
EOF

    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable dnsmasq >/dev/null 2>&1 || true
        systemctl restart dnsmasq
    else
        service dnsmasq restart
    fi
}

setup_avahi() {
    log "Step 8: 配置 mDNS 广播 (Avahi)..."

    mkdir -p /etc/avahi/services
    cat > /etc/avahi/services/quantclaw.service <<EOF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">QuantClaw on %h</name>
  <service>
    <type>_http._tcp</type>
    <port>80</port>
    <txt-record>path=/</txt-record>
  </service>
  <service>
    <type>_quantclaw._tcp</type>
    <port>80</port>
    <txt-record>type=zero-touch</txt-record>
    <txt-record>hostname=${GADGET_HOSTNAME}.local</txt-record>
  </service>
</service-group>
EOF

    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable avahi-daemon >/dev/null 2>&1 || true
        systemctl restart avahi-daemon
    else
        service avahi-daemon restart
    fi
}

install_qcg_init_service() {
    log "Step 9: 安装 qcg-init 开机恢复服务..."

    install -m 0755 "$0" "$SCRIPT_DEST"

    cat > "$QCG_SERVICE" <<EOF
[Unit]
Description=QuantClaw USB Gadget Bootstrap
After=systemd-modules-load.service local-fs.target
Wants=systemd-modules-load.service

[Service]
Type=oneshot
ExecStart=${SCRIPT_DEST} --boot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable qcg-init.service
}

setup_quantclaw_web_service() {
    log "Step 10: 配置 quantclaw-web 服务..."

    if ! command -v systemctl >/dev/null 2>&1; then
        log "  跳过: systemd 不可用"
        return
    fi

    if systemctl list-unit-files | grep -q "^quantclaw-web.service"; then
        systemctl enable quantclaw-web.service >/dev/null 2>&1 || true
        log "  已检测到现有 quantclaw-web.service，保持启用状态"
        return
    fi

    if [ ! -x "$QUANTCLAW_BIN" ]; then
        log "  警告: ${QUANTCLAW_BIN} 不存在或不可执行，未创建 quantclaw-web.service"
        return
    fi

    cat > "$WEB_SERVICE" <<EOF
[Unit]
Description=QuantClaw Web UI
After=network-online.target qcg-init.service
Wants=network-online.target qcg-init.service

[Service]
Type=simple
User=quant
WorkingDirectory=$(dirname "$QUANTCLAW_BIN")
ExecStart=${QUANTCLAW_BIN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable quantclaw-web.service
    log "  已创建并启用 quantclaw-web.service"
}

install_provision_agent_service() {
    log "Step 11: 安装 QuantClaw USB 配网 agent..."

    if ! command -v python3 >/dev/null 2>&1; then
        log "  警告: 设备缺少 python3，跳过 USB 配网 agent 安装"
        return
    fi

    local provision_agent_src
    provision_agent_src="$(cd "$(dirname "$0")/../scripts" && pwd)/quantclaw_provision_agent.py"

    if [ ! -f "$provision_agent_src" ]; then
        log "  警告: 未找到 ${provision_agent_src}，跳过 USB 配网 agent 安装"
        return
    fi

    install -m 0755 "$provision_agent_src" "$PROVISION_AGENT_DEST"

    cat > "$PROVISION_AGENT_SERVICE" <<EOF
[Unit]
Description=QuantClaw USB Provision Agent
After=network-online.target qcg-init.service
Wants=network-online.target qcg-init.service

[Service]
Type=simple
ExecStart=/usr/bin/env python3 ${PROVISION_AGENT_DEST} --port 8081
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable quantclaw-provision-agent.service
    systemctl restart quantclaw-provision-agent.service
    log "  已启用 quantclaw-provision-agent.service (端口 8081)"
}

setup_nat() {
    log "Step 12: 配置 NAT (可选)..."

    if ! command -v iptables >/dev/null 2>&1; then
        log "  未安装 iptables，跳过 NAT 配置"
        return
    fi

    local wan_iface
    wan_iface="$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)"

    if [ -z "$wan_iface" ] || [ "$wan_iface" = "$USB_IFACE" ]; then
        log "  未检测到有效上行接口，跳过 NAT 配置"
        return
    fi

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -t nat -C POSTROUTING -o "$wan_iface" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$wan_iface" -j MASQUERADE
    iptables -C FORWARD -i "$USB_IFACE" -o "$wan_iface" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$USB_IFACE" -o "$wan_iface" -j ACCEPT
    iptables -C FORWARD -i "$wan_iface" -o "$USB_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_iface" -o "$USB_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
}

persist_nat_rules() {
    log "Step 13: 持久化 NAT 规则..."

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
        log "  已通过 netfilter-persistent 保存"
        return
    fi

    mkdir -p /etc/iptables

    if iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
        log "  已通过 iptables-save 保存至 /etc/iptables/rules.v4"
        return
    fi

    if [ -f /etc/rc.local ]; then
        cat >> /etc/rc.local <<'RCLOCAL'
iptables-restore < /etc/iptables/rules.v4 2>/dev/null || true
RCLOCAL
        chmod +x /etc/rc.local
        log "  已添加 iptables-restore 至 /etc/rc.local"
    else
        log "  警告: 无法持久化 iptables 规则"
    fi
}

print_summary() {
    log ""
    log "============================================"
    log "  QuantClaw USB Gadget 配置完成"
    log "============================================"
    log "  设备地址:     ${GADGET_IP}"
    log "  宿主机 DHCP:  ${HOST_IP_START} - ${HOST_IP_END}"
    log "  USB 接口:     ${USB_IFACE}"
    log "  mDNS 地址:    http://${GADGET_HOSTNAME}.local"
    log ""
    if command -v systemctl >/dev/null 2>&1; then
        log "  qcg-init:     $(systemctl is-enabled qcg-init.service 2>/dev/null || echo disabled)"
        log "  dnsmasq:      $(systemctl is-active dnsmasq 2>/dev/null || echo inactive)"
        log "  avahi:        $(systemctl is-active avahi-daemon 2>/dev/null || echo inactive)"
        log "  quantclaw-web: $(systemctl is-enabled quantclaw-web.service 2>/dev/null || echo missing)"
        log "  usb-agent:    $(systemctl is-enabled quantclaw-provision-agent.service 2>/dev/null || echo missing)"
    fi
    log ""
    log "  Mac 侧验证:"
    log "    1. 用 USB-C 将 RPi 连接到 Mac"
    log "    2. 确认 Mac 网络接口拿到 9.9.9.x"
    log "    3. 打开 http://localhost:8001，顶部应显示 USB 已连接"
    log "    4. 点击“连接设备”，应跳转到 http://${GADGET_HOSTNAME}.local"
    log ""
    log "  自检诊断:    sudo bash deploy/usb-gadget-check.sh"
}

run_runtime_setup() {
    load_modules
    ensure_udc_available
    setup_configfs
    setup_network
    setup_dhcp
    setup_avahi
}

main() {
    must_be_root "$@"

    log "QuantClaw USB Gadget 一键部署"
    log "================================"
    log "目标设备: $(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo 'Unknown Board')"
    log "模式: ${MODE}"
    log ""

    if [ "$MODE" != "--boot" ]; then
        enable_boot_config
        ensure_hostname
        install_runtime_packages
    fi

    run_runtime_setup

    if [ "$MODE" != "--boot" ]; then
        install_qcg_init_service
        setup_quantclaw_web_service
        install_provision_agent_service
        setup_nat
        persist_nat_rules
        print_summary
    fi
}

main "$@"
