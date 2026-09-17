"""``miot.lan.NetworkManager.is_cross_subnet`` 加 tailscale 远端 LAN 子网兜底。

根因（2026-09-17）
-------------------
sg-node miloco 走 Tailscale subnet route → armbian → 家里 192.168.31.x 摄像头，包能
到（实测 ping 31.1 = 53ms、TCP 31.x 全 OPEN）。但 miot SDK ``is_cross_subnet()``
（``backend/miot/src/miot/lan.py:654``）拿**本机所有网卡 IPv4Network**跟目标 IP 比，
sg-node 上的 tailscale0 = ``100.108.187.71/32`` 跟 192.168.31.x 当然不同段 →
cross_subnet=True → SDK 跟摄像头的 mIPC 协议握手失败（协议依赖二层）→ 拉流 ≥ 90s
收不到 first frame → ``MIoTProxy.stream_nat_blocked()`` 触发 →
``stream_error="cross_subnet_nat"`` → 前端显示 "跨网段拉流失败，建议...全锥/开放 NAT"
——属于误诊。

修法
----
不改 SDK；miloco 后端启动时 monkey-patch ``NetworkManager.is_cross_subnet``：
原判定为 True（跨网段）时，再看目标 IP 是否落在 ``ip route show dev tailscale0``
返回的远端 CIDR 里；若是，**实际是可达的 LAN，不算跨网段**——返回 False。

不修 SDK 的理由
- ``backend/miot/`` 是 vendor 源码（memories/MEMORY.md 红线"vendor 不可改"）；
  patch 在升级时悄悄失效，定位困难。
- 注入点单一、逻辑简单；集中放 miloco 这一层、加 escape hatch
  （``MILOCO_DISABLE_TAILSCALE_SUBNET_PATCH=1`` 跳过）便于回滚。

何时刷新
--------
启动一次。is_cross_subnet 调用频率不高（每相机每 LAN 探测周期），Tailscale 子网
变更是罕见事件；如需运行时热刷，调用方重复调 ``patch_is_cross_subnet_for_tailscale_subnets``
即可重读 ``ip route``。
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
from typing import Optional

from miot.lan import MIoTLan as _MIoTLanClass  # is_cross_subnet 宿主类

_LOG = logging.getLogger(__name__)

# 模块级缓存：patch 时一次读 ip route，运行时不再 subprocess。
_extra_nets: list[ipaddress.IPv4Network] = []
_original_is_cross_subnet: Optional[object] = None


def _read_extra_nets(iface: str) -> list[ipaddress.IPv4Network]:
    """``ip -4 route show table all dev <iface>`` 解析每行第一列 CIDR。

    输出形如::

        192.168.31.0/24 table 52        # sg-node 上 Tailscale subnet route 在 table 52
        100.100.100.100/32 table 52
        local 100.108.187.71 table local proto kernel scope host src ...

    用 ``table all`` 而不是默认 main：**Tailscale subnet route 不在 main 表**，sg-node 上
    tailscale0 的 192.168.31.0/24 在 table 52。``show dev <iface>`` 默认只查 main →
    返回空 → patch 退化为 no-op。早期实修过这个,见 git blame。
    """
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "table", "all", "dev", iface],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        _LOG.warning("tailscale subnet patch: ip route failed: %s", e)
        return []
    if out.returncode != 0:
        _LOG.debug(
            "tailscale subnet patch: ip route exit=%d stderr=%s",
            out.returncode,
            out.stderr.strip(),
        )
        return []
    nets: list[ipaddress.IPv4Network] = []
    for line in out.stdout.splitlines():
        first = line.split()[0] if line.split() else ""
        # ``ip route show table all`` 会带 ``local X.X.X.X table local proto kernel``
        # 行,首列也是合法 IPv4Address,但**不是** CIDR,会被 IPv4Network(strict=False)
        # 解析成 /32 然后误注入为单 IP 网段。Tailscale 注入场景里 local /32 是
        # tailscale0 自身地址,严格说"同段"但实际上游不会拿自己 IP 当目标相机,
        # 放过不影响语义;仍保留以减少漏检风险。
        try:
            nets.append(ipaddress.IPv4Network(first, strict=False))
        except ValueError:
            continue
    return nets


def _patched_is_cross_subnet(
    self,
    ip: Optional[str],
) -> Optional[bool]:
    """原判定为 True（跨网段）时，再用注入的 tailscale 远端 LAN 子网兜底。

    严格只"把跨网段 False 化"——绝不能把"判不出来（None）"翻成 True，也不能把"同段
    （False）"翻成 True。后者本来就是 patched 的"同段"语义，前者会让上层把一台 IP
    缺失的相机诊断成 NAT 阻断，方向与 SDK 设计（宁可少报也不错报）冲突。
    """
    assert _original_is_cross_subnet is not None  # patch 流程保证
    result = _original_is_cross_subnet(self, ip)  # type: ignore[operator]
    if result is not True:
        return result
    if not ip or not _extra_nets:
        return result  # SDK 已经把"无 IP"判为 None/True 都尊重原语义
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        # IP 非法：SDK 真版会判 None（"判不出来"），保留 None；不可贸然翻成 True
        # 让上层引去折腾路由器。直接返回 None 与 SDK 设计"宁可少报也不错报"对齐。
        return None
    if any(addr in net for net in _extra_nets):
        return False
    return True


def patch_is_cross_subnet_for_tailscale_subnets(iface: str = "tailscale0") -> int:
    """monkey-patch ``NetworkManager.is_cross_subnet`` 加 tailscale 远端 LAN 兜底。

    Returns
    -------
    int
        注入的子网数。0 = 未注入（tailscale0 不存在/ip 不可用/env 禁用），等价于
        此次调用 no-op。

    Notes
    -----
    幂等：重复调用 = 重新读 ``ip route`` 并覆盖之前的注入；SDK 类的 method 引用不会
    重复包。
    """
    global _extra_nets, _original_is_cross_subnet

    if os.environ.get("MILOCO_DISABLE_TAILSCALE_SUBNET_PATCH") == "1":
        _LOG.info("tailscale subnet patch disabled by env")
        _extra_nets = []
        return 0

    nets = _read_extra_nets(iface)
    if _original_is_cross_subnet is None:
        _original_is_cross_subnet = _MIoTLanClass.is_cross_subnet
    _extra_nets = nets

    if not nets:
        _LOG.info(
            "tailscale subnet patch: no nets on dev %s (skipping)", iface
        )
        return 0

    _MIoTLanClass.is_cross_subnet = _patched_is_cross_subnet  # type: ignore[assignment]
    _LOG.info(
        "tailscale subnet patch: %d extra nets from dev %s: %s",
        len(nets),
        iface,
        [str(n) for n in nets],
    )
    return len(nets)
