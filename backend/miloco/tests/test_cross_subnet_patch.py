"""``miloco.miot.cross_subnet_patch`` 单测。

钉死四个契约：
- patch 后类方法被替换为新函数（monkey-patch 落到了类层级）
- 原判定为 True（真跨网段）且目标在 tailscale 远端 LAN 子网里 → 改判 False
- 原判定为 True 且目标不在注入子网里 → 仍判 True（不误扩大"同段"语义）
- 原判定为 None（判不出来）或 False（同段）→ 不被改写
- env ``MILOCO_DISABLE_TAILSCALE_SUBNET_PATCH=1`` 时 patch 退化为 no-op
"""

from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock, patch

import pytest
from miloco.miot import cross_subnet_patch as csp


def _restore_sdk_original(sdk_orig):
    """测试间清理：把 SDK 类方法还原到 monkey-patch 之前的状态。

    用 fixture 缓存的 SDK 真版（不是 ``_original_is_cross_subnet``）做还原——
    后者可能是上一个测试塞的 stub,直接用会污染 SDK 类方法到下个测试。
    """
    from miot.lan import MIoTLan as _MIoTLanClass

    _MIoTLanClass.is_cross_subnet = sdk_orig  # type: ignore[assignment]
    csp._extra_nets = []
    csp._original_is_cross_subnet = None


@pytest.fixture(autouse=True)
def _cleanup_patch():
    """autouse: 进测试前把 SDK 真版快照出来,结束用快照还原。"""
    from miot.lan import MIoTLan as _MIoTLanClass

    sdk_orig = _MIoTLanClass.is_cross_subnet
    yield
    _restore_sdk_original(sdk_orig)


def _fake_route_output(text: str):
    """``subprocess.run`` mock 返回值工厂（用 MagicMock 而非真实 subprocess）。"""
    m = MagicMock()
    m.returncode = 0
    m.stdout = text
    m.stderr = ""
    return m


# ─── _read_extra_nets ────────────────────────────────────────────────────────


@pytest.mark.unit
def test_read_extra_nets_parses_cidr_first_column():
    """`ip route` 输出每行首列是 CIDR；proto/scope/src 等后缀忽略。"""
    fake = _fake_route_output(
        "192.168.31.0/24 proto static scope link src 100.94.99.1\n"
        "100.100.100.100/32 dev tailscale0\n"
    )
    with patch.object(csp.subprocess, "run", return_value=fake) as run:
        nets = csp._read_extra_nets("tailscale0")
    # 命令应显式带 ``table all``——main 表不含 tailscale 子网路由,只查 main 会漏
    # 注入。早期实修过这个回归,见 git blame cross_subnet_patch.py。
    cmd = run.call_args[0][0]
    assert "table" in cmd and "all" in cmd, f"missing 'table all' in {cmd}"
    assert nets == [
        ipaddress.IPv4Network("192.168.31.0/24"),
        ipaddress.IPv4Network("100.100.100.100/32"),
    ]


@pytest.mark.unit
def test_read_extra_nets_handles_table_all_format():
    """``ip -4 route show table all`` 输出形如 ``192.168.31.0/24 table 52``,
    解析首列 CIDR 即可,与 main 表格式同算法。"""
    fake = _fake_route_output(
        "100.68.221.50 table 52\n"
        "100.72.90.68 table 52\n"
        "100.94.99.1 table 52\n"
        "100.100.100.100/32 table 52\n"
        "192.168.31.0/24 table 52\n"
        "local 100.108.187.71 table local proto kernel scope host src 100.108.187.71\n"
    )
    with patch.object(csp.subprocess, "run", return_value=fake):
        nets = csp._read_extra_nets("tailscale0")
    assert ipaddress.IPv4Network("192.168.31.0/24") in nets
    assert ipaddress.IPv4Network("100.100.100.100/32") in nets


@pytest.mark.unit
def test_read_extra_nets_handles_invalid_lines():
    """含非法行（首列不是合法 CIDR）→ 跳过、其余仍解析。"""
    fake = _fake_route_output(
        "default via 192.168.31.1 dev tailscale0\n"  # default 行无 CIDR
        "not-an-ip\n"
        "192.168.31.0/24 proto static\n"
    )
    with patch.object(csp.subprocess, "run", return_value=fake):
        nets = csp._read_extra_nets("tailscale0")
    assert nets == [ipaddress.IPv4Network("192.168.31.0/24")]


@pytest.mark.unit
def test_read_extra_nets_returns_empty_on_command_failure():
    """``ip route`` 返回非 0（tailscale0 不存在时常见）→ 空列表、不抛。"""
    fake = MagicMock()
    fake.returncode = 1
    fake.stdout = ""
    fake.stderr = "RTNETLINK answers: Network is unreachable"
    with patch.object(csp.subprocess, "run", return_value=fake):
        assert csp._read_extra_nets("tailscale0") == []


@pytest.mark.unit
def test_read_extra_nets_returns_empty_on_timeout():
    """subprocess 超时 → 空列表、不抛。"""
    import subprocess as _sp

    with patch.object(
        csp.subprocess, "run", side_effect=_sp.TimeoutExpired(cmd="ip", timeout=2)
    ):
        assert csp._read_extra_nets("tailscale0") == []


# ─── patch_is_cross_subnet_for_tailscale_subnets ────────────────────────────


@pytest.mark.unit
def test_patch_installs_method_at_class_level():
    """patch 后 ``_MIoTLanClass.is_cross_subnet`` 指向 patched 函数。"""
    fake = _fake_route_output("192.168.31.0/24 proto static\n")
    with patch.object(csp.subprocess, "run", return_value=fake):
        n = csp.patch_is_cross_subnet_for_tailscale_subnets("tailscale0")
    assert n == 1
    from miot.lan import MIoTLan as _MIoTLanClass

    assert _MIoTLanClass.is_cross_subnet is csp._patched_is_cross_subnet


@pytest.mark.unit
def test_patch_no_op_when_no_nets_on_iface():
    """tailscale0 不存在/ip 无路由 → 不替换方法（保持 SDK 原版），返回 0。"""
    fake = MagicMock()
    fake.returncode = 1
    fake.stdout = ""
    fake.stderr = ""
    from miot.lan import MIoTLan as _MIoTLanClass

    original = _MIoTLanClass.is_cross_subnet
    with patch.object(csp.subprocess, "run", return_value=fake):
        n = csp.patch_is_cross_subnet_for_tailscale_subnets("tailscale0")
    assert n == 0
    assert _MIoTLanClass.is_cross_subnet is original


@pytest.mark.unit
def test_patch_disabled_by_env(monkeypatch):
    """``MILOCO_DISABLE_TAILSCALE_SUBNET_PATCH=1`` → no-op、不动 SDK。"""
    monkeypatch.setenv("MILOCO_DISABLE_TAILSCALE_SUBNET_PATCH", "1")
    from miot.lan import MIoTLan as _MIoTLanClass

    original = _MIoTLanClass.is_cross_subnet
    fake = _fake_route_output("192.168.31.0/24\n")
    with patch.object(csp.subprocess, "run", return_value=fake) as run:
        n = csp.patch_is_cross_subnet_for_tailscale_subnets("tailscale0")
    assert n == 0
    assert _MIoTLanClass.is_cross_subnet is original
    run.assert_not_called()


# ─── patched 行为（核心契约）────────────────────────────────────────────────


def _install_patch_with(nets_cidr: list[str]):
    """装一个 stub _MIoTLanClass.is_cross_subnet（不再读 SDK 真实类）+ 注入子网。"""
    from miot.lan import MIoTLan as _MIoTLanClass

    # 模拟"原 SDK 方法"：始终返回 True（强制走到 patched 兜底分支）。
    def stub_orig(self, ip):
        return True

    csp._original_is_cross_subnet = _MIoTLanClass.is_cross_subnet
    # 把 SDK 类方法临时换为 stub，确保 _patched 包的是我们的 stub，不是 SDK 真品。
    _MIoTLanClass.is_cross_subnet = stub_orig  # type: ignore[assignment]
    csp._extra_nets = [ipaddress.IPv4Network(c) for c in nets_cidr]
    _MIoTLanClass.is_cross_subnet = csp._patched_is_cross_subnet  # type: ignore[assignment]


@pytest.mark.unit
def test_patched_downgrades_cross_subnet_to_same_when_in_extra_nets():
    """目标 IP 在注入子网里 → 跨网段被改判同段（False）。"""
    _install_patch_with(["192.168.31.0/24"])
    fake_mgr = MagicMock()
    assert csp._patched_is_cross_subnet(fake_mgr, "192.168.31.165") is False


@pytest.mark.unit
def test_patched_keeps_cross_subnet_when_outside_extra_nets():
    """目标 IP 不在注入子网里 → 仍判 True（不扩大"同段"语义）。"""
    _install_patch_with(["192.168.31.0/24"])
    fake_mgr = MagicMock()
    assert csp._patched_is_cross_subnet(fake_mgr, "10.0.0.5") is True


@pytest.mark.unit
def test_patched_passes_through_when_original_not_true():
    """原判定不是 True（同段=False 或判不出=None）→ 不改写，原样返回。

    这是关键防护：被某些相机特殊态触发原 SDK 的"判不出 → None"语义时，
    patched 绝不能擅自把它变成 True（那会让上层把一台其实同段的相机诊断成 NAT 阻断）。
    """
    from miot.lan import MIoTLan as _MIoTLanClass

    def stub_orig_none(self, ip):
        return None

    def stub_orig_false(self, ip):
        return False

    csp._original_is_cross_subnet = _MIoTLanClass.is_cross_subnet
    csp._extra_nets = [ipaddress.IPv4Network("192.168.31.0/24")]
    _MIoTLanClass.is_cross_subnet = csp._patched_is_cross_subnet  # type: ignore[assignment]

    fake_mgr = MagicMock()

    # Stub 的"original"是 None → patched 必须返回 None
    csp._original_is_cross_subnet = stub_orig_none
    assert csp._patched_is_cross_subnet(fake_mgr, "192.168.31.165") is None

    # Stub 的"original"是 False → patched 必须返回 False
    csp._original_is_cross_subnet = stub_orig_false
    assert csp._patched_is_cross_subnet(fake_mgr, "192.168.31.165") is False


@pytest.mark.unit
def test_patched_keeps_none_for_invalid_ip():
    """IP 非法 → SDK 原版返回 None（"判不出来"），patched 必须保留 None。

    这是关键防护：把一台"IP 缺失/格式错"（=SDK 本来判不出）的相机"强行判
    跨网段"会把上层引去折腾路由器，方向与 SDK 设计的"宁可少报也不错报"原则
    冲突。patched 不能改写 None。
    """
    _install_patch_with(["192.168.31.0/24"])
    fake_mgr = MagicMock()
    assert csp._patched_is_cross_subnet(fake_mgr, "not-an-ip") is None
    assert csp._patched_is_cross_subnet(fake_mgr, "") is None
    assert csp._patched_is_cross_subnet(fake_mgr, None) is None


@pytest.mark.unit
def test_patched_no_extra_nets_passes_through():
    """注入子网为空（罕见：patch 失败但方法已替换）→ 严格不扩大语义。"""
    from miot.lan import MIoTLan as _MIoTLanClass

    def stub_orig_true(self, ip):
        return True

    csp._original_is_cross_subnet = stub_orig_true
    csp._extra_nets = []
    _MIoTLanClass.is_cross_subnet = csp._patched_is_cross_subnet  # type: ignore[assignment]

    fake_mgr = MagicMock()
    assert csp._patched_is_cross_subnet(fake_mgr, "192.168.31.165") is True
