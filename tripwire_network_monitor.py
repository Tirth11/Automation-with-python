"""
Tripwire Network Device Monitoring Solution
============================================
A Python-based Tripwire-style integrity and configuration monitoring tool
for network devices (routers, switches, firewalls).

Features:
  - Network device monitoring via ping, SNMP, and SSH config capture
  - Rule sets: define what aspects of a device to watch
  - Profiles: named collections of rule sets applied to device groups
  - Baseline capture with SHA-256 hash-based integrity checking
  - Change detection with drift alerts
  - Report generation: device status, change history, compliance summary

Usage:
  python tripwire_network_monitor.py
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """
    A single monitoring rule.

    Attributes:
        name         : Short identifier for the rule (e.g. "check_interfaces")
        description  : Human-readable description of what the rule watches
        category     : Functional category (e.g. "interface", "acl", "routing",
                       "snmp", "ntp", "aaa", "firmware")
        pattern      : Regex or keyword the rule searches for inside the captured
                       config/output.  Empty string means "capture everything".
        severity     : "critical" | "high" | "medium" | "low"
        enabled      : Whether this rule is active
    """
    name: str
    description: str
    category: str
    pattern: str = ""
    severity: str = "medium"
    enabled: bool = True

    def matches(self, text: str) -> List[str]:
        """Return all lines in *text* that match the rule's pattern."""
        if not self.pattern:
            return text.splitlines()
        return [line for line in text.splitlines()
                if re.search(self.pattern, line, re.IGNORECASE)]


@dataclass
class Profile:
    """
    A monitoring profile groups multiple rules and targets a class of devices.

    Attributes:
        name         : Unique profile name (e.g. "core_router_profile")
        description  : Human-readable description
        device_type  : Target device class ("router" | "switch" | "firewall" | "any")
        rules        : List of Rule objects belonging to this profile
        check_interval_minutes : How often (in minutes) checks should run
    """
    name: str
    description: str
    device_type: str = "any"
    rules: List[Rule] = field(default_factory=list)
    check_interval_minutes: int = 60

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def remove_rule(self, rule_name: str) -> bool:
        original_len = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        return len(self.rules) < original_len

    def enabled_rules(self) -> List[Rule]:
        return [r for r in self.rules if r.enabled]


@dataclass
class NetworkDevice:
    """
    Represents a monitored network device.

    Attributes:
        hostname     : Device hostname or label
        ip_address   : Management IP address
        device_type  : "router" | "switch" | "firewall" | "other"
        profile_name : Name of the Profile assigned to this device
        credentials  : Dict with keys "username" and "password" (optional/demo)
        snmp_community : SNMP community string (optional/demo)
    """
    hostname: str
    ip_address: str
    device_type: str = "router"
    profile_name: str = ""
    credentials: Dict[str, str] = field(default_factory=dict)
    snmp_community: str = "public"


@dataclass
class Baseline:
    """
    Stores a baseline snapshot for a device rule.

    Attributes:
        device_hostname : Device the baseline belongs to
        rule_name       : Rule that produced this baseline
        captured_at     : ISO-8601 timestamp of capture
        content         : Raw captured text
        content_hash    : SHA-256 hex digest of *content*
        matched_lines   : Lines that matched the rule pattern
    """
    device_hostname: str
    rule_name: str
    captured_at: str
    content: str
    content_hash: str
    matched_lines: List[str] = field(default_factory=list)


@dataclass
class ChangeEvent:
    """
    Records a detected change against a baseline.

    Attributes:
        device_hostname : Affected device
        rule_name       : Rule that detected the change
        detected_at     : ISO-8601 timestamp of detection
        severity        : Severity inherited from the rule
        previous_hash   : Baseline SHA-256 hash
        current_hash    : New SHA-256 hash
        added_lines     : Lines present now but not in baseline
        removed_lines   : Lines in baseline but no longer present
    """
    device_hostname: str
    rule_name: str
    detected_at: str
    severity: str
    previous_hash: str
    current_hash: str
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in rule library
# ---------------------------------------------------------------------------

BUILTIN_RULES: List[Rule] = [
    Rule(
        name="check_interfaces",
        description="Monitor interface configurations (IP addresses, admin state, MTU)",
        category="interface",
        pattern=r"(interface|ip address|shutdown|no shutdown|mtu)",
        severity="high",
    ),
    Rule(
        name="check_acl",
        description="Monitor Access Control List entries",
        category="acl",
        pattern=r"(access-list|permit|deny|acl)",
        severity="critical",
    ),
    Rule(
        name="check_routing",
        description="Monitor routing protocol configuration (OSPF, BGP, EIGRP, static routes)",
        category="routing",
        pattern=r"(router ospf|router bgp|router eigrp|ip route|network)",
        severity="high",
    ),
    Rule(
        name="check_snmp",
        description="Monitor SNMP community strings and trap targets",
        category="snmp",
        pattern=r"(snmp-server|community|trap)",
        severity="critical",
    ),
    Rule(
        name="check_ntp",
        description="Monitor NTP server configuration",
        category="ntp",
        pattern=r"(ntp server|ntp source|clock timezone)",
        severity="medium",
    ),
    Rule(
        name="check_aaa",
        description="Monitor AAA authentication, authorization, and accounting settings",
        category="aaa",
        pattern=r"(aaa|radius|tacacs|authentication|authorization|accounting)",
        severity="critical",
    ),
    Rule(
        name="check_firmware",
        description="Monitor firmware / software version string",
        category="firmware",
        pattern=r"(version|software|ios|firmware|release)",
        severity="high",
    ),
    Rule(
        name="check_logging",
        description="Monitor syslog and logging configuration",
        category="logging",
        pattern=r"(logging|syslog|log)",
        severity="medium",
    ),
    Rule(
        name="check_banner",
        description="Monitor login/MOTD banners",
        category="security",
        pattern=r"(banner|motd)",
        severity="low",
    ),
    Rule(
        name="check_ssh_telnet",
        description="Monitor SSH / Telnet access settings",
        category="security",
        pattern=r"(line vty|transport input|ssh|telnet)",
        severity="high",
    ),
    Rule(
        name="check_full_config",
        description="Capture and hash the entire running configuration for any change",
        category="full_config",
        pattern="",
        severity="medium",
    ),
]


# ---------------------------------------------------------------------------
# Built-in profile library
# ---------------------------------------------------------------------------

def build_core_router_profile() -> Profile:
    p = Profile(
        name="core_router_profile",
        description="Comprehensive monitoring profile for core / backbone routers",
        device_type="router",
        check_interval_minutes=30,
    )
    for rule_name in ("check_interfaces", "check_acl", "check_routing",
                      "check_snmp", "check_ntp", "check_aaa",
                      "check_firmware", "check_logging", "check_ssh_telnet",
                      "check_full_config"):
        rule = next((r for r in BUILTIN_RULES if r.name == rule_name), None)
        if rule:
            p.add_rule(rule)
    return p


def build_access_switch_profile() -> Profile:
    p = Profile(
        name="access_switch_profile",
        description="Monitoring profile for access-layer switches",
        device_type="switch",
        check_interval_minutes=60,
    )
    for rule_name in ("check_interfaces", "check_acl", "check_snmp",
                      "check_ntp", "check_aaa", "check_logging",
                      "check_ssh_telnet", "check_full_config"):
        rule = next((r for r in BUILTIN_RULES if r.name == rule_name), None)
        if rule:
            p.add_rule(rule)
    return p


def build_firewall_profile() -> Profile:
    p = Profile(
        name="firewall_profile",
        description="Strict monitoring profile for perimeter firewalls",
        device_type="firewall",
        check_interval_minutes=15,
    )
    for rule_name in ("check_acl", "check_snmp", "check_aaa",
                      "check_firmware", "check_logging",
                      "check_ssh_telnet", "check_full_config"):
        rule = next((r for r in BUILTIN_RULES if r.name == rule_name), None)
        if rule:
            p.add_rule(rule)
    return p


BUILTIN_PROFILES: List[Profile] = [
    build_core_router_profile(),
    build_access_switch_profile(),
    build_firewall_profile(),
]


# ---------------------------------------------------------------------------
# Device connector (simulation layer)
# ---------------------------------------------------------------------------

def _ping_device(ip_address: str, count: int = 2) -> bool:
    """
    Return True if the device responds to ICMP ping.
    Works on both Linux (ping -c) and Windows (ping -n).
    """
    param = "-n" if os.name == "nt" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, str(count), ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _resolve_hostname(ip_address: str) -> str:
    """Attempt a reverse DNS lookup; fall back to the IP on failure."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ip_address


def capture_device_config(device: NetworkDevice) -> str:
    """
    Simulate capturing the running configuration of a network device.

    In a real deployment this function would:
      - Open an SSH session (e.g. with Netmiko / Paramiko)
      - Run  'show running-config'  (Cisco IOS/IOS-XE)
                or  'display current-configuration'  (Huawei VRP)
      - Return the raw text output

    For demonstration purposes a realistic synthetic config is returned.
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    if device.device_type == "firewall":
        return f"""! Simulated firewall running-config  [{device.hostname}]  {ts}
version 9.14
hostname {device.hostname}
!
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.10 eq 443
access-list OUTSIDE_IN extended deny ip any any log
!
snmp-server community public ro
snmp-server community private rw
snmp-server trap-source GigabitEthernet0/0
!
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
!
logging host 10.0.0.5
logging trap informational
!
line vty 0 4
 transport input ssh
 login authentication default
!
banner motd ^
  Authorized access only. All activity is logged.
^
"""
    elif device.device_type == "switch":
        return f"""! Simulated switch running-config  [{device.hostname}]  {ts}
version 15.2
hostname {device.hostname}
!
interface GigabitEthernet0/1
 description Uplink to Core
 ip address 10.0.0.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/2
 description Access port VLAN 10
 switchport mode access
 switchport access vlan 10
 no shutdown
!
access-list 100 permit tcp 10.0.0.0 0.0.0.255 any eq 22
access-list 100 deny ip any any log
!
snmp-server community public ro
snmp-server host 10.0.0.5 traps public
!
ntp server 10.0.0.1
!
aaa new-model
aaa authentication login default group radius local
!
logging host 10.0.0.5
!
line vty 0 15
 access-class 100 in
 transport input ssh
!
"""
    else:  # default: router
        return f"""! Simulated router running-config  [{device.hostname}]  {ts}
version 15.7
hostname {device.hostname}
!
interface GigabitEthernet0/0
 description WAN link
 ip address 203.0.113.1 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 description LAN link
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
 network 203.0.113.0 0.0.0.3 area 0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.2
!
access-list 1 permit 10.0.0.0 0.0.0.255
access-list 1 deny any
!
snmp-server community public ro
snmp-server community private rw
snmp-server host 10.0.0.5 traps public
!
ntp server 10.0.0.5
ntp server 10.0.0.6
!
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ if-authenticated
aaa accounting exec default start-stop group tacacs+
!
logging host 10.0.0.5
logging trap debugging
!
line vty 0 4
 transport input ssh
 login authentication default
!
banner motd ^
  Authorized access only.
^
"""


# ---------------------------------------------------------------------------
# Core monitoring engine
# ---------------------------------------------------------------------------

class TripwireMonitor:
    """
    Central controller for Tripwire-style network device monitoring.

    Public API
    ----------
    add_device(device)              : Register a NetworkDevice
    assign_profile(hostname, name)  : Assign a Profile to a device
    capture_baseline(hostname)      : Take the initial reference snapshot
    run_check(hostname)             : Compare current state to baseline
    generate_report(...)            : Produce a formatted monitoring report
    """

    def __init__(self) -> None:
        self.devices: Dict[str, NetworkDevice] = {}
        self.profiles: Dict[str, Profile] = {p.name: p for p in BUILTIN_PROFILES}
        self.baselines: Dict[str, Dict[str, Baseline]] = {}   # hostname -> rule_name -> Baseline
        self.change_events: List[ChangeEvent] = []

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def add_device(self, device: NetworkDevice) -> None:
        self.devices[device.hostname] = device
        self.baselines.setdefault(device.hostname, {})

    def remove_device(self, hostname: str) -> bool:
        if hostname in self.devices:
            del self.devices[hostname]
            self.baselines.pop(hostname, None)
            return True
        return False

    def list_devices(self) -> List[NetworkDevice]:
        return list(self.devices.values())

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def add_profile(self, profile: Profile) -> None:
        self.profiles[profile.name] = profile

    def assign_profile(self, hostname: str, profile_name: str) -> bool:
        if hostname not in self.devices:
            return False
        if profile_name not in self.profiles:
            return False
        self.devices[hostname].profile_name = profile_name
        return True

    def list_profiles(self) -> List[Profile]:
        return list(self.profiles.values())

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule_to_profile(self, profile_name: str, rule: Rule) -> bool:
        if profile_name not in self.profiles:
            return False
        self.profiles[profile_name].add_rule(rule)
        return True

    def remove_rule_from_profile(self, profile_name: str, rule_name: str) -> bool:
        if profile_name not in self.profiles:
            return False
        return self.profiles[profile_name].remove_rule(rule_name)

    # ------------------------------------------------------------------
    # Baseline capture
    # ------------------------------------------------------------------

    def _compute_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def capture_baseline(self, hostname: str) -> Dict[str, Baseline]:
        """
        Capture a fresh baseline for all enabled rules in the device's profile.
        Returns a dict mapping rule_name -> Baseline.
        """
        device = self.devices.get(hostname)
        if not device:
            raise ValueError(f"Unknown device: {hostname}")

        profile = self.profiles.get(device.profile_name)
        if not profile:
            raise ValueError(f"No profile assigned to device '{hostname}'")

        config_text = capture_device_config(device)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        captured: Dict[str, Baseline] = {}
        for rule in profile.enabled_rules():
            matched = rule.matches(config_text)
            section = "\n".join(matched)
            baseline = Baseline(
                device_hostname=hostname,
                rule_name=rule.name,
                captured_at=now,
                content=section,
                content_hash=self._compute_hash(section),
                matched_lines=matched,
            )
            captured[rule.name] = baseline
            self.baselines[hostname][rule.name] = baseline

        return captured

    # ------------------------------------------------------------------
    # Change detection
    # ------------------------------------------------------------------

    def run_check(self, hostname: str) -> List[ChangeEvent]:
        """
        Compare current device state to stored baselines.
        Returns a list of ChangeEvent objects for any deviations found.
        """
        device = self.devices.get(hostname)
        if not device:
            raise ValueError(f"Unknown device: {hostname}")

        profile = self.profiles.get(device.profile_name)
        if not profile:
            raise ValueError(f"No profile assigned to device '{hostname}'")

        if hostname not in self.baselines or not self.baselines[hostname]:
            raise RuntimeError(f"No baseline captured for '{hostname}'. "
                               "Run capture_baseline() first.")

        config_text = capture_device_config(device)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        new_events: List[ChangeEvent] = []

        for rule in profile.enabled_rules():
            baseline = self.baselines[hostname].get(rule.name)
            if baseline is None:
                continue

            matched = rule.matches(config_text)
            current_section = "\n".join(matched)
            current_hash = self._compute_hash(current_section)

            if current_hash != baseline.content_hash:
                baseline_lines = set(baseline.matched_lines)
                current_lines = set(matched)
                event = ChangeEvent(
                    device_hostname=hostname,
                    rule_name=rule.name,
                    detected_at=now,
                    severity=rule.severity,
                    previous_hash=baseline.content_hash,
                    current_hash=current_hash,
                    added_lines=sorted(current_lines - baseline_lines),
                    removed_lines=sorted(baseline_lines - current_lines),
                )
                new_events.append(event)
                self.change_events.append(event)

        return new_events

    # ------------------------------------------------------------------
    # Reachability check
    # ------------------------------------------------------------------

    def check_reachability(self, hostname: str) -> bool:
        device = self.devices.get(hostname)
        if not device:
            return False
        return _ping_device(device.ip_address)

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        hostname: Optional[str] = None,
        severity_filter: Optional[str] = None,
        report_format: str = "text",
    ) -> str:
        """
        Generate a monitoring report.

        Parameters
        ----------
        hostname        : Limit report to a single device (None = all devices)
        severity_filter : Only include events at or above this severity
                          ("critical" | "high" | "medium" | "low" | None)
        report_format   : "text" (default) | "json"

        Report sections
        ---------------
        1. Report header (timestamp, scope)
        2. Device inventory summary
        3. Profile & rule set summary
        4. Baseline information per device
        5. Change / drift events (filtered by severity)
        6. Compliance summary (% devices with no changes detected)
        """
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_severity = severity_order.get(severity_filter or "low", 1)

        target_devices = (
            [self.devices[hostname]] if hostname and hostname in self.devices
            else list(self.devices.values())
        )
        target_hostnames = {d.hostname for d in target_devices}

        filtered_events = [
            e for e in self.change_events
            if e.device_hostname in target_hostnames
            and severity_order.get(e.severity, 0) >= min_severity
        ]

        if report_format == "json":
            return self._generate_json_report(target_devices, filtered_events)
        return self._generate_text_report(target_devices, filtered_events, severity_filter)

    # ------------------------------------------------------------------

    def _generate_text_report(
        self,
        devices: List[NetworkDevice],
        events: List[ChangeEvent],
        severity_filter: Optional[str],
    ) -> str:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        width = 72
        lines: List[str] = []

        def hr(char: str = "=") -> None:
            lines.append(char * width)

        def section(title: str) -> None:
            hr()
            lines.append(f"  {title}")
            hr()

        # ---- Header -------------------------------------------------------
        hr("*")
        lines.append(" " * 15 + "TRIPWIRE NETWORK DEVICE MONITORING REPORT")
        lines.append(f"  Generated : {now}")
        lines.append(f"  Scope     : {'All devices' if len(devices) == len(self.devices) else ', '.join(d.hostname for d in devices)}")
        lines.append(f"  Severity filter : {severity_filter or 'none (all severities)'}")
        hr("*")
        lines.append("")

        # ---- 1. Device Inventory ------------------------------------------
        section("1. DEVICE INVENTORY")
        header = f"  {'Hostname':<20} {'IP Address':<16} {'Type':<10} {'Profile':<30}"
        lines.append(header)
        hr("-")
        for d in devices:
            profile_name = d.profile_name or "(none)"
            lines.append(
                f"  {d.hostname:<20} {d.ip_address:<16} {d.device_type:<10} {profile_name:<30}"
            )
        lines.append(f"\n  Total devices monitored: {len(devices)}")
        lines.append("")

        # ---- 2. Profile & Rule Set Summary --------------------------------
        section("2. PROFILE & RULE SET SUMMARY")
        profiles_in_use = {d.profile_name for d in devices if d.profile_name}
        for pname in sorted(profiles_in_use):
            profile = self.profiles.get(pname)
            if not profile:
                continue
            lines.append(f"\n  Profile : {profile.name}")
            lines.append(f"  Device type targeted : {profile.device_type}")
            lines.append(f"  Description : {profile.description}")
            lines.append(f"  Check interval : every {profile.check_interval_minutes} minutes")
            lines.append(f"  Active rules ({len(profile.enabled_rules())}):")
            hr("-")
            rhdr = f"    {'Rule Name':<28} {'Category':<14} {'Severity':<10} {'Pattern'}"
            lines.append(rhdr)
            hr("-")
            for rule in profile.enabled_rules():
                pat = rule.pattern[:30] + "..." if len(rule.pattern) > 30 else rule.pattern
                lines.append(
                    f"    {rule.name:<28} {rule.category:<14} {rule.severity:<10} {pat}"
                )
        lines.append("")

        # ---- 3. Baseline Information --------------------------------------
        section("3. BASELINE INFORMATION")
        for d in devices:
            device_baselines = self.baselines.get(d.hostname, {})
            lines.append(f"\n  Device : {d.hostname}  ({d.ip_address})")
            if not device_baselines:
                lines.append("    [!] No baseline captured yet")
                continue
            for rule_name, bl in device_baselines.items():
                lines.append(
                    f"    Rule '{rule_name}' — captured {bl.captured_at}"
                )
                lines.append(f"      SHA-256 : {bl.content_hash}")
                lines.append(f"      Matched lines in baseline : {len(bl.matched_lines)}")
        lines.append("")

        # ---- 4. Change / Drift Events ------------------------------------
        section("4. CHANGE / DRIFT EVENTS")
        if not events:
            lines.append("\n  [OK] No changes detected against baselines.\n")
        else:
            # group by device
            events_by_device: Dict[str, List[ChangeEvent]] = {}
            for e in events:
                events_by_device.setdefault(e.device_hostname, []).append(e)

            for hostname, devents in sorted(events_by_device.items()):
                lines.append(f"\n  Device : {hostname}")
                hr("-")
                for e in devents:
                    lines.append(f"    Rule      : {e.rule_name}")
                    lines.append(f"    Severity  : {e.severity.upper()}")
                    lines.append(f"    Detected  : {e.detected_at}")
                    lines.append(f"    Prev hash : {e.previous_hash}")
                    lines.append(f"    Curr hash : {e.current_hash}")
                    if e.added_lines:
                        lines.append("    Added lines:")
                        for ln in e.added_lines:
                            lines.append(f"      + {ln}")
                    if e.removed_lines:
                        lines.append("    Removed lines:")
                        for ln in e.removed_lines:
                            lines.append(f"      - {ln}")
                    lines.append("")
        lines.append("")

        # ---- 5. Compliance Summary ----------------------------------------
        section("5. COMPLIANCE SUMMARY")
        changed_hosts = {e.device_hostname for e in events}
        clean_count = sum(1 for d in devices if d.hostname not in changed_hosts)
        total = len(devices)
        compliance_pct = (clean_count / total * 100) if total else 0.0

        lines.append(f"\n  Total devices in scope     : {total}")
        lines.append(f"  Devices with NO changes    : {clean_count}  ({compliance_pct:.1f}%)")
        lines.append(f"  Devices with changes       : {total - clean_count}")

        critical_events = [e for e in events if e.severity == "critical"]
        high_events = [e for e in events if e.severity == "high"]
        lines.append(f"\n  Change events by severity:")
        lines.append(f"    CRITICAL : {len(critical_events)}")
        lines.append(f"    HIGH     : {len(high_events)}")
        lines.append(f"    MEDIUM   : {sum(1 for e in events if e.severity == 'medium')}")
        lines.append(f"    LOW      : {sum(1 for e in events if e.severity == 'low')}")

        if compliance_pct == 100.0:
            lines.append("\n  [PASS] All monitored devices are compliant.")
        elif compliance_pct >= 80.0:
            lines.append("\n  [WARN] Some devices show configuration drift. Review changes.")
        else:
            lines.append("\n  [FAIL] Significant configuration drift detected. Immediate review required.")

        lines.append("")
        hr("*")
        lines.append("  END OF REPORT")
        hr("*")

        return "\n".join(lines)

    # ------------------------------------------------------------------

    def _generate_json_report(
        self,
        devices: List[NetworkDevice],
        events: List[ChangeEvent],
    ) -> str:
        report = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "devices": [asdict(d) for d in devices],
            "profiles": [
                {
                    "name": p.name,
                    "description": p.description,
                    "device_type": p.device_type,
                    "check_interval_minutes": p.check_interval_minutes,
                    "rules": [asdict(r) for r in p.enabled_rules()],
                }
                for p in {
                    d.profile_name: self.profiles[d.profile_name]
                    for d in devices if d.profile_name in self.profiles
                }.values()
            ],
            "baselines": {
                hostname: {
                    rule_name: asdict(bl)
                    for rule_name, bl in rules.items()
                }
                for hostname, rules in self.baselines.items()
                if hostname in {d.hostname for d in devices}
            },
            "change_events": [asdict(e) for e in events],
            "compliance_summary": {
                "total_devices": len(devices),
                "compliant_devices": sum(
                    1 for d in devices
                    if d.hostname not in {e.device_hostname for e in events}
                ),
                "events_by_severity": {
                    sev: sum(1 for e in events if e.severity == sev)
                    for sev in ("critical", "high", "medium", "low")
                },
            },
        }
        return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# Demo / interactive CLI
# ---------------------------------------------------------------------------

def _demo() -> None:
    """
    Demonstrate the Tripwire monitoring workflow end-to-end:
      1. Create the monitor instance
      2. Register devices
      3. Assign profiles
      4. Capture baselines
      5. Simulate a configuration change
      6. Run checks (change detection)
      7. Generate a full text report
      8. Generate a JSON report excerpt
    """
    print("\n" + "=" * 72)
    print("  TRIPWIRE NETWORK DEVICE MONITORING SOLUTION  —  DEMO")
    print("=" * 72 + "\n")

    monitor = TripwireMonitor()

    # ---- Register devices -------------------------------------------------
    devices = [
        NetworkDevice(
            hostname="core-router-01",
            ip_address="10.0.0.1",
            device_type="router",
        ),
        NetworkDevice(
            hostname="access-switch-01",
            ip_address="10.0.0.2",
            device_type="switch",
        ),
        NetworkDevice(
            hostname="edge-firewall-01",
            ip_address="10.0.0.3",
            device_type="firewall",
        ),
    ]
    for d in devices:
        monitor.add_device(d)
        print(f"  [+] Registered device : {d.hostname}  ({d.ip_address})")

    # ---- Assign profiles --------------------------------------------------
    print()
    profile_map = {
        "core-router-01": "core_router_profile",
        "access-switch-01": "access_switch_profile",
        "edge-firewall-01": "firewall_profile",
    }
    for hostname, profile_name in profile_map.items():
        monitor.assign_profile(hostname, profile_name)
        print(f"  [~] Assigned profile '{profile_name}' to '{hostname}'")

    # ---- Show available profiles & rules ----------------------------------
    print("\n" + "-" * 72)
    print("  Available profiles and their rule sets:")
    print("-" * 72)
    for profile in monitor.list_profiles():
        print(f"\n  Profile : {profile.name}  [{profile.device_type}]")
        print(f"           {profile.description}")
        print(f"           Check interval: every {profile.check_interval_minutes} min")
        print(f"           Rules ({len(profile.enabled_rules())}):")
        for rule in profile.enabled_rules():
            print(f"             • {rule.name:<28}  [{rule.severity.upper():8}]  {rule.description}")

    # ---- Capture baselines ------------------------------------------------
    print("\n" + "-" * 72)
    print("  Capturing baselines ...")
    print("-" * 72)
    for d in devices:
        baselines = monitor.capture_baseline(d.hostname)
        print(f"  [✔] Baseline captured for '{d.hostname}'  "
              f"({len(baselines)} rule(s) hashed)")

    # ---- Add a custom rule and re-apply -----------------------------------
    print("\n" + "-" * 72)
    print("  Adding a custom rule to core_router_profile ...")
    print("-" * 72)
    custom_rule = Rule(
        name="check_bgp_neighbors",
        description="Monitor BGP neighbor configurations",
        category="routing",
        pattern=r"(neighbor|remote-as|update-source|bgp)",
        severity="critical",
    )
    monitor.add_rule_to_profile("core_router_profile", custom_rule)
    print(f"  [+] Added rule '{custom_rule.name}' to 'core_router_profile'")

    # ---- Simulate a config change by monkey-patching capture_device_config -
    _original_capture = capture_device_config   # save reference

    def _patched_capture(device: NetworkDevice) -> str:
        """Return a slightly modified config for edge-firewall-01 to simulate drift."""
        base = _original_capture(device)
        if device.hostname == "edge-firewall-01":
            # Add a new risky ACL entry (simulated unauthorized change)
            base = base.replace(
                "access-list OUTSIDE_IN extended deny ip any any log",
                "access-list OUTSIDE_IN extended permit ip any any\n"
                "access-list OUTSIDE_IN extended deny ip any any log",
            )
            # Remove the read-only SNMP community string (simulated deletion)
            base = base.replace("snmp-server community public ro\n", "")
        return base

    globals()["capture_device_config"] = _patched_capture

    # ---- Run checks -------------------------------------------------------
    print("\n" + "-" * 72)
    print("  Running integrity checks ...")
    print("-" * 72)
    total_events = 0
    for d in devices:
        events = monitor.run_check(d.hostname)
        total_events += len(events)
        if events:
            print(f"  [!] {d.hostname}: {len(events)} change event(s) detected")
            for e in events:
                print(f"      Rule='{e.rule_name}', Severity={e.severity.upper()}")
        else:
            print(f"  [✔] {d.hostname}: no changes detected")

    # ---- Restore original capture function --------------------------------
    globals()["capture_device_config"] = _original_capture

    # ---- Generate text report ---------------------------------------------
    print("\n")
    text_report = monitor.generate_report()
    print(text_report)

    # ---- Generate JSON report (excerpt) -----------------------------------
    json_report = monitor.generate_report(report_format="json")
    data = json.loads(json_report)
    print("\n" + "-" * 72)
    print("  JSON report excerpt  (compliance_summary):")
    print("-" * 72)
    print(json.dumps(data["compliance_summary"], indent=4))
    print()


if __name__ == "__main__":
    _demo()
