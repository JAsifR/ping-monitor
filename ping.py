#!/usr/bin/env python3
"""
Advanced Network Ping Monitor
Real-time monitoring of multiple hosts with latency tracking,
jitter, packet loss, uptime stats, geolocation and CSV logging.
For IT support and cybersecurity portfolio.
"""

import subprocess
import platform
import datetime
import time
import os
import csv
import socket
import threading
import requests
from collections import deque

# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    END    = '\033[0m'

# ── Hosts to monitor — add/remove as needed ───────────────────────────────────
HOSTS = [
    {"name": "Google DNS",       "ip": "8.8.8.8"},
    {"name": "Cloudflare DNS",   "ip": "1.1.1.1"},
    {"name": "OpenDNS",          "ip": "208.67.222.222"},
    {"name": "Local Router",     "ip": "192.168.1.1"},
    {"name": "Google",           "ip": "google.com"},
    {"name": "Cloudflare",       "ip": "cloudflare.com"},
]

# ── Per-host stats tracker ────────────────────────────────────────────────────
class HostStats:
    def __init__(self, name, ip):
        self.name         = name
        self.ip           = ip
        self.resolved_ip  = ip
        self.hostname     = ip
        self.geo          = ""
        self.latencies    = deque(maxlen=50)  # last 50 pings
        self.total_pings  = 0
        self.successful   = 0
        self.failed       = 0
        self.status       = "UNKNOWN"
        self.last_seen    = None
        self.outages      = []
        self.current_outage_start = None
        self.lock         = threading.Lock()

    @property
    def avg_latency(self):
        return round(sum(self.latencies) / len(self.latencies), 1) if self.latencies else 0

    @property
    def min_latency(self):
        return round(min(self.latencies), 1) if self.latencies else 0

    @property
    def max_latency(self):
        return round(max(self.latencies), 1) if self.latencies else 0

    @property
    def jitter(self):
        if len(self.latencies) < 2:
            return 0
        diffs = [abs(self.latencies[i] - self.latencies[i-1]) for i in range(1, len(self.latencies))]
        return round(sum(diffs) / len(diffs), 1)

    @property
    def packet_loss(self):
        if self.total_pings == 0:
            return 0
        return round((self.failed / self.total_pings) * 100, 1)

    @property
    def uptime_percent(self):
        if self.total_pings == 0:
            return 0
        return round((self.successful / self.total_pings) * 100, 1)

    def quality_rating(self):
        if self.status == "OFFLINE":
            return f"{C.RED}OFFLINE{C.END}", "OFFLINE"
        avg = self.avg_latency
        loss = self.packet_loss
        if loss == 0 and avg < 50:
            return f"{C.GREEN}EXCELLENT{C.END}", "EXCELLENT"
        elif loss < 2 and avg < 100:
            return f"{C.GREEN}GOOD{C.END}", "GOOD"
        elif loss < 5 and avg < 200:
            return f"{C.YELLOW}FAIR{C.END}", "FAIR"
        elif loss < 10 and avg < 500:
            return f"{C.YELLOW}POOR{C.END}", "POOR"
        else:
            return f"{C.RED}CRITICAL{C.END}", "CRITICAL"

# ── Ping function ─────────────────────────────────────────────────────────────
def ping_host(ip):
    """Ping a host and return latency in ms or None if failed"""
    param  = "-n" if platform.system().lower() == "windows" else "-c"
    w_flag = ["-w", "1000"] if platform.system().lower() == "windows" else ["-W", "1"]
    cmd    = ["ping", param, "1"] + w_flag + [ip]
    try:
        start  = time.time()
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elapsed = (time.time() - start) * 1000

        if result.returncode == 0:
            output = result.stdout.decode(errors="ignore")
            # Try to extract real latency from ping output
            import re
            # Windows: "Average = Xms"
            match = re.search(r'Average\s*=\s*(\d+)ms', output)
            if match:
                return float(match.group(1))
            # Linux: "time=X.X ms"
            match = re.search(r'time[=<]([\d.]+)\s*ms', output)
            if match:
                return float(match.group(1))
            return round(elapsed, 1)
        return None
    except Exception:
        return None

# ── Resolve DNS and geolocate ─────────────────────────────────────────────────
def resolve_host(stats):
    try:
        stats.resolved_ip = socket.gethostbyname(stats.ip)
        try:
            stats.hostname = socket.gethostbyaddr(stats.resolved_ip)[0]
        except:
            stats.hostname = stats.ip
    except:
        pass

    # Geolocate (skip private IPs)
    ip = stats.resolved_ip
    if not (ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.")):
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country,city,isp",
                timeout=3
            )
            if r.status_code == 200:
                data = r.json()
                city    = data.get("city", "")
                country = data.get("country", "")
                stats.geo = f"{city}, {country}" if city else country
        except:
            stats.geo = ""
    else:
        stats.geo = "Local Network"

# ── Save to CSV ───────────────────────────────────────────────────────────────
def save_csv(all_stats):
    os.makedirs("ping_logs", exist_ok=True)
    log_file   = "ping_logs/ping_monitor_log.csv"
    file_exists = os.path.exists(log_file)
    timestamp  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "Timestamp", "Host", "IP", "Status",
                "Avg Latency (ms)", "Min (ms)", "Max (ms)",
                "Jitter (ms)", "Packet Loss %", "Uptime %", "Quality"
            ])
        for s in all_stats:
            _, quality = s.quality_rating()
            writer.writerow([
                timestamp, s.name, s.resolved_ip, s.status,
                s.avg_latency, s.min_latency, s.max_latency,
                s.jitter, s.packet_loss, s.uptime_percent, quality
            ])

# ── Print live table ──────────────────────────────────────────────────────────
def print_table(all_stats, scan_num, total_scans):
    os.system('cls' if platform.system().lower() == 'windows' else 'clear')

    print(f"\n{C.BOLD}{'='*80}{C.END}")
    print(f"{C.BOLD}  ADVANCED NETWORK PING MONITOR{C.END}")
    print(f"  Scan {scan_num}/{total_scans} — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}{C.END}\n")

    # Table header
    print(f"  {C.BOLD}{'HOST':<18} {'IP':<16} {'STATUS':<10} {'AVG ms':<9} {'MIN':<7} {'MAX':<7} {'JITTER':<8} {'LOSS%':<7} {'UPTIME%':<9} {'QUALITY'}{C.END}")
    print(f"  {'─'*18} {'─'*16} {'─'*10} {'─'*9} {'─'*7} {'─'*7} {'─'*8} {'─'*7} {'─'*9} {'─'*10}")

    alerts = []
    for s in all_stats:
        if s.status == "ONLINE":
            status_str = f"{C.GREEN}ONLINE{C.END}"
        elif s.status == "OFFLINE":
            status_str = f"{C.RED}OFFLINE{C.END}"
        else:
            status_str = f"{C.YELLOW}UNKNOWN{C.END}"

        quality_str, quality_raw = s.quality_rating()

        avg  = f"{s.avg_latency}ms" if s.avg_latency else "—"
        mn   = f"{s.min_latency}ms" if s.min_latency else "—"
        mx   = f"{s.max_latency}ms" if s.max_latency else "—"
        jit  = f"{s.jitter}ms"    if s.jitter else "—"
        loss = f"{s.packet_loss}%"
        up   = f"{s.uptime_percent}%"

        print(f"  {s.name:<18} {s.resolved_ip:<16} {status_str:<20} {avg:<9} {mn:<7} {mx:<7} {jit:<8} {loss:<7} {up:<9} {quality_str}")

        # Collect alerts
        if s.status == "OFFLINE":
            alerts.append(f"{C.RED}  ⚠  {s.name} ({s.resolved_ip}) is OFFLINE!{C.END}")
        elif s.packet_loss >= 10:
            alerts.append(f"{C.YELLOW}  ⚠  {s.name} has high packet loss: {s.packet_loss}%{C.END}")
        elif s.avg_latency >= 200:
            alerts.append(f"{C.YELLOW}  ⚠  {s.name} has high latency: {s.avg_latency}ms{C.END}")

    # Geo info
    print(f"\n  {C.DIM}{'HOST':<18} {'LOCATION':<30} {'HOSTNAME'}{C.END}")
    print(f"  {C.DIM}{'─'*18} {'─'*30} {'─'*30}{C.END}")
    for s in all_stats:
        geo  = s.geo or "—"
        host = s.hostname[:35] if s.hostname != s.ip else "—"
        print(f"  {C.DIM}{s.name:<18} {geo:<30} {host}{C.END}")

    # Alerts
    print(f"\n{'='*80}")
    if alerts:
        print(f"{C.BOLD}  ALERTS:{C.END}")
        for a in alerts:
            print(a)
    else:
        print(f"  {C.GREEN}✅ All hosts reachable — network healthy{C.END}")

    # Outage log
    outage_log = []
    for s in all_stats:
        for o in s.outages[-3:]:  # show last 3 outages per host
            outage_log.append(f"  {s.name}: DOWN at {o['start']} — UP at {o.get('end','still down')}")
    if outage_log:
        print(f"\n{C.BOLD}  RECENT OUTAGES:{C.END}")
        for o in outage_log:
            print(f"{C.RED}{o}{C.END}")

    print(f"{'='*80}")
    print(f"  {C.DIM}Log saved to: ping_logs/ping_monitor_log.csv{C.END}")
    print(f"{'='*80}\n")

# ── Monitor loop ──────────────────────────────────────────────────────────────
def run_monitor(interval=5, runs=10):
    print(f"\n{C.BOLD}  ADVANCED NETWORK PING MONITOR{C.END}")
    print(f"  Initialising — resolving hosts and geolocating...\n")

    # Build stats objects
    all_stats = [HostStats(h["name"], h["ip"]) for h in HOSTS]

    # Resolve all hosts in parallel
    threads = [threading.Thread(target=resolve_host, args=(s,)) for s in all_stats]
    for t in threads: t.start()
    for t in threads: t.join()

    print(f"  {C.GREEN}All hosts resolved. Starting monitor...{C.END}\n")
    time.sleep(1)

    try:
        for scan in range(1, runs + 1):
            # Ping all hosts in parallel
            def ping_and_update(s):
                latency = ping_host(s.resolved_ip)
                with s.lock:
                    s.total_pings += 1
                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    if latency is not None:
                        s.latencies.append(latency)
                        s.successful += 1
                        s.last_seen   = ts
                        # End outage if there was one
                        if s.current_outage_start:
                            s.outages.append({
                                "start": s.current_outage_start,
                                "end":   ts
                            })
                            s.current_outage_start = None
                        s.status = "ONLINE"
                    else:
                        s.failed += 1
                        s.status  = "OFFLINE"
                        if not s.current_outage_start:
                            s.current_outage_start = ts
                            s.outages.append({"start": ts, "end": "ongoing"})

            ping_threads = [threading.Thread(target=ping_and_update, args=(s,)) for s in all_stats]
            for t in ping_threads: t.start()
            for t in ping_threads: t.join()

            print_table(all_stats, scan, runs)
            save_csv(all_stats)

            if scan < runs:
                time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Monitor stopped by user.{C.END}\n")

    # Final summary
    print(f"\n{C.BOLD}{'='*80}{C.END}")
    print(f"{C.BOLD}  FINAL SUMMARY{C.END}")
    print(f"{'='*80}\n")
    for s in all_stats:
        quality_str, _ = s.quality_rating()
        print(f"  {s.name:<20} Uptime: {s.uptime_percent}%  Avg: {s.avg_latency}ms  Loss: {s.packet_loss}%  Quality: {quality_str}")
    print(f"\n  Total outages logged: {sum(len(s.outages) for s in all_stats)}")
    print(f"  Full log: ping_logs/ping_monitor_log.csv")
    print(f"\n{'='*80}\n")


# ── Entry point ───────────────────────────────────────────────────────────────
print(f"\n{C.BOLD}{'='*60}{C.END}")
print(f"{C.BOLD}  ADVANCED NETWORK PING MONITOR{C.END}")
print(f"{'='*60}\n")
print("  How many scans to run?")
print("  [1] Quick test  — 5 scans (every 5s)")
print("  [2] Standard    — 20 scans (every 5s)")
print("  [3] Long run    — 60 scans (every 10s)")
print("  [4] Custom\n")

try:
    choice = input("  Select (1/2/3/4): ").strip()
    if choice == "1":
        runs, interval = 5, 5
    elif choice == "2":
        runs, interval = 20, 5
    elif choice == "3":
        runs, interval = 60, 10
    elif choice == "4":
        runs     = int(input("  Number of scans: "))
        interval = int(input("  Seconds between scans: "))
    else:
        runs, interval = 5, 5

    run_monitor(interval=interval, runs=runs)

except KeyboardInterrupt:
    print(f"\n\n  {C.YELLOW}Exited.{C.END}\n")
    