#!/usr/bin/env python3
import subprocess
import json
import re
import argparse

SYSTEMD_NAMES = {
    "systemd",
    "systemd-resolved",
    "systemd-networkd",
    "systemd-journald",
    "systemd-timesyncd",
    "systemd-udevd"
}

def detect_systemd(ip, port, pid, process_name, line):
    """
    Erkennt systemd-basierte Sockets.
    """
    # 1. PID 1 = systemd
    if pid == "1":
        return True

    # 2. Prozessname ist ein bekannter systemd-Dienst
    if process_name in SYSTEMD_NAMES:
        return True

    # 3. systemd-resolved: 127.0.0.53:53
    if ip == "127.0.0.53" and port == 53:
        return True

    # 4. Kein Prozessname, aber systemd-Pattern in der Zeile
    if "systemd" in line and not process_name:
        return True

    return False


def parse_ss_output(ignore_list):
    try:
        output = subprocess.check_output(
            ["ss", "-tlnp"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="replace")
    except FileNotFoundError:
        return {"error": "ss command not found", "sockets": []}
    except subprocess.CalledProcessError as e:
        return {"error": f"ss command failed with exit code {e.returncode}", "sockets": []}

    sockets = []

    for line in output.splitlines()[1:]:
        # 1. Filterung: Falls die Zeile einen ignorierten Socket enthält
        if any(ignore_item in line for ignore_item in ignore_list):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        local_addr = parts[3]
        if ":" not in local_addr:
            continue

        # IPv4/IPv6 Parsing
        if local_addr.startswith("["):
            # IPv6 mit Brackets: [::1]:443 oder [fe80::1%eth0]:443
            bracket_end = local_addr.rfind("]:")
            if bracket_end == -1:
                continue
            ip = local_addr[1:bracket_end].split("%")[0]
            port = local_addr[bracket_end + 2:]
        else:
            raw_ip, port = local_addr.rsplit(":", 1)
            ip = raw_ip.split("%")[0]

        try:
            port = int(port)
        except ValueError:
            continue

        # PID & Prozessname
        pid = ""
        process_name = ""

        pid_match = re.search(r"pid=(\d+)", line)
        if pid_match:
            pid = pid_match.group(1)

        proc_match = re.search(r'\(+"([^"]+)",pid=', line)
        if proc_match:
            process_name = proc_match.group(1)

        # systemd-Erkennung
        is_systemd = detect_systemd(ip, port, pid, process_name, line)

        sockets.append({
            "ip": ip,
            "port": port,
            "pid": pid,
            "process": process_name,
            "systemd": is_systemd
        })

    return sockets


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ignore", help="Kommagetrennte Liste von IP:Port")
    args = parser.parse_args()

    ignore_list = args.ignore.split(",") if args.ignore else []
    result = parse_ss_output(ignore_list)
    print(json.dumps(result))
