#!/usr/bin/env python3
import subprocess
import json
import re
import argparse

def parse_ss_output(ignore_list):
    """
    Parst die Ausgabe von 'ss -tlnp' und gibt eine Liste von Sockets zurück.

    Returns:
        list: Liste von Socket-Dictionaries oder ein Dict mit 'error' Key bei Fehlern.
    """
    try:
        # Wir nutzen -p für Prozesse, -l für LISTEN, -t für TCP, -n für numerisch
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

        # IP und Port extrahieren (robust für IPv4 und IPv6)
        if local_addr.startswith("["):
            # IPv6 mit Brackets: [::1]:443 oder [fe80::1%eth0]:443
            bracket_end = local_addr.rfind("]:")
            if bracket_end == -1:
                continue
            ip = local_addr[1:bracket_end].split("%")[0]
            port = local_addr[bracket_end + 2:]
        else:
            # IPv4 oder IPv6 ohne Brackets
            raw_ip, port = local_addr.rsplit(":", 1)
            ip = raw_ip.split("%")[0]

        # Port als Integer validieren
        try:
            port = int(port)
        except ValueError:
            continue

        # 2. PID und Prozessname extrahieren (Robust über Regex)
        # Sucht nach users:(("PROZESSNAME",pid=PID,...))
        pid = ""
        process_name = ""
        
        # Suche nach pid
        pid_match = re.search(r"pid=(\d+)", line)
        if pid_match:
            pid = pid_match.group(1)
            
        # Suche nach Prozessnamen (Text zwischen ((" und ",pid)
        proc_match = re.search(r'\(+"([^"]+)",pid=', line)
        if proc_match:
            process_name = proc_match.group(1)

        sockets.append({
            "ip": ip,
            "port": port,
            "pid": pid,
            "process": process_name
        })

    return sockets

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ignore", help="Kommagetrennte Liste von IP:Port")
    args = parser.parse_args()
    
    ignore_list = args.ignore.split(",") if args.ignore else []
    result = parse_ss_output(ignore_list)
    print(json.dumps(result))