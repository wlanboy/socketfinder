#!/usr/bin/env python3
import subprocess
import json
import re

def parse_ss_output():
    """
    Ruft `ss -tlpen` auf und parst die Ausgabe robust.
    Liefert eine Liste von Dicts: {ip, port, pid}
    """

    try:
        output = subprocess.check_output(
            ["ss", "-tlpen"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="replace")
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return

    sockets = []

    # Jede Zeile durchgehen
    for line in output.splitlines()[1:]:  # erste Zeile ist Header
        parts = line.split()

        if len(parts) < 5:
            continue

        state = parts[0]
        local_addr = parts[3]
        proc_info = parts[6] if len(parts) > 6 else ""

        # Nur LISTEN-Sockets
        if state != "LISTEN":
            continue

        # Adresse muss IP:PORT enthalten
        if ":" not in local_addr:
            continue

        # IPv6 in [] entfernen
        local_addr = local_addr.strip("[]")

        # IP und Port extrahieren
        ip, port = local_addr.rsplit(":", 1)

        # Port muss eine Zahl sein
        if not port.isdigit():
            continue

        # PID extrahieren
        pid_match = re.search(r"pid=(\d+)", proc_info)
        pid = pid_match.group(1) if pid_match else ""

        sockets.append({
            "ip": ip,
            "port": port,
            "pid": pid
        })

    print(json.dumps(sockets))


if __name__ == "__main__":
    parse_ss_output()
