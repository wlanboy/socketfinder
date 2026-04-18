# socketfinder

Ansible-basiertes Tool zur automatischen Erkennung offener TCP-Sockets auf Linux-Servern und anschließendem TLS/SSL-Scan aller gefundenen Dienste. Die Ergebnisse werden als CSV exportiert und können direkt weiterverarbeitet werden.

## Funktionsweise

Das Tool läuft in drei Phasen:

1. **Socket-Erkennung** (`discover_sockets.py`): Auf jedem Ziel-Host werden via `ss -tlnp` alle lauschenden TCP-Sockets ermittelt. Systemd-interne Dienste, NetWorker-Prozesse und konfigurierbare Ignorier-Listen werden herausgefiltert.

2. **TLS-Scan** (`tls_scan.py`): Für jeden gefundenen Socket wird ein TLS-Handshake versucht. Das Script ermittelt automatisch den höchsten unterstützten OpenSSL-SECLEVEL (0–5), liest die vollständige Zertifikatskette via `openssl s_client` aus und extrahiert:
   - TLS-Version, Cipher Suite, Key-Exchange-Methode
   - ALPN-Protokoll, Kompression, Session-Resumption
   - Zertifikats-Fingerprint (SHA-256), Subject, Issuer, SAN, Ablaufdatum
   - Key Usage, Extended Key Usage
   - Vollständigkeit der Zertifikatskette

3. **CSV-Export**: Ergebnisse werden pro Host in zwei Dateien geschrieben — `<host>_tls.csv` (erfolgreiche Scans) und `<host>_errors.csv` (fehlgeschlagene Verbindungen) — und ins lokale `results/`-Verzeichnis übertragen.

## Voraussetzungen

- Ansible auf dem Control-Node
- Python 3.12+ auf den Ziel-Hosts
- `openssl`-CLI auf den Ziel-Hosts
- `ss` (iproute2) auf den Ziel-Hosts
- Sudo-Rechte auf den Ziel-Hosts (für `ss` mit Prozessinformationen)

## Installation (Control-Node)

```bash
uv lock --upgrade
uv run report.py
```

### Code-Qualität prüfen

```bash
uv pyright
uv ruff check
```

## Inventory

Das Inventory liegt unter `inventory/dev.yaml`. Ziel-Hosts werden der Gruppe `gmkservers` zugeordnet.

### Verbindung testen

```bash
ansible -i inventory/dev.yaml gmkservers -m ping
```

## Ausführung

### Alle Hosts scannen

```bash
ansible-playbook -i inventory/dev.yaml playbook.yml -K
```

### Einzelne Hosts scannen

```bash
# Nur localhost
ansible-playbook -i inventory/dev.yaml playbook.yml --limit localhost -K

# Bestimmten Host
ansible-playbook -i inventory/dev.yaml playbook.yml --limit gmk.lan -K
```

## Ergebnisse

Nach dem Lauf liegen die CSV-Dateien im Verzeichnis `results/`:

| Datei | Inhalt |
|---|---|
| `<host>_tls.csv` | Erfolgreiche TLS-Scans mit vollständigen Zertifikatsdaten |
| `<host>_errors.csv` | Sockets ohne TLS oder mit Verbindungsfehlern |

### Spalten in `_tls.csv`

`ip`, `port`, `process`, `tls_version`, `cipher`, `kex_info`, `alpn`, `compression`, `session_resumed`, `fingerprint_sha256`, `key_usage`, `ext_key_usage`, `issuer`, `subject`, `not_after`, `san`, `chain`, `chain_complete`, `seclevel`

## Sockets ignorieren

Nicht zu scannende Sockets werden in `roles/sslscan/ignored_sockets.yml` konfiguriert:

```yaml
ignored_ports:
  - { socket: "0.0.0.0:22",  comment: "Openssh server IPv4" }
  - { socket: "0.0.0.0:111", comment: "RPCbind IPv4" }
```

Vorkonfiguriert sind u.a.: SSH, DNS (systemd-resolved), RPCbind, Samba, CUPS, SMTP, libvirt/KVM, Kubernetes-interne Ports.

## Manueller TLS-Scan (einzelner Socket)

```bash
python3 roles/sslscan/files/tls_scan.py <ip> <port> <process> <inventory_hostname>

# Beispiele:
python3 roles/sslscan/files/tls_scan.py 192.168.178.91 8448 nginx gmk.lan
python3 roles/sslscan/files/tls_scan.py 192.168.178.91 2443 nginx gmk.lan
```

## Projektstruktur

```
socketfinder/
├── playbook.yml                        # Haupt-Playbook
├── inventory/
│   └── dev.yaml                        # Ansible-Inventory
├── results/                            # CSV-Ausgabe (nach dem Scan)
└── roles/sslscan/
    ├── ignored_sockets.yml             # Ignorier-Liste
    ├── files/
    │   ├── discover_sockets.py         # Socket-Erkennung via ss
    │   └── tls_scan.py                 # TLS-Scan + Zertifikatsanalyse
    └── tasks/
        ├── main.yml
        ├── discover_sockets.yml        # Phase 1: Sockets finden
        ├── scan_tls.yml                # Phase 2: TLS prüfen (async)
        └── write_csv.yml               # Phase 3: CSV schreiben
```
