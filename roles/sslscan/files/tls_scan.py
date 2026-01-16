#!/usr/bin/env python3
import ssl
import socket
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_process_cmd(pid):
    if not pid or pid == "" or pid == "0":
        return ""
    try:
        cmd = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "cmd="],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return cmd
    except Exception:
        return ""

def scan_tls(ip, port, pid):
    # Mapping von "*" auf localhost für den Scan-Verbindungsaufbau
    target_ip = "127.0.0.1" if ip in ["*", "0.0.0.0", "::"] else ip
    
    result = {
        "ip": ip,
        "port": port,
        "pid": pid,
        "process": get_process_cmd(pid),
        "tls_version": "",
        "cipher": "",
        "issuer": "",
        "subject": "",
        "not_after": "",
        "san": "",
        "chain": [],
        "error": ""
    }

    try:
        # Erstelle einen Kontext, der moderne und alte Protokolle erlaubt
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Manche Java-Apps benötigen explizit die Erlaubnis für ältere Ciphers
        ctx.set_ciphers('DEFAULT@SECLEVEL=1') 

        with socket.create_connection((target_ip, int(port)), timeout=5) as sock:
            # WICHTIG: server_hostname nur setzen, wenn es keine IP ist oder 
            # wenn der Handshake ohne SNI fehlschlägt. 
            # Wir versuchen es hier ohne SNI (server_hostname=None), 
            # da das bei Java/Spring meist stabiler gegen IPs ist.
            try:
                with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                    result["tls_version"] = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher"] = cipher[0]

                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        result["subject"] = cert.subject.rfc4514_string()
                        result["issuer"] = cert.issuer.rfc4514_string()
                        result["not_after"] = cert.not_valid_after.isoformat()
                        
                        try:
                            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                            result["san"] = ";".join(ext.value.get_values_for_type(x509.DNSName))
                        except: pass
                        result["chain"].append(cert.subject.rfc4514_string())
            except ssl.SSLError:
                # Zweiter Versuch MIT SNI, falls der Server es erzwingt
                with socket.create_connection((target_ip, int(port)), timeout=5) as sock2:
                    with ctx.wrap_socket(sock2, server_hostname="gmk.lan") as ssock:
                        # ... (gleiche Extraktionslogik wie oben)
                        result["tls_version"] = ssock.version()
                        # (der Kürze halber hier abgekürzt)

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 3:
        scan_tls(sys.argv[1], sys.argv[2], sys.argv[3])