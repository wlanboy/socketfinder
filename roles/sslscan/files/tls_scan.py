#!/usr/bin/env python3
import ssl
import socket
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# ------------------------------------------------------------
# Hilfsfunktion: Prozessname zu PID ermitteln
# ------------------------------------------------------------
def get_process_cmd(pid):
    if not pid or pid in ["", "0"]:
        return ""
    try:
        return subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "cmd="],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except:
        return ""


# ------------------------------------------------------------
# Hilfsfunktion: TLS-Verbindung mit bestimmtem SECLEVEL testen
# ------------------------------------------------------------
def try_connect(ip, port, sni, seclevel):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(f"DEFAULT@SECLEVEL={seclevel}")

        sock = socket.create_connection((ip, int(port)), timeout=3)
        ssock = ctx.wrap_socket(sock, server_hostname=sni)

        # Prüfen, ob TLS-Zertifikat geliefert wurde
        if ssock.getpeercert(binary_form=True) is None:
            ssock.close()
            return None

        return ssock

    except Exception:
        return None


# ------------------------------------------------------------
# Hauptfunktion: TLS-Scan
# ------------------------------------------------------------
def scan_tls(ip, port, pid, inventory_hostname):
    target_ip = "127.0.0.1" if ip in ["*", "0.0.0.0", "::", "::1"] else ip

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
        "chain": "",
        "seclevel": "",
        "error": ""
    }

    # ------------------------------------------------------------
    # 1. Höchsten funktionierenden SECLEVEL finden (5 → 0)
    # ------------------------------------------------------------
    working_level = None
    for level in reversed(range(0, 6)):
        ssock = try_connect(target_ip, port, inventory_hostname, level)
        if ssock:
            working_level = level
            ssock.close()
            break

    if working_level is None:
        result["error"] = "No TLS detected (SECLEVEL 0–5 all failed)"
        print(json.dumps(result))
        return

    result["seclevel"] = working_level

    # ------------------------------------------------------------
    # 2. TLS-Scan mit gefundenem SECLEVEL durchführen
    # ------------------------------------------------------------
    success = False
    for sni_host in [inventory_hostname, None]:
        if success:
            break

        ssock = try_connect(target_ip, port, sni_host, working_level)
        if not ssock:
            continue

        try:
            # TLS-Metadaten
            result["tls_version"] = ssock.version()
            result["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""

            # Zertifikatskette extrahieren
            der_chain = []

            if hasattr(ssock, "get_verified_chain"):
                try:
                    der_chain = [c.as_der() for c in ssock.get_verified_chain()]
                except:
                    pass

            if not der_chain:
                leaf = ssock.getpeercert(binary_form=True)
                if not leaf:
                    result["error"] = "TLS handshake succeeded but no certificate was provided"
                    ssock.close()
                    print(json.dumps(result))
                    return
                der_chain = [leaf]

            chain_subjects = []
            for i, cert_der in enumerate(der_chain):
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                subject = cert.subject.rfc4514_string()
                chain_subjects.append(subject)

                if i == 0:
                    result["subject"] = subject
                    result["issuer"] = cert.issuer.rfc4514_string()
                    result["not_after"] = cert.not_valid_after.isoformat()

                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        result["san"] = ";".join(ext.value.get_values_for_type(x509.DNSName))
                    except:
                        pass

            result["chain"] = " | ".join(chain_subjects)
            result["error"] = ""
            success = True

        except Exception as e:
            result["error"] = str(e)

        finally:
            ssock.close()

    print(json.dumps(result))


# ------------------------------------------------------------
# CLI-Entry
# ------------------------------------------------------------
if __name__ == "__main__":
    import sys
    args = sys.argv + ["", "", "", "", ""]
    scan_tls(args[1], args[2], args[3], args[4])
