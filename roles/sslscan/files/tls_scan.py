#!/usr/bin/env python3
import ssl
import socket
import json
import subprocess
import sys
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# ------------------------------------------------------------
# Konstanten
# ------------------------------------------------------------
CONNECT_TIMEOUT = 3
MAX_SECLEVEL = 5


def output_result(result: dict) -> None:
    """Gibt das Ergebnis als JSON auf stdout aus."""
    print(json.dumps(result), file=sys.stdout, flush=True)


# ------------------------------------------------------------
# Prozessname zu PID ermitteln
# ------------------------------------------------------------
def get_process_cmd(pid: str) -> str:
    if not pid or pid in ["", "0"]:
        return ""
    try:
        return subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "cmd="],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except (subprocess.SubprocessError, OSError):
        return ""


# ------------------------------------------------------------
# RFC‑konformer Hostname‑Check
# ------------------------------------------------------------
def check_hostname_rfc(expected_hostname: str, cert: x509.Certificate) -> tuple[bool, str, str]:
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns = []

    if san_dns:
        presented = san_dns
    else:
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            presented = [cn]
        except (IndexError, ValueError):
            presented = []

    def match(host: str, pattern: str) -> bool:
        host_lower = host.lower()
        pattern_lower = pattern.lower()
        if pattern_lower.startswith("*."):
            suffix = pattern_lower[2:]
            if host_lower == suffix:
                return False
            return host_lower.endswith("." + suffix) and host_lower.count(".") == suffix.count(".") + 1
        return host_lower == pattern_lower

    for p in presented:
        if match(expected_hostname, p):
            return False, expected_hostname, p

    return True, expected_hostname, ", ".join(presented) if presented else ""


# ------------------------------------------------------------
# TLS‑Verbindung mit bestimmtem SECLEVEL testen
# ------------------------------------------------------------
def try_connect(ip: str, port: int | str, sni: Optional[str], seclevel: int) -> Optional[ssl.SSLSocket]:
    sock = None
    ssock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(f"DEFAULT@SECLEVEL={seclevel}")

        sock = socket.create_connection((ip, int(port)), timeout=CONNECT_TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=sni)

        if ssock.getpeercert(binary_form=True) is None:
            ssock.close()
            return None

        return ssock

    except (ssl.SSLError, socket.error, OSError):
        if ssock:
            ssock.close()
        elif sock:
            sock.close()
        return None


# ------------------------------------------------------------
# Hauptfunktion: TLS‑Scan
# ------------------------------------------------------------
def scan_tls(ip: str, port: int | str, pid: str, inventory_hostname: str) -> None:
    target_ip = "127.0.0.1" if ip in ["*", "0.0.0.0", "::", "::1"] else ip

    result = {
        "ip": ip,
        "port": port,
        "pid": pid,
        "process": get_process_cmd(pid),
        "tls_version": "",
        "cipher": "",
        "kex_info": "",
        "alpn": "",
        "compression": "",
        "session_resumed": "",
        "fingerprint_sha256": "",
        "key_usage": "",
        "ext_key_usage": "",
        "issuer": "",
        "subject": "",
        "not_after": "",
        "san": "",
        "chain": "",
        "hostname_mismatch": "",
        "hostname_expected": "",
        "hostname_presented": "",
        "seclevel": "",
        "error": ""
    }

    # ------------------------------------------------------------
    # 1. Höchsten funktionierenden SECLEVEL finden
    # ------------------------------------------------------------
    working_level = None
    for level in reversed(range(0, MAX_SECLEVEL + 1)):
        ssock = try_connect(target_ip, port, inventory_hostname, level)
        if ssock:
            working_level = level
            ssock.close()
            break

    if working_level is None:
        result["error"] = f"No TLS detected (SECLEVEL 0–{MAX_SECLEVEL} all failed)"
        output_result(result)
        return

    result["seclevel"] = working_level

    # ------------------------------------------------------------
    # 2. TLS‑Scan durchführen
    # ------------------------------------------------------------
    success = False
    for sni_host in [inventory_hostname, None]:
        if success:
            break

        ssock = try_connect(target_ip, port, sni_host, working_level)
        if not ssock:
            continue

        try:
            # TLS‑Basisdaten
            result["tls_version"] = ssock.version()
            cipher = ssock.cipher()
            result["cipher"] = cipher[0] if cipher else ""

            # ------------------------------------------------------------
            # Key Exchange Informationen
            # ------------------------------------------------------------
            if cipher:
                cname = cipher[0]
                if "ECDHE" in cname:
                    result["kex_info"] = "ECDHE"
                elif "DHE" in cname:
                    result["kex_info"] = "DHE"
                elif "RSA" in cname:
                    result["kex_info"] = "RSA"
                else:
                    result["kex_info"] = "UNKNOWN"

            # ------------------------------------------------------------
            # TLS‑Features
            # ------------------------------------------------------------
            result["alpn"] = ssock.selected_alpn_protocol() or ""
            result["compression"] = ssock.compression() or ""
            result["session_resumed"] = ssock.session_reused

            # ------------------------------------------------------------
            # Zertifikatskette
            # ------------------------------------------------------------
            der_chain = []
            if hasattr(ssock, "get_verified_chain"):
                try:
                    der_chain = [c.as_der() for c in ssock.get_verified_chain()]
                except (AttributeError, ssl.SSLError):
                    pass

            if not der_chain:
                leaf = ssock.getpeercert(binary_form=True)
                if not leaf:
                    result["error"] = "TLS handshake succeeded but no certificate was provided"
                    ssock.close()
                    output_result(result)
                    return
                der_chain = [leaf]

            chain_subjects = []

            for i, cert_der in enumerate(der_chain):
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                subject = cert.subject.rfc4514_string()
                chain_subjects.append(subject)

                if i == 0:
                    # Leaf‑Zertifikat
                    result["subject"] = subject
                    result["issuer"] = cert.issuer.rfc4514_string()
                    result["not_after"] = cert.not_valid_after_utc.isoformat()

                    # SAN
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        san_list = ext.value.get_values_for_type(x509.DNSName)
                        result["san"] = ";".join(san_list)
                    except x509.ExtensionNotFound:
                        pass

                    # SHA‑256 Fingerprint
                    result["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()

                    # Key Usage
                    try:
                        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                        usages = []
                        if ku.digital_signature: usages.append("DigitalSignature")
                        if ku.key_encipherment: usages.append("KeyEncipherment")
                        if ku.key_agreement: usages.append("KeyAgreement")
                        if ku.key_cert_sign: usages.append("KeyCertSign")
                        if ku.crl_sign: usages.append("CRLSign")
                        result["key_usage"] = ";".join(usages)
                    except x509.ExtensionNotFound:
                        pass

                    # Extended Key Usage
                    try:
                        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                        eku_list = [oid._name for oid in eku]
                        result["ext_key_usage"] = ";".join(eku_list)
                    except x509.ExtensionNotFound:
                        pass

                    # Hostname‑Mismatch
                    mismatch, expected, presented = check_hostname_rfc(inventory_hostname, cert)
                    result["hostname_mismatch"] = mismatch
                    result["hostname_expected"] = expected
                    result["hostname_presented"] = presented

            result["chain"] = " | ".join(chain_subjects)
            result["error"] = ""
            success = True

        except Exception as e:
            result["error"] = str(e)

        finally:
            ssock.close()

    output_result(result)


# ------------------------------------------------------------
# CLI‑Entry
# ------------------------------------------------------------
if __name__ == "__main__":
    args = sys.argv + ["", "", "", "", ""]
    scan_tls(args[1], args[2], args[3], args[4])
