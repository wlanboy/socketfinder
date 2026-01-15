#!/usr/bin/env python3
import ssl
import socket
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_process_cmd(pid):
    """Return process command for a given PID."""
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
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, int(port)), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                # TLS version & cipher
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = cipher[0]

                # Leaf certificate
                der = ssock.getpeercert(binary_form=True)
                if der:
                    cert = x509.load_der_x509_certificate(der, default_backend())

                    result["subject"] = cert.subject.rfc4514_string()
                    result["issuer"] = cert.issuer.rfc4514_string()
                    result["not_after"] = cert.not_valid_after.isoformat()

                    # SAN
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        result["san"] = ";".join(ext.value.get_values_for_type(x509.DNSName))
                    except Exception:
                        pass

                    # Chain (OpenSSL only gives leaf)
                    result["chain"].append(cert.subject.rfc4514_string())

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result))


if __name__ == "__main__":
    import sys
    scan_tls(sys.argv[1], sys.argv[2], sys.argv[3])
