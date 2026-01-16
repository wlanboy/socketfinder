#!/usr/bin/env python3
import ssl
import socket
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_process_cmd(pid):
    if not pid or pid in ["", "0"]: return ""
    try:
        return subprocess.check_output(["ps", "-p", str(pid), "-o", "cmd="], 
               stderr=subprocess.DEVNULL).decode().strip()
    except: return ""

def scan_tls(ip, port, pid, inventory_hostname):
    target_ip = "127.0.0.1" if ip in ["*", "0.0.0.0", "::", "::1"] else ip
    
    result = {
        "ip": ip, "port": port, "pid": pid, "process": get_process_cmd(pid),
        "tls_version": "", "cipher": "", "issuer": "", "subject": "",
        "not_after": "", "san": "", "chain": "", "error": ""
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('DEFAULT@SECLEVEL=1')

    # STRATEGIE: 1. SNI (Vhost), 2. Ohne SNI (Fallback/Legacy)
    success = False
    for sni_host in [inventory_hostname, None]:
        if success: break
        try:
            with socket.create_connection((target_ip, int(port)), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                    result["tls_version"] = ssock.version()
                    result["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                    
                    # Zertifikatsdaten extrahieren
                    der_chain = []
                    # get_verified_chain liefert oft die komplette Kette (Py 3.10+)
                    if hasattr(ssock, 'get_verified_chain'):
                        try:
                            der_chain = [c.as_der() for c in ssock.get_verified_chain()]
                        except: pass
                    
                    # Wenn leer, nehmen wir zumindest das Leaf
                    if not der_chain:
                        leaf = ssock.getpeercert(binary_form=True)
                        if leaf: der_chain = [leaf]

                    chain_subjects = []
                    for i, cert_der in enumerate(der_chain):
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        subject = cert.subject.rfc4514_string()
                        chain_subjects.append(subject)
                        
                        # Metadaten nur vom ersten Zertifikat (Leaf)
                        if i == 0:
                            result["subject"] = subject
                            result["issuer"] = cert.issuer.rfc4514_string()
                            result["not_after"] = cert.not_valid_after.isoformat()
                            try:
                                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                                result["san"] = ";".join(ext.value.get_values_for_type(x509.DNSName))
                            except: pass

                    result["chain"] = " | ".join(chain_subjects)
                    result["error"] = "" # Fehler löschen, falls der zweite Versuch klappt
                    success = True
        except Exception as e:
            result["error"] = str(e)

    print(json.dumps(result))

if __name__ == "__main__":
    import sys
    args = sys.argv + ["", "", "", "", ""] # Padding gegen IndexErrors
    scan_tls(args[1], args[2], args[3], args[4])