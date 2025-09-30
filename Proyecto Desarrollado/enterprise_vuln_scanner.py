#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise Vulnerability Scanner (Nmap wrapper)
- Requiere tener Nmap instalado y accesible en PATH.
- No usa dependencias extra (usa subprocess + XML parse).
- Ejecuta nmap con -sV y scripts NSE de categoría 'vuln' y extras útiles.
- Extrae:
    * Servicios, puertos, productos y versiones
    * CVEs (script vulners / vuln)
    * Configuraciones inseguras comunes (TLS débil, SMB signing, FTP anónimo, RDP, SSH algos débiles)
- Marca versiones 'obsoletas' con umbrales configurables.

Uso:
    python enterprise_vuln_scanner.py --targets 192.168.1.10
    python enterprise_vuln_scanner.py --targets 192.168.1.0/24
    python enterprise_vuln_scanner.py --file objetivos.txt
"""

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any

# ===== Configuración =====
NMAP_SCRIPTS = ",".join([
    "vulners",                # CVEs por versión
    "vuln",                   # categoría general de scripts de vulnerabilidad
    "ssl-enum-ciphers",       # TLS/SSL débiles
    "ssh2-enum-algos",        # SSH algoritmos
    "ftp-anon",               # FTP anónimo
    "smb2-security-mode",     # SMB signing, etc.
    "smb-security-mode",
    "rdp-enum-encryption",    # RDP cifrado/NLA
    "http-security-headers",  # encabezados de seguridad HTTP
    "http-title",
])

# Mínimos "saludables"
MIN_SAFE_VERSIONS = {
    "openssh": "8.0",
    "apache httpd": "2.4.60",
    "nginx": "1.20.0",
    "microsoft-iis": "10.0",
    "mysql": "8.0.0",
    "mariadb": "10.5.0",
    "postgresql": "12.0",
    "openssl": "1.1.1",
    "smb": "3.0",
}

WEAK_TLS_PATTERNS = [
    r"TLSv1\.0", r"TLSv1\.1", r"SSLv3", r"EXPORT", r"NULL cipher", r"weak"
]
WEAK_SSH_PATTERNS = [
    r"([-,\s]|^)diffie-hellman-group1-sha1", r"([-,\s]|^)ssh-dss",
    r"([-,\s]|^)hmac-md5", r"([-,\s]|^)cbc"
]

# ===== Funciones auxiliares =====
def which_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        sys.exit(" No se encontró Nmap en PATH. Instálalo desde https://nmap.org/download.html y vuelve a intentar.")
    return path

def parse_args_interactive():
    """
    Combina argparse con interacción por terminal si no se pasan argumentos.
    """
    ap = argparse.ArgumentParser(description="Scanner de vulnerabilidades (wrapper Nmap).")
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("--targets", help="IP/CIDR/host (ej: 192.168.1.10 o 192.168.1.0/24)")
    g.add_argument("--file", help="Archivo con una IP/host por línea")
    ap.add_argument("--top-ports", type=int, default=None, help="Cantidad de puertos top a escanear")
    ap.add_argument("--rate", type=int, default=None, help="Límite de velocidad --min-rate (p.ej. 500)")
    ap.add_argument("--os-detect", action="store_true", help="Intentar detección de SO (-O)")
    ap.add_argument("--timing", default=None, choices=["T2", "T3", "T4", "T5"], help="Perfil de tiempo de Nmap")

    args = ap.parse_args()

    # Si no se pasó ni targets ni file, pedimos al usuario
    if not args.targets and not args.file:
        modo = input("Desea ingresar (1) Targets o (2) Archivo? [1/2]: ").strip()
        if modo == "1":
            args.targets = input("Ingrese IP(s)/host separados por puntos: ").strip()
        elif modo == "2":
            args.file = input("Ingrese ruta al archivo de objetivos: ").strip()
        else:
            sys.exit("Opción inválida. Saliendo.")

    # Valores opcionales interactivos
    if args.top_ports is None:
        tp = input("Cantidad de top puertos a escanear [default 1000]: ").strip()
        args.top_ports = int(tp) if tp else 1000
    if args.timing is None:
        tm = input("Perfil de timing (T2,T3,T4,T5) [default T4]: ").strip().upper()
        args.timing = tm if tm in ["T2","T3","T4","T5"] else "T4"

    return args

def version_tuple(v: str):
    nums = re.findall(r"\d+", v)
    return tuple(int(x) for x in nums[:3]) if nums else (0,)

def is_outdated(product: str, version: str) -> bool:
    if not product or not version:
        return False
    p = product.lower().strip()
    for key in MIN_SAFE_VERSIONS.keys():
        if p.startswith(key):
            try:
                return version_tuple(version) < version_tuple(MIN_SAFE_VERSIONS[key])
            except Exception:
                return False
    return False

def run_nmap(targets: List[str], args) -> str:
    nmap_bin = which_nmap()
    cmd = [
        nmap_bin,
        "-sV",
        "-Pn",
        f"-{args.timing}",
        f"--top-ports", str(args.top_ports),
        "--script", NMAP_SCRIPTS,
        "-oX", "-"
    ]
    if args.os_detect:
        cmd.append("-O")
    if args.rate:
        cmd += ["--min-rate", str(args.rate)]

    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(",") if t.strip()]

    cmd += targets
    #print(" Ejecutando:", " ".join(cmd))
    print("Espere mientras se realiza el escaneo de vulnerabilidades...")

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except subprocess.CalledProcessError as e:
        print(e.output)
        sys.exit(f" Error ejecutando Nmap (código {e.returncode}).")

def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)
    report: Dict[str, Any] = {"hosts": []}

    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"
        hostnames = [hn.get("name") for hn in host.findall("hostnames/hostname")]
        os_name = None
        if host.find("os") is not None:
            osmatch = host.find("os").find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")

        services = []
        for port in host.findall("ports/port"):
            state = port.find("state").get("state") if port.find("state") is not None else "unknown"
            if state != "open":
                continue
            proto = port.get("protocol")
            pnum = int(port.get("portid"))
            service_elt = port.find("service")
            product = version = extrainfo = name = ""
            if service_elt is not None:
                name = service_elt.get("name") or ""
                product = service_elt.get("product") or ""
                version = service_elt.get("version") or ""
                extrainfo = service_elt.get("extrainfo") or ""

            scripts = []
            for sc in port.findall("script"):
                sid = sc.get("id") or "unknown"
                out = sc.get("output") or ""
                detail = out
                for child in sc.findall(".//elem"):
                    txt = (child.text or "").strip()
                    if txt:
                        detail += f"\n- {txt}"
                scripts.append({"id": sid, "output": detail})

            services.append({
                "port": pnum,
                "proto": proto,
                "name": name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "scripts": scripts
            })

        report["hosts"].append({
            "ip": ip,
            "hostnames": hostnames,
            "os": os_name,
            "services": services
        })

    return report

def analyze_findings(report: Dict[str, Any]) -> Dict[str, Any]:
    issues = []
    cves = []

    for h in report["hosts"]:
        ip = h["ip"]
        for s in h["services"]:
            product = (s["product"] or s["name"] or "").strip()
            version = (s["version"] or "").strip()

            if is_outdated(product, version):
                issues.append({
                    "severity": "MEDIUM",
                    "host": ip,
                    "port": s["port"],
                    "title": f"{product} {version} por debajo de umbral recomendado",
                    "details": f"Versión detectada: {product} {version}. Considera actualizar (política local)."
                })

            for sc in s["scripts"]:
                sid = sc["id"].lower()
                out = sc["output"]

                if "vulners" in sid or sid.startswith("vuln"):
                    for cve in re.findall(r"(CVE-\d{4}-\d{4,7})", out, re.I):
                        cves.append({
                            "host": ip,
                            "port": s["port"],
                            "product": product,
                            "version": version,
                            "cve": cve,
                            "source": sid
                        })
                    if "is VULNERABLE" in out or "VULNERABLE:" in out:
                        issues.append({
                            "severity": "HIGH",
                            "host": ip,
                            "port": s["port"],
                            "title": "Vulnerabilidad detectada por script NSE",
                            "details": f"Script {sid} reportó vulnerabilidad.\n{out[:400]}"
                        })

                if "ssl-enum-ciphers" in sid:
                    if any(re.search(pat, out, re.I) for pat in WEAK_TLS_PATTERNS):
                        issues.append({
                            "severity": "MEDIUM",
                            "host": ip,
                            "port": s["port"],
                            "title": "Protocolos/cifrados TLS débiles habilitados",
                            "details": out[:400]
                        })

                if "ssh2-enum-algos" in sid:
                    if any(re.search(pat, out, re.I) for pat in WEAK_SSH_PATTERNS):
                        issues.append({
                            "severity": "MEDIUM",
                            "host": ip,
                            "port": s["port"],
                            "title": "Algoritmos SSH débiles permitidos",
                            "details": out[:400]
                        })

                if "ftp-anon" in sid and re.search(r"Anonymous FTP login allowed", out, re.I):
                    issues.append({
                        "severity": "HIGH",
                        "host": ip,
                        "port": s["port"],
                        "title": "FTP anónimo habilitado",
                        "details": out[:400]
                    })

                if ("smb2-security-mode" in sid or "smb-security-mode" in sid) and re.search(r"message signing:\s*disabled", out, re.I):
                    issues.append({
                        "severity": "HIGH",
                        "host": ip,
                        "port": s["port"],
                        "title": "SMB Signing deshabilitado",
                        "details": out[:400]
                    })

                if "rdp-enum-encryption" in sid:
                    if re.search(r"NLA:\s*Disabled", out, re.I) or re.search(r"SSL\s*Protocol:\s*TLS1\.0", out, re.I):
                        issues.append({
                            "severity": "MEDIUM",
                            "host": ip,
                            "port": s["port"],
                            "title": "RDP con NLA deshabilitado o TLS débil",
                            "details": out[:400]
                        })

                if "http-security-headers" in sid and re.search(r"(missing|not present)", out, re.I):
                    issues.append({
                        "severity": "LOW",
                        "host": ip,
                        "port": s["port"],
                        "title": "Headers de seguridad HTTP ausentes",
                        "details": out[:400]
                    })

    return {"issues": issues, "cves": cves}

def save_reports(struct: Dict[str, Any]) -> Dict[str, str]:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(f"escaneo/scan_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "report.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(struct, f, indent=2, ensure_ascii=False)

    issues_csv = out_dir / "issues.csv"
    with issues_csv.open("w", encoding="utf-8") as f:
        f.write("severity,host,port,title,details\n")
        for i in struct.get("findings", {}).get("issues", []):
            d = (i.get("details") or "").replace("\n", " ").replace(",", ";")
            f.write(f"{i['severity']},{i['host']},{i['port']},{i['title'].replace(',', ';')},{d}\n")

    cves_csv = out_dir / "cves.csv"
    with cves_csv.open("w", encoding="utf-8") as f:
        f.write("host,port,product,version,cve,source\n")
        for c in struct.get("findings", {}).get("cves", []):
            f.write(f"{c['host']},{c['port']},{(c.get('product') or '').replace(',', ' ')},{c.get('version')},{c['cve']},{c['source']}\n")

    return {"json": str(json_path), "issues_csv": str(issues_csv), "cves_csv": str(cves_csv)}

# ===== Main =====
def main():
    args = parse_args_interactive()

    targets: List[str] = []
    if args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    else:
        lines = Path(args.file).read_text(encoding="utf-8").splitlines()
        targets = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]

    xml = run_nmap(targets, args)
    nmap_report = parse_nmap_xml(xml)
    findings = analyze_findings(nmap_report)

    struct = {
        "meta": {
            "generated_at": dt.datetime.now().isoformat(),
            "targets": targets,
            "top_ports": args.top_ports,
            "os_detect": args.os_detect,
            "timing": args.timing,
            "scripts": NMAP_SCRIPTS,
        },
        "nmap": nmap_report,
        "findings": findings
    }

    paths = save_reports(struct)

    total_hosts = len(nmap_report["hosts"])
    total_issues = len(findings["issues"])
    total_cves = len(findings["cves"])
    print("\n===== RESUMEN =====")
    print(f"Hosts analizados: {total_hosts}")
    print(f"Issues encontradas: {total_issues}")
    print(f"CVEs detectadas: {total_cves}")
    if total_issues:
        print("\nTop 5 issues:")
        for i in findings["issues"][:5]:
            print(f"- [{i['severity']}] {i['host']}:{i['port']} -> {i['title']}")

    print("\n Reportes guardados:")
    print(f"- JSON  : {paths['json']}")
    print(f"- Issues: {paths['issues_csv']}")
    print(f"- CVEs  : {paths['cves_csv']}")

if __name__ == "__main__":
    main()
