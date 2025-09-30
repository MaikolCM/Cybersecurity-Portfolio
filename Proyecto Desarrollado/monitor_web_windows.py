import re
import subprocess
from scapy.all import sniff, IP, TCP, Raw
from registro_incidentes import registrar_incidente  # Para registrar eventos
from alertas_email import enviar_alerta_telegram      # Para enviar alertas por Telegram

# IPs bloqueadas
ips_bloqueadas = set()
ip_alerts = {}
resumen_incidentes = []  # Lista para guardar todos los eventos en tiempo real

# Patrones de ataques
SQLI_PATTERNS = [r"(\%27)|(\')|(\-\-)|(\%23)|(#)", r"(\b(OR|AND)\b\s+\w+\s*=\s*\w+)"]
XSS_PATTERNS = [r"<script.*?>.*?</script>", r"javascript:", r"(<.*?on\w+\s*=.*?>)"]

# Función para registrar resumen
def registrar_resumen(ip, tipo, detalle):
    resumen_incidentes.append({
        "ip": ip,
        "tipo": tipo,
        "detalle": detalle
    })

# Función para bloquear IP en Windows
def bloquear_ip_windows(ip):
    if ip not in ips_bloqueadas:
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=Bloqueo_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                check=True
            )
            ips_bloqueadas.add(ip)
            # Registrar y enviar alerta por Telegram
            registrar_incidente(ip, "Bloqueo IP", "IP bloqueada en firewall", "Regla aplicada")
            registrar_resumen(ip, "Bloqueo IP", "IP bloqueada en firewall")
            enviar_alerta_telegram(f"Alerta: IP {ip} bloqueada en firewall")
        except Exception as e:
            registrar_incidente(ip, "Error Bloqueo IP", str(e), "N/A")
            enviar_alerta_telegram(f"[ERROR] No se pudo bloquear la IP {ip}: {e}")

# Analizar paquetes HTTP
def analizar_paquete(paquete):
    if IP in paquete and TCP in paquete and Raw in paquete:
        ip_origen = paquete[IP].src
        payload = str(paquete[Raw].load)

        # Detectar SQL Injection
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                registrar_incidente(ip_origen, "SQL Injection", payload[:100], "IP bloqueada si es repetitivo")
                registrar_resumen(ip_origen, "SQL Injection", payload[:100])
                bloquear_ip_windows(ip_origen)
                enviar_alerta_telegram(f"SQL Injection detectado desde {ip_origen}")

        # Detectar XSS
        for pattern in XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                registrar_incidente(ip_origen, "XSS", payload[:100], "IP bloqueada si es repetitivo")
                registrar_resumen(ip_origen, "XSS", payload[:100])
                bloquear_ip_windows(ip_origen)
                enviar_alerta_telegram(f"XSS detectado desde {ip_origen}")

        # Detectar fuerza bruta HTTP
        if "POST" in payload and ("login" in payload.lower() or "password" in payload.lower()):
            ip_alerts[ip_origen] = ip_alerts.get(ip_origen, 0) + 1
            if ip_alerts[ip_origen] >= 5:
                registrar_incidente(ip_origen, "Fuerza Bruta HTTP", f"{ip_alerts[ip_origen]} intentos detectados", "IP bloqueada")
                registrar_resumen(ip_origen, "Fuerza Bruta HTTP", f"{ip_alerts[ip_origen]} intentos detectados")
                bloquear_ip_windows(ip_origen)
                enviar_alerta_telegram(f" Fuerza Bruta HTTP detectada desde {ip_origen}")
                ip_alerts[ip_origen] = 0

# Monitoreo con límite de tiempo (60 segundos)
TIEMPO_MONITOREO = 60
print(f"Monitoreando tráfico HTTP durante {TIEMPO_MONITOREO} segundos...")
sniff(filter="tcp", prn=analizar_paquete, store=0, timeout=TIEMPO_MONITOREO)
#sniff(filter="tcp port 80", prn=analizar_paquete, store=0, timeout=TIEMPO_MONITOREO)

# Mostrar resumen al finalizar
print("\nMonitoreo finalizado. Resumen de incidentes detectados:")
for incidente in resumen_incidentes:
    print(f"- IP: {incidente['ip']}, Tipo: {incidente['tipo']}, Detalle: {incidente['detalle']}")
