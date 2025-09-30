import subprocess
from scapy.all import sniff, IP, TCP
from alertas_email import enviar_alerta_telegram  # Para enviar alertas por Telegram

# Conjunto de IPs ya bloqueadas
ips_bloqueadas = set()

# Función para bloquear IP en Windows
def bloquear_ip_windows(ip):
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=Bloqueo_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
            check=True
        )
        print(f"IP bloqueada en Windows Firewall: {ip}")
        # Enviar alerta por Telegram
        enviar_alerta_telegram(f"Alerta: IP {ip} bloqueada en Windows Firewall")
    except Exception as e:
        print(f"Error bloqueando {ip}: {e}")
        enviar_alerta_telegram(f"[ERROR] No se pudo bloquear la IP {ip}: {e}")

# Función para analizar paquetes
def detectar_paquete(paquete):
    if IP in paquete:
        ip_origen = paquete[IP].src
        # Puertos sensibles (SSH/RDP)
        puertos_sensibles = [22, 3389]
        if TCP in paquete and paquete[TCP].dport in puertos_sensibles:
            if ip_origen not in ips_bloqueadas:
                print(f"IP sospechosa detectada: {ip_origen}")
                ips_bloqueadas.add(ip_origen)
                bloquear_ip_windows(ip_origen)

# Inicio del monitor de tráfico con límite de tiempo
TIEMPO_MONITOREO = 60  # segundos
print(f"Iniciando monitor de tráfico durante {TIEMPO_MONITOREO} segundos (Windows)...")
sniff(filter="ip", prn=detectar_paquete, store=0, timeout=TIEMPO_MONITOREO)

# Resumen final
print("\nMonitoreo finalizado. IPs bloqueadas:")
for ip in ips_bloqueadas:
    print(f"- {ip}")
