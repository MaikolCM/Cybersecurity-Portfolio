from scapy.all import sniff, IP, TCP
from registro_incidentes import registrar_incidente
from alertas_email import enviar_alerta_telegram  # Importa tu función de alertas

connection_attempts = {}

def detectar_paquete(paquete):
    if paquete.haslayer(IP) and paquete.haslayer(TCP):
        ip_origen = paquete[IP].src
        puerto_destino = paquete[TCP].dport

        # Registrar intento en el diccionario temporal
        if ip_origen not in connection_attempts:
            connection_attempts[ip_origen] = set()
        connection_attempts[ip_origen].add(puerto_destino)

        # Mostrar resumen por consola
        print(f"{ip_origen} intentó conectarse al puerto {puerto_destino}")

        #  Más de 10 puertos distintos ya es → sospechoso
        if len(connection_attempts[ip_origen]) > 10:
            print(f"Posible escaneo de puertos desde {ip_origen}")
            
            # Registrar incidente
            registrar_incidente(
                ip=ip_origen,
                tipo_ataque="Escaneo de puertos",
                detalle=f"Intento de conexión a {len(connection_attempts[ip_origen])} puertos",
                accion="Monitoreo activado"
            )
            
            # Enviar alerta por Telegram
            mensaje = f" Alerta de seguridad: posible escaneo de puertos desde {ip_origen} ({len(connection_attempts[ip_origen])} puertos intentados)"
            enviar_alerta_telegram(mensaje)

print("Monitoreando tráfico de red durante 60 segundos...")
sniff(prn=detectar_paquete, store=0, timeout=60)

print("\nEscaneo finalizado.")
print("Resumen de intentos detectados:")
for ip, puertos in connection_attempts.items():
    print(f"{ip} intentó conectarse a {len(puertos)} puertos")
    # Guardar conexiones normales
    if len(puertos) <= 10:
        registrar_incidente(
            ip=ip,
            tipo_ataque="Conexión TCP",
            detalle=f"Intento de conexión a {len(puertos)} puertos",
            accion="Monitoreo activado"
        )
