import win32evtlog  # Requiere: pip install pywin32
import re

def analizar_eventos():
    log_type = "Security"  
    server = "localhost"

    # Abrir el registro de eventos
    hand = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    eventos = []

    # Leer eventos
    while True:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break
        for ev_obj in records:
            if ev_obj.EventID == 4625:
                eventos.append(f"[ALERTA] Fallo de inicio de sesión detectado en {ev_obj.TimeGenerated}")
            elif ev_obj.EventID == 4688:
                eventos.append(f"[INFO] Creación de proceso detectada en {ev_obj.TimeGenerated}")

    win32evtlog.CloseEventLog(hand)
    return eventos


if __name__ == "__main__":
    resultados = analizar_eventos()
    if resultados:
        print("=== EVENTOS SOSPECHOSOS DETECTADOS ===")
        for r in resultados:
            print(r)
    else:
        print("No se detectaron eventos sospechosos.")
