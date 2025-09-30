import subprocess
from registro_incidentes import registrar_incidente

def menu():
    while True:
        print("\n=== SISTEMA DE SEGURIDAD EMPRESA ===")
        print("1. Monitor de red")
        print("2. Monitor Web HTTP")
        print("3. Monitor de eventos Windows")
        print("4. Escaneo de vulnerabilidades")
        print("5. Generar informe de seguridad")
        print("6. Bloqueo de IPS")
        print("7. Salir")
        opcion = input("Selecciona una opción: ")

        if opcion == "1":
            # Ejecuta monitor de red
            subprocess.run(["python", "monitor_red.py"])
        elif opcion == "2":
            # Ejecuta monitor HTTP
            subprocess.run(["python", "monitor_web_windows.py"])
        elif opcion == "3":
            # Ejecuta monitor de eventos Windows
            subprocess.run(["python", "monitor_eventos.py"])
        elif opcion == "4":
            # Ejecuta escaneo de vulnerabilidades interactivo
            subprocess.run(["python", "enterprise_vuln_scanner.py"])
        elif opcion == "5":
            # Genera informe de seguridad
            subprocess.run(["python", "informe_seguridad.py"])
        elif opcion == "6":
            # Ejecuta prevencion de IPS y las bloquea
            subprocess.run(["python", "prevencion_ips.py"])
        elif opcion == "7":
            print("Saliendo...")
            break
        else:
            print("Opción inválida. Intenta de nuevo.")

if __name__ == "__main__":
    menu()
