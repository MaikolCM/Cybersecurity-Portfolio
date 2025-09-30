import csv
import datetime
import os

# Archivo donde se guardarán los incidentes
LOG_FILE = "incidentes/incidentes.csv"

# Verificar si el archivo existe, si no crear con encabezados
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Fecha", "IP", "Tipo de Ataque", "Detalle", "Accion Tomada"])

# Función para registrar un incidente
def registrar_incidente(ip, tipo_ataque, detalle, accion):
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([fecha, ip, tipo_ataque, detalle, accion])
   # print(f"Incidente registrado: {tipo_ataque} desde {ip}")
