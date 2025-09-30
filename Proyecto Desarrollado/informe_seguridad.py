import pandas as pd
import pdfkit
from datetime import datetime

CSV_FILE = "incidentes/incidentes.csv"
HTML_FILE = "informe/informe_seguridad.html"
PDF_FILE = "informe/informe_seguridad.pdf"

# Ruta al ejecutable wkhtmltopdf
path_wkhtmltopdf = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

# Leer CSV
df = pd.read_csv(CSV_FILE)

# Estadísticas básicas
total_incidentes = len(df)
tipos_ataques = df['Tipo de Ataque'].value_counts()

# Crear HTML del informe
html = f"""
<h1>Informe de Seguridad</h1>
<p>Fecha de generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total de incidentes detectados: {total_incidentes}</p>
<h2>Tipos de ataques</h2>
<ul>
"""

for tipo, count in tipos_ataques.items():
    html += f"<li>{tipo}: {count}</li>"

html += "</ul>"

html += "<h2>Detalles de incidentes</h2><table border='1'><tr><th>Fecha</th><th>IP</th><th>Tipo</th><th>Detalle</th><th>Acción</th></tr>"

for _, row in df.iterrows():
    html += f"<tr><td>{row['Fecha']}</td><td>{row['IP']}</td><td>{row['Tipo de Ataque']}</td><td>{row['Detalle']}</td><td>{row['Accion Tomada']}</td></tr>"

html += "</table>"

html += "<h2>Recomendaciones</h2><ul><li>Actualizar software y parches</li><li>Revisar configuraciones de firewall</li><li>Capacitar al personal en seguridad</li></ul>"

# Guardar HTML
with open(HTML_FILE, "w", encoding="utf-8") as f:
    f.write(html)

# Generar PDF usando la configuración con ruta de wkhtmltopdf
pdfkit.from_file(HTML_FILE, PDF_FILE, configuration=config)

print(f"Informe generado: {PDF_FILE}")

