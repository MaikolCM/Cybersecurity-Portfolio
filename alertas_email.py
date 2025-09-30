import requests

# Configuración
TOKEN = "8177843714:AAGDiAcQ07RZSLy3LZBvm149g4jNRCHpUG0"    # Token del bot 
CHAT_ID = "7204496103"      #  chat_id obtenido
MENSAJE_DEFAULT = "Alerta de seguridad: posible ataque detectado"

def enviar_alerta_telegram(mensaje):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": mensaje
    }
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            print("Alerta enviada por Telegram")
        else:
            print(f"Error enviando alerta: {response.text}")
    except Exception as e:
        print(f"Excepción al enviar alerta: {e}")

 