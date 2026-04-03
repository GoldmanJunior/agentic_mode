import datetime
import json

def log_event(level,message,data=None):
    '''log les événements importants pour le débug et l'audit'''
    if message:
        try:            
            with open("acda.log", "a", encoding='utf-8') as f:
                log_entry = f"{datetime.datetime.now().isoformat()} - {level} - {message}"
                if data:
                    log_entry += f" - Data: {json.dumps(data)}"
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Erreur lors de l'écriture du log : {e}")