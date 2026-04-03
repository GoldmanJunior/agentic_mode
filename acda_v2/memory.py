import json
import os

def save_incident(incident):
    '''Sauvegarde l'incident dans un fichier json'''
    event={
        "timestamp": incident.get("timestamp", "unknown"),
        "src_ip": incident.get("src_ip", "unknown"),
        "event_type": incident.get("event_type", "unknown"),
        "score": incident.get("score", 0),
        "action": incident.get("action", "unknown"),
    }
    if os.path.exists("memory.json"):
        with open("memory.json", 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = {"incidents": []}
    
    data["incidents"].append(event)

    with open("memory.json", "w") as f:
        json.dump(data, f, indent=4)

def load_incidents():
    '''Charge les incidents depuis le fichier json'''
    try:
        with open("memory.json", "r") as f:
            try:
                incidents = json.load(f)
                return incidents["incidents"]
            except json.JSONDecodeError:
                return []
    except FileNotFoundError:
        return []