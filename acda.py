import datetime
from pyexpat.errors import messages
import random
import anthropic
import os
from dotenv import load_dotenv
import json

load_dotenv() 

client = anthropic.Anthropic()

tools = [
    {
        "name": "calculate_anomalie_score",
        "description": "Calcule un score d'anomalie pour un événement réseau donné.",
        "input_schema": {
            "type": "object",
            "properties": {
                "event": {
                    "type": "object",
                    "properties": {
                        "timestamp": {"type": "string"},
                        "src_ip": {"type": "string"},
                        "dst_ip": {"type": "string"},
                        "port": {"type": "integer"},
                        "protocol": {"type": "string"},
                        "bytes": {"type": "integer"},
                        "packets": {"type": "integer"},
                        "event_type": {"type": "string"}
                    },
                    "required": ["timestamp", "src_ip", "dst_ip", "port", "protocol", "bytes", "packets", "event_type"]
                }
            },
            "required": ["event"]
        }
    },
      {
          "name": "generate_network_event",
          "description": "Génère un événement réseau de type normale, port_scan, ddos ou brute_force.",
          "input_schema": {
              "type": "object",
              "properties": {
                  "event_type": {
                      "type": "string",
                      "enum": ["normale", "port_scan", "ddos", "brute_force"],
                      "description": "Le type d'événement à générer"
                  }
              },
              "required": ["event_type"]
          }
      },
      {
          "name": "decide_action",
          "description": "Décide de l'action à prendre en fonction du score d'anomalie et du type d'événement.",
          "input_schema": {
              "type": "object",
              "properties": {
                  "score": {
                      "type": "integer",
                      "description": "Le score d'anomalie calculé pour l'événement"
                  },
                  "event": {
                      "type": "object",
                      "properties": {
                          "timestamp": {"type": "string"},
                          "src_ip": {"type": "string"},
                          "dst_ip": {"type": "string"},
                          "port": {"type": "integer"},
                          "protocol": {"type": "string"},
                          "bytes": {"type": "integer"},
                          "packets": {"type": "integer"},
                          "event_type": {"type": "string"}
                      },
                      "required": ["timestamp", "src_ip", "dst_ip", "port", "protocol", "bytes", "packets", "event_type"]
                  }
              },
              "required": ["score", "event"]
          }
      },
      {
            "name": "save_incident",
            "description": "Sauvegarde un incident dans un fichier json.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "incident": {
                        "type": "object",
                        "properties": {
                            "timestamp": {"type": "string"},
                            "src_ip": {"type": "string"},
                            "event_type": {"type": "string"},
                            "score": {"type": "integer"},
                            "action": {"type": "string"}
                        },
                        "required": ["timestamp", "src_ip", "event_type", "score", "action"]
                    }
                },
                "required": ["incident"]
            }
      },
        {
                "name": "calculate_metrics",
                "description": "Calcule les métriques à partir des données de mémoire.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "memory_file": {
                            "type": "string",
                            "description": "Le chemin vers le fichier de mémoire contenant les incidents"
                        }
                    },
                    "required": ["memory_file"]
                }
        },
        {
                "name": "llm_judge",
                "description": "Utilise un LLM pour juger de la pertinence d'une décision d'action en fonction de l'incident.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action_decision": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string"},
                                "target": {"type": "string"},
                                "justification": {"type": "string"},
                                "confidence": {"type": "number"}
                            },
                            "required": ["action", "target", "justification", "confidence"]
                        },
                        "incident": {
                            "type": "object",
                            "properties": {
                                "timestamp": {"type": "string"},
                                "src_ip": {"type": "string"},
                                "event_type": {"type": "string"},
                                "score": {"type": "integer"},
                                "action": {"type": "string"}
                            },
                            "required": ["timestamp", "src_ip", "event_type", "score", "action"]
                        }
                    },
                    "required": ["action_decision", "incident"]
                }
        }
]

def generer_ip_aleatoire():
    """
    Génère une adresse IPv4 aléatoire valide.
    Chaque octet est compris entre 0 et 255.
    """
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_network_event(event_type):
    '''Génère un événement réseau'''

    if event_type == "normale":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        num_bytes = random.randint(100, 5000)
        packets = random.randint(1, 50)
        port = random.randint(1, 65535)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "normale"
        }
    elif event_type == "port_scan":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        port = random.randint(1, 65535)
        num_bytes = random.randint(40, 200)
        packets = random.randint(1, 50)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "port_scan"
        }
    elif event_type == "ddos":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        num_bytes = random.randint(50000, 500000)
        port = random.randint(1, 65535)
        packets = random.randint(1000, 10000)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "ddos"
        }
    elif event_type == "brute_force":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        num_bytes = random.randint(100, 5000)
        packets = random.randint(1000, 10000)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": 22,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "brute_force"
        }
    else:
        raise ValueError("Type d'événement inconnu")
    
def calculate_anomalie_score(event):
    '''Calcule un score d'anomalie pour un événement réseau donné'''

    score=0
    if event["port"] == 22 and event["packets"] > 1000:
        score += 70
    if event["packets"] > 1000 and event["bytes"] > 50000:
            score += 80
    if event["bytes"] < 200 and event["packets"] < 50:
                score += 40

    return min(score, 100)

def decide_action(score, event):
    '''Décide de l'action à prendre en fonction du score d'anomalie et du type d'événement'''
    if score >= 80:
        return {
                "action": "QUARANTINE",
                "target": event["src_ip"],
                "justification": f"Score d'anomalie élevé ({score}), événement de type {event['event_type']}",
                "confidence": score/100
        }
    elif 51<=score <= 80:
        return {
                "action": "BLOCK_IP",
                "target": event["src_ip"],
                "justification": f"Score d'anomalie modéré ({score}), événement de type {event['event_type']}",
                "confidence":score/100
        }
    elif 31<=score <= 50:
        return {
                "action": "ALERT",
                "target": event["src_ip"],
                "justification": f"Score d'anomalie faible ({score}), événement de type {event['event_type']}",
                "confidence": score/100
        }
    elif 0 <score <= 30:
        return {
                "action": "MONITOR",
                "target": event["src_ip"],
                "justification": f"Score d'anomalie très faible ({score}), événement de type {event['event_type']}",
                "confidence": score/100
        }
    else:  
        return {
                "action": "NO_ACTION",
                "target": event["src_ip"],
                "justification": f"Score d'anomalie nul ({score}), événement de type {event['event_type']}",
                "confidence": 1.0
        }

def save_incident(incident):
    '''Sauvegarde l'incident dans un fichier json'''
    event={
        "timestamp": incident["timestamp"],
        "src_ip": incident["src_ip"],
        "event_type": incident["event_type"],
        "score": incident["score"],
        "action":incident["action"],
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

def human_in_the_loop_decision(action_decision):
    '''en cas d'action irreversible comme QUARANTINE ou BLOCK_IP, demande la validation de l'humain pour valider ou invalider la décision de l'agent'''
    if action_decision["action"] == "QUARANTINE" or action_decision["action"] == "BLOCK_IP":
        response=input(f"Action proposée : {action_decision}. Validez-vous cette action ? True/False : ").lower().strip()
        return response in ["true", "yes", "y", "oui", "o"]
    else:
        return False

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

def calculate_metrics(memory_file):
    '''Calcule les métriques à partir des données de mémoire'''
    try:
        with open(memory_file, 'r',encoding='utf-8') as f:
            data = json.load(f)
            incidents = data.get("incidents", [])
            total_incidents = len(incidents)
            action_counts = {}
            for incident in incidents:
                action = incident.get("action", "UNKNOWN")
                action_counts[action] = action_counts.get(action, 0) + 1
            event_type_counts = {}
            for incident in incidents:
                event_type = incident.get("event_type", "UNKNOWN")
                event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
            metrics = {
                "total_incidents": total_incidents,
                "action_distribution": action_counts,
                "score_moyen": sum(incident.get("score", 0) for incident in incidents) / total_incidents if total_incidents > 0 else 0,
                "type_attaque_distribution": event_type_counts
            }
            return metrics
    except FileNotFoundError:
        print(f"Fichier de mémoire {memory_file} non trouvé.")
        return {"total_incidents": 0, "action_distribution": {}, "score_moyen": 0}

def llm_judge(action_decision,incident):
    '''Utilise un LLM pour juger de la pertinence d'une décision d'action en fonction de l'incident'''

    prompt = f'''Incident : {incident}\nDécision d'action : {action_decision}\n'''
    
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=4096,
        system='''Tu es un expert en cybersécurité chargé d'évaluer les décisions d'un agent de défense autonome. 
        Évalue si l'action proposée est appropriée, proportionnelle et bien justifiée.
        Retourne une évaluation structurée avec : verdict (APPROUVÉ/REFUSÉ), score de qualité (0-100), et justification courte.''',
        messages=[{"role": "user", "content": prompt}]
    )
    judgement = next(
        block.text for block in response.content
        if hasattr(block, "text")
    ).strip()
    return judgement 

def execute_tool(tool_name: str, tool_input: dict) -> dict:
    if tool_name == "calculate_anomalie_score":
        event = tool_input["event"]
        score = calculate_anomalie_score(event)
        log_event("INFO", "Score d'anomalie calculé", {"event_type": event["event_type"], "src_ip": event["src_ip"], "score": score})
        return {"anomalie_score": score}
    elif tool_name == "generate_network_event":
        event_type = tool_input["event_type"]
        event = generate_network_event(event_type)
        log_event("INFO", "Événement réseau généré", {"event": event})
        return {"event": event}
    elif tool_name == "decide_action":
        score = tool_input["score"]
        event = tool_input["event"]
        action_decision = decide_action(score, event)
        log_event("INFO", f"Décision d'action prise : {action_decision}", {"action_decision": action_decision})
        approved = human_in_the_loop_decision(action_decision)
        if approved:
            log_event("INFO", f"Action approuvée : {action_decision}", {"action_decision": action_decision})
            return {"action_decision": action_decision, "status": "approved"}
        else:
            log_event("WARNING", f"Action rejetée par l'analyste", {"action_decision": action_decision})
            return {"action_decision": action_decision, "status": "rejected", "message": f"Action {action_decision['action']} annulée par l'analyste"}
    elif tool_name == "save_incident":
        incident = tool_input["incident"]
        save_incident(incident)
        log_event("INFO", f"Incident sauvegardé", {"incident": incident})
        return {"status": "incident_saved"}
    elif tool_name == "calculate_metrics":
        memory_file = tool_input["memory_file"]
        metrics = calculate_metrics(memory_file)
        return {"metrics": metrics}
    elif tool_name == "llm_judge":
        action_decision = tool_input["action_decision"]
        incident = tool_input["incident"]
        judgement = llm_judge(action_decision, incident)
        return {"judgement": judgement}
    else:
        log_event("ERROR", f"Tool inconnu : {tool_name}")
        raise ValueError(f"Tool inconnu : {tool_name}")
    
def run_agent(user_message: str, max_iterations: int = 10) -> str:
    incidents = load_incidents()
    if incidents:
        memory_context= f"Historique des incidents précédents : {json.dumps(incidents, indent=2)}"
    else:
        memory_context= "Aucun incident précédent en mémoire."

    messages = [{"role": "user", "content": user_message}]
    for iteration in range(max_iterations):
        print(f"[Iteration {iteration + 1}]")
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            tools=tools,
            system=memory_context,
            messages=messages
        )
        print(f"Stop reason: {response.stop_reason}")
        if response.stop_reason == "end_turn":
            final_response = next(
                block.text for block in response.content
                if hasattr(block, "text")
            )
            return final_response

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result)
                    })

            messages.append({"role": "user", "content": tool_results})

    return "Nombre maximum d'iterations atteint."
if __name__ == "__main__":
    result = run_agent("Génère un événement ddos, calcule le score, décide l'action, et demande au juge LLM d'évaluer la décision.")
    print(result)