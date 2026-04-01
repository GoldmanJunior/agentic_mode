import datetime
import random
import anthropic
import os
from dotenv import load_dotenv

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

def decide_action(score,event):
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

def execute_tool(tool_name: str, tool_input: dict) -> dict:
    if tool_name == "calculate_anomalie_score":
        event = tool_input["event"]
        score = calculate_anomalie_score(event)
        return {"anomalie_score": score}
    elif tool_name == "generate_network_event":
        event_type = tool_input["event_type"]
        event = generate_network_event(event_type)
        return {"event": event}
    elif tool_name == "decide_action":
        score = tool_input["score"]
        event = tool_input["event"]
        action_decision = decide_action(score, event)
        return {"action_decision": action_decision}
    else:
        raise ValueError(f"Tool inconnu : {tool_name}")
    
def run_agent(user_message: str, max_iterations: int = 10) -> str:
    messages = [{"role": "user", "content": user_message}]

    for iteration in range(max_iterations):
        print(f"[Iteration {iteration + 1}]")
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            tools=tools,
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
    result = run_agent("Génère un événement de chaque type (normale, port_scan, ddos, brute_force), calcule le score d'anomalie de chacun, décide l'action à prendre, et présente un rapport de synthèse.")
    print(result)