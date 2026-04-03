import sys
import os
import json
from anthropic import Anthropic

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.dirname(__file__))
import logger
import memory
from analyse_agent import run_analyse_agent
from collecte_agent import run_collecte_agent
from detection_agent import run_detection_agent
from decision_agent import run_decision_agent

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def load_incidents():
    if hasattr(memory, "load_incidents"):
        return memory.load_incidents()
    return []

tools = [
    {
        "name": "run_collecte_agent",
        "description": "Simule la collecte d'événements réseau",
        "input_schema": {
            "type": "object",
            "properties": {
                "event_type": {
                    "type": "string",
                    "description": "Le type d'événement à simuler (normale, port_scan, ddos, brute_force)"
                }
            },
            "required": ["event_type"]
        }
    },
    {
        "name": "run_detection_agent",
        "description": "Analyse un événement réseau et retourne une évaluation de son score d'anomalie",
        "input_schema": {
            "type": "object",
            "properties": {
                "event": {
                    "type": "object",
                    "description": "L'événement réseau à analyser"
                }
            },
            "required": ["event"]
        }
    },
    {
        "name": "run_decision_agent",
        "description": "Prend un score d'anomalie et décide d'une action à prendre",
        "input_schema": {
            "type": "object",
            "properties": {
                "score": {
                    "type": "number",
                    "description": "Le score d'anomalie de l'événement"
                },
                "event": {
                    "type": "object",
                    "description": "L'événement réseau analysé"
                }
            },
            "required": ["score", "event"]
        }
    },
    {
        "name": "run_analyse_agent",
        "description": "Utilise un LLM pour juger de la pertinence d'une décision d'action en fonction de l'incident",
        "input_schema": {
            "type": "object",
            "properties": {
                "action_decision": {
                    "type": "object",
                    "description": "La décision d'action prise par l'agent de décision"
                },
                "incident": {
                    "type": "object",
                    "description": "L'incident réseau associé à la décision d'action"
                }
            },
            "required": ["action_decision", "incident"]
        }
    },
    {
        "name": "sauvegarder_incident",
        "description": "Sauvegarde un incident en mémoire persistante",
        "input_schema": {
            "type": "object",
            "properties": {
                "incident": {
                    "type": "object",
                    "description": "L'incident réseau à sauvegarder"
                }
            },
            "required": ["incident"]
        }
    },
]

def _parse_dict(value):
    """Désérialise une valeur si elle arrive comme string JSON."""
    if isinstance(value, str):
        return json.loads(value)
    return value

def execute_tool(tool_name: str, tool_input: dict) -> dict:
    if tool_name == "run_detection_agent":
        event = _parse_dict(tool_input["event"])
        score = run_detection_agent(event)
        logger.log_event("INFO", "Score d'anomalie calculé", {"event_type": event["event_type"], "src_ip": event["src_ip"], "score": score})
        return {"anomalie_score": score}
    elif tool_name == "run_collecte_agent":
        event_type = tool_input["event_type"]
        event = run_collecte_agent(event_type)
        logger.log_event("INFO", "Événement réseau généré", {"event": event})
        return {"event": event}
    elif tool_name == "run_decision_agent":
        score = tool_input["score"]
        event = _parse_dict(tool_input["event"])
        action_decision = run_decision_agent(score, event)
        logger.log_event("INFO", f"Décision d'action prise : {action_decision}", {"action_decision": action_decision})
        return {"action_decision": action_decision}
    elif tool_name == "run_analyse_agent":
        action_decision = tool_input["action_decision"]
        incident = tool_input["incident"]
        judgement = run_analyse_agent(action_decision, incident)
        logger.log_event("INFO", f"Jugement LLM obtenu", {"judgement": judgement})
        return {"judgement": judgement}
    elif tool_name == "sauvegarder_incident":
        incident = _parse_dict(tool_input["incident"])
        memory.save_incident(incident)
        logger.log_event("INFO", "Incident sauvegardé", {"incident": incident})
        return {"status": "incident_saved"}
    else:
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
    return "Limite d'itérations atteinte sans réponse finale."