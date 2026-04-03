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


def human_in_the_loop_decision(action_decision):
    '''en cas d'action irreversible comme QUARANTINE ou BLOCK_IP, demande la validation de l'humain pour valider ou invalider la décision de l'agent'''
    if action_decision["action"] == "QUARANTINE" or action_decision["action"] == "BLOCK_IP":
        response=input(f"Action proposée : {action_decision}. Validez-vous cette action ? True/False : ").lower().strip()
        return response in ["true", "yes", "y", "oui", "o"]
    else:
        return True

def run_decision_agent(score, event):
    '''Prend une décision d'action en fonction du score d'anomalie et du type d'événement, avec validation humaine pour les actions critiques'''
    action_decision=decide_action(score, event)
    if human_in_the_loop_decision(action_decision):
        return action_decision
    else:
        return {
                "action": "NO_ACTION",
                "target": event["src_ip"],
                "justification": f"Action initiale {action_decision['action']} annulée par l'humain, score d'anomalie {score}, événement de type {event['event_type']}",
                "confidence": 1.0
        }