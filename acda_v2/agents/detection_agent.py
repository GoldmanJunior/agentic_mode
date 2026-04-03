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

def run_detection_agent(event):
       '''Analyse un événement réseau et retourne une évaluation de son score d'anomalie'''
       score=calculate_anomalie_score(event)
       return score