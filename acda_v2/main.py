from agents.orchestrateur import run_agent

if __name__ == "__main__":
    result = run_agent("Génère un événement ddos, analyse-le, décide l'action appropriée, évalue la décision, et sauvegarde l'incident en mémoire.")
    print(result)