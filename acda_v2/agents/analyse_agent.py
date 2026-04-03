
import anthropic
from dotenv import load_dotenv


load_dotenv() 

client = anthropic.Anthropic()

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

def run_analyse_agent(action_decision, incident):
    '''Exécute l'agent d'analyse en utilisant un LLM pour juger de la pertinence d'une décision d'action en fonction de l'incident'''
    judgement=llm_judge(action_decision, incident)
    return judgement