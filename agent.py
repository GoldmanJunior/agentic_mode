import anthropic
import os
from dotenv import load_dotenv

load_dotenv() 

client = anthropic.Anthropic()

def run_weather_agent(query: str) -> str:
    tools = [
        {
            "name": "get_weather",
            "description": "Retourne la meteo simulee pour une ville donnee.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "Le nom de la ville"
                    }
                },
                "required": ["city"]
            }
        }
    ]

    def get_weather(city: str) -> str:
        weather_data = {
            "paris": "18°C, partiellement nuageux",
            "abidjan": "32°C, ensoleille",
            "london": "12°C, pluvieux"
        }
        return weather_data.get(city.lower(), f"Donnees non disponibles pour {city}")

    messages = [{"role": "user", "content": query}]

    for _ in range(5):
        print(f"[weather - Iteration { _ + 1}]")
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=512,
            tools=tools,
            messages=messages
        )

        if response.stop_reason == "end_turn":
            return next(block.text for block in response.content if hasattr(block, "text"))

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = get_weather(block.input["city"])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })
            messages.append({"role": "user", "content": tool_results})

    return "Iterations max atteintes."


def run_calc_agent(query: str) -> str:
    tools = [
        {
            "name": "calculate",
            "description": "Effectue un calcul mathematique.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "L'expression mathematique a evaluer"
                    }
                },
                "required": ["expression"]
            }
        }
    ]

    def calculate(expression: str) -> str:
        try:
            return f"Resultat : {eval(expression)}"
        except Exception as e:
            return f"Erreur : {str(e)}"

    messages = [{"role": "user", "content": query}]

    for _ in range(5):
        print(f"[Calcul - Iteration { _ + 1}]")
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=512,
            tools=tools,
            messages=messages
        )

        if response.stop_reason == "end_turn":
            return next(block.text for block in response.content if hasattr(block, "text"))

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = calculate(block.input["expression"])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })
            messages.append({"role": "user", "content": tool_results})

    return "Iterations max atteintes."


def run_orchestrator(user_message: str) -> str:
    tools = [
        {
            "name": "agent_meteo",
            "description": "Agent specialise dans les donnees meteorologiques. Appelle-le pour toute question sur la meteo d'une ville.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "La question meteorologique a poser a l'agent"
                    }
                },
                "required": ["query"]
            }
        },
        {
            "name": "agent_calcul",
            "description": "Agent specialise dans les calculs mathematiques. Appelle-le pour toute operation numerique.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "La question mathematique a poser a l'agent"
                    }
                },
                "required": ["query"]
            }
        }
    ]

    def execute_agent(agent_name: str, query: str) -> str:
        if agent_name == "agent_meteo":
            return run_weather_agent(query)
        elif agent_name == "agent_calcul":
            return run_calc_agent(query)
        return f"Agent inconnu : {agent_name}"

    messages = [{"role": "user", "content": user_message}]

    for iteration in range(10):
        print(f"[Orchestrateur - Iteration {iteration + 1}]")

        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            tools=tools,
            messages=messages
        )

        print(f"Stop reason: {response.stop_reason}")

        if response.stop_reason == "end_turn":
            return next(block.text for block in response.content if hasattr(block, "text"))

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  Delegation vers : {block.name}")
                    print(f"  Query : {block.input['query']}")
                    result = execute_agent(block.name, block.input["query"])
                    print(f"  Reponse : {result}")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })
            messages.append({"role": "user", "content": tool_results})

    return "Iterations max atteintes."


if __name__ == "__main__":
    result = run_orchestrator(
        "Quelle est la meteo a Abidjan ? Et si la temperature etait en Fahrenheit, ca ferait combien ?"
    )
    print(f"\nReponse finale : {result}")