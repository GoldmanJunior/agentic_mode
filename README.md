# ACDA — Autonomous Cyber Defense Agent

A multi-agent autonomous cybersecurity system built from scratch using the Anthropic Claude API. Developed over 5 weeks as the capstone project of a hands-on AI agents training program based on the Google/Kaggle 5-Day AI Agents Intensive course.

ACDA detects simulated network attacks, scores their severity, decides on a defensive action, validates irreversible actions with a human, evaluates the decision quality via an LLM judge, and persists incidents to memory — all orchestrated by a ReAct agent powered by Claude.

---

## Architecture

```
acda_v2/
├── agents/
│   ├── collecte_agent.py      # Generates simulated network events
│   ├── detection_agent.py     # Computes anomaly score (0–100)
│   ├── decision_agent.py      # Decides action + Human-in-the-Loop
│   ├── analyse_agent.py       # LLM-as-a-Judge via Claude
│   └── orchestrateur.py      # ReAct multi-agent orchestrator
├── memory.py                  # Persistent JSON memory
├── logger.py                  # Structured audit logging
├── main.py                    # Entry point
├── memory.json                # Auto-generated incident history
└── acda.log                   # Auto-generated audit log
```

### Agent flow

```
User prompt
    │
    ▼
Orchestrateur (ReAct loop)
    ├── run_collecte_agent     →  Network event (dict)
    ├── run_detection_agent    →  Anomaly score (0–100)
    ├── run_decision_agent     →  Action decision + HITL validation
    ├── run_analyse_agent      →  LLM judgment (APPROUVÉ / REFUSÉ)
    └── sauvegarder_incident   →  Persist to memory.json
```

---

## Features

| Feature | Description |
|---|---|
| Attack detection | 4 event types: `ddos`, `brute_force`, `port_scan`, `normale` |
| Anomaly scoring | Rule-based scoring engine, 0–100 scale |
| Autonomous decisions | `NO_ACTION`, `MONITOR`, `ALERT`, `BLOCK_IP`, `QUARANTINE` |
| Human-in-the-Loop | Mandatory human confirmation before `BLOCK_IP` and `QUARANTINE` |
| Persistent memory | Incident history in `memory.json`, injected as context on startup |
| LLM-as-a-Judge | Claude evaluates decision quality with verdict + quality score |
| Structured logging | All events written to `acda.log` with timestamp and data |
| ReAct orchestration | Claude autonomously sequences tool calls to complete the mission |

---

## Prerequisites

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/)

---

## Installation

```bash
git clone <repo-url>
cd "master agents/acda_v2"

pip install anthropic python-dotenv
```

Create a `.env` file in `acda_v2/`:

```env
ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

```bash
python main.py
```

The default prompt triggers a full pipeline run for a DDoS event:

```python
run_agent(
    "Génère un événement ddos, analyse-le, décide l'action appropriée, "
    "évalue la décision, et sauvegarde l'incident en mémoire."
)
```

You can change the event type by editing `main.py` or calling `run_agent()` directly with any prompt referencing `normale`, `port_scan`, `ddos`, or `brute_force`.

> **Note:** If the decision agent proposes `BLOCK_IP` or `QUARANTINE`, you will be prompted in the terminal to confirm (`True` / `False`) before the action proceeds.

---

## Agents

### `collecte_agent.py` — Event Collection
Simulates a network traffic collector. Generates realistic event dicts with randomized `src_ip`, `dst_ip`, `port`, `bytes`, `packets`, and `timestamp` for a given attack type.

### `detection_agent.py` — Anomaly Detection
Rule-based scoring engine. Assigns a score from 0 to 100 based on traffic characteristics:
- SSH port (22) + high packet count → +70
- High packets + high bytes → +80 (DDoS pattern)
- Low bytes + low packets → +40 (port scan pattern)

### `decision_agent.py` — Decision + HITL
Maps the anomaly score to a defensive action:

| Score | Action |
|---|---|
| 0 | NO_ACTION |
| 1–30 | MONITOR |
| 31–50 | ALERT |
| 51–80 | BLOCK_IP |
| 81–100 | QUARANTINE |

For `BLOCK_IP` and `QUARANTINE`, the agent pauses and requests human validation via `input()` before returning the decision.

### `analyse_agent.py` — LLM-as-a-Judge
Sends the incident and the decision to Claude with a cybersecurity expert system prompt. Returns a structured verdict (`APPROUVÉ` / `REFUSÉ`), a quality score (0–100), and a short justification.

### `orchestrateur.py` — ReAct Orchestrator
The brain of the system. Uses the Claude API with tool use to autonomously plan and execute the full pipeline. Implements a ReAct (Reasoning + Acting) loop: Claude decides which tool to call at each step based on the results of previous calls. On startup, it loads the incident history from `memory.py` and injects it as a system prompt for context-aware behavior.

---

## Example output

```
[Iteration 1]
Stop reason: tool_use
[Iteration 2]
Stop reason: tool_use
Action proposée : {'action': 'BLOCK_IP', 'target': '142.67.23.198', ...}. Validez-vous cette action ? True/False : true
[Iteration 3]
Stop reason: tool_use
[Iteration 4]
Stop reason: tool_use
[Iteration 5]
Stop reason: end_turn

Voici le résumé de l'analyse de l'incident DDoS :

- Événement généré : DDoS depuis 142.67.23.198, 4312 paquets, 187 430 bytes
- Score d'anomalie : 80/100
- Décision : BLOCK_IP (validée par l'opérateur)
- Jugement LLM : APPROUVÉ — Score qualité : 88/100
  "L'action BLOCK_IP est proportionnelle à un score de 80. La menace DDoS est avérée."
- Incident sauvegardé en mémoire.
```

Audit trail in `acda.log`:
```
2026-04-03T14:22:01 - INFO - Événement réseau généré - Data: {"event": {...}}
2026-04-03T14:22:03 - INFO - Score d'anomalie calculé - Data: {"score": 80}
2026-04-03T14:22:05 - INFO - Décision d'action prise : BLOCK_IP
2026-04-03T14:22:08 - INFO - Jugement LLM obtenu - Data: {"judgement": "APPROUVÉ..."}
2026-04-03T14:22:08 - INFO - Incident sauvegardé
```

---

## AI Agent concepts demonstrated

| Concept | Implementation |
|---|---|
| **ReAct pattern** | Orchestrator loops through Reason → Act → Observe until `end_turn` |
| **Multi-agent system** | 4 specialized agents with single responsibilities, coordinated by an orchestrator |
| **Tool use** | Claude calls `run_collecte_agent`, `run_detection_agent`, `run_decision_agent`, `run_analyse_agent`, `sauvegarder_incident` |
| **Persistent memory** | `memory.json` stores past incidents; loaded and injected as system context on each run |
| **Context engineering** | Incident history formatted and passed as a system prompt to inform Claude's decisions |
| **Human-in-the-Loop (HITL)** | Irreversible actions require explicit human approval before execution |
| **LLM-as-a-Judge** | A second Claude call independently evaluates the quality of the first agent's decision |
| **Structured logging** | Full audit trail with timestamps for observability and post-incident review |

---

`acda_v2/` is the production version. The `acda/` folder and `agent.py` at the root are earlier learning prototypes kept for reference.

---

## License

MIT
