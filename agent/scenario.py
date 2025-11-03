import json
from datetime import datetime
from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from utility.core_utility import Core
from rich.console import Console

core = Core()
console = Console()

class ScenarioAgent:
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def create_scenario(self, challenge_info: dict, state: dict, option: str) -> dict:
        state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        
        prompt = [
            {"role": "developer", "content": CTFSolvePrompt.scenario_prompt},
            {"role": "user", "content": json.dumps({
                "challenge": challenge_info,
                "state": state_for_json,
                "option": option
            }, ensure_ascii=False)}
        ]

        try:
            res = self.client.chat.completions.create(model=self.model, messages=prompt)
            raw = res.choices[0].message.content
            scenario = json.loads(raw)
            
            # Add timestamp
            scenario["created_at"] = datetime.now().isoformat()
            
            # Save scenario
            core.save_json(fileName="scenario.json", obj=scenario)
            console.print("=== Scenario Created ===", style="bold green")
            console.print(f"Scenario ID: {scenario.get('scenario_id', 'unknown')}")
            console.print(f"Objective: {scenario.get('objective', 'unknown')}")
            console.print(f"Milestones: {len(scenario.get('success_milestones', []))}")
            
            return scenario
            
        except Exception as e:
            console.print(f"Error creating scenario: {e}", style="red")
            return {}
