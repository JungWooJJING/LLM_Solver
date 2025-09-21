import os
import json
import re

from typing import List, Dict, Any
from rich.console import Console

console = Console()

STATE_FILE = "state.json"
COT_FILE = "CoT.json"
Cal_FILE = "Cal.json"
Cal_SCORED_FILE = "Cal_scored.json"
INSTRUCTION_FILE = "instruction.json"
PLAN_FILE = "plan.json"

DEFAULT_STATE = {
  "iter": 0,
  "goal": "",
  "constraints": ["no brute-force > 1000"],
  "env": {},
  "selected": {},
  "results": []
}

DEFAULT_PLAN = {
  "todos": [],
  "runs": [],
  "seen_cmd_hashes": [],
  "artifacts": {},
  "backlog" : []
}

class Core:
    def multi_line_input(self):
        console.print("Enter multiple lines. Type <<<END>>> on a new line to finish input.", style="bold yellow")
        lines = []
        while True:
            line = input(" ")
            if line.strip() == "<<<END>>>":
                break
            lines.append(line)
        return "\n".join(lines)
    
    def cleanUp(self, all=True):
        targets = [COT_FILE, Cal_FILE, Cal_SCORED_FILE, INSTRUCTION_FILE, PLAN_FILE]
        if all:
            targets.append(STATE_FILE)
        for f in targets:
            if os.path.exists(f):
                os.remove(f)
                
    def load_plan(self) -> Dict[str, Any]:
        if not os.path.exists(PLAN_FILE):
            self.save_plan(DEFAULT_PLAN.copy())
        with open(PLAN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_plan(self, plan: dict) -> None:
        with open(PLAN_FILE, "w", encoding="utf-8") as f:
            json.dump(plan, f, ensure_ascii=False, indent=2)

    def load_state(self):
        if not os.path.exists(STATE_FILE):
            self.save_state(DEFAULT_STATE.copy())
            
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_state(self, state: dict):
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)