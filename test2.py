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
  "challenge" : [],
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
    
    def init_state(self):
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_STATE, f, ensure_ascii=False, indent=2)    
    
    def init_plan(self):
        with open(PLAN_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_PLAN, f, ensure_ascii=False, indent=2)    
    
    def safe_json_loads(self, s):
        if isinstance(s, (dict, list)):
            return s
        if not isinstance(s, str):
            return {}
        try:
            return json.loads(s)
        except Exception:
            try:
                s2 = s[s.find("{"): s.rfind("}") + 1]
                s2 = re.sub(r"```(json)?|```", "", s2).strip()
                return json.loads(s2)
            except Exception:
                return {}
            
    def load_json(self, fileName, default):
        if not isinstance(default, (dict, list)):
            default = {}
        if not os.path.exists(fileName):
            with open(fileName, "w", encoding="utf-8") as f:
                json.dump(default, f, ensure_ascii=False, indent=2)
            return default
        with open(fileName, "r", encoding="utf-8") as f:
            return json.load(f)

    
    def save_json(self, fileName, obj):
        with open(fileName, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        console.print(f"[Prompt saved to {fileName}]", style="green")

    def parsing_CoT_stateSelected(self):
      CoT_json = self.load_json(fileName="CoT.json", default={})
      Cal_json = self.load_json(fileName="Cal.json", default={})

      cal_res = Cal_json.get("results", [])
      
      if not cal_res or "vuln" not in cal_res[0]:
          raise KeyError("Cal.json: results[0].vuln None")

      Cal_vuln = str(cal_res[0]["vuln"])
      idx = -1

      for i, c in enumerate(CoT_json.get("candidates", [])):
          v = c.get("vuln")
          if isinstance(v, list):
              if Cal_vuln in map(str, v):
                  idx = i; break
          else:
              if str(v) == Cal_vuln:
                  idx = i; break

      if idx == -1:
          raise ValueError(f"Match Error!")

      cand = CoT_json["candidates"][idx]
      notes = cal_res[0].get("notes", "")
      return {
          "vuln": cand.get("vuln"),
          "why": cand.get("why"),
          "cot_now": cand.get("cot_now"),
          "thought": cand.get("thought"),
          "tasks": cand.get("tasks", []),
          "expected_signals": cand.get("expected_signals", []),
          "notes": notes,
      }
      
    def parsing_CoT_stateResults(self):
        CoT_json = self.load_json(fileName="CoT.json", default={})
        Cal_json = self.load_json(fileName="Cal.json", default={})    
        
        cal_res = Cal_json.get("results", [])
      
        if not cal_res or "vuln" not in cal_res[0]:
            raise KeyError("Cal.json: results[0].vuln None")

        Cal_vuln = str(cal_res[0]["vuln"])
        idx = -1

        for i, c in enumerate(CoT_json.get("candidates", [])):
            v = c.get("vuln")
            if isinstance(v, list):
                if Cal_vuln in map(str, v):
                    idx = i; break
            else:
                if str(v) == Cal_vuln:
                    idx = i; break

        if idx == -1:
            raise ValueError(f"Match Error!")
        
        cand = CoT_json["candidates"][idx]
        return {
          "vuln": cand.get("vuln"),
          "why": cand.get("why"),
          "thought": cand.get("thought"),
          "success": ""
        }

    def state_update(self):
        parsing_CoT = self.parsing_CoT_stateSelected()
        parsing_CoT2 = self.parsing_CoT_stateResults()
        state_json = self.load_json(fileName="state.json", default=DEFAULT_STATE)

        if not isinstance(state_json.get("selected"), dict):
            state_json["selected"] = {}
            
        state_json["selected"].update(parsing_CoT)
        state_json["results"].append(parsing_CoT2)

        self.save_json("state.json", state_json)
        
    def count_CoT_Num(self, field):
        plan_json = self.load_json(fileName="plan.json", default=DEFAULT_PLAN)
        
        plan_step = len(plan_json[field]) + 1
        
        return f"plan-step-{plan_step}"
        
    def parsing_todos(self):
        CoT_json = self.load_json(fileName="CoT.json", default={})
        Cal_json = self.load_json(fileName="Cal.json", default={}) 
        
        cal_res = Cal_json.get("results", [])
      
        if not cal_res or "vuln" not in cal_res[0]:
            raise KeyError("Cal.json: results[0].vuln None")

        Cal_vuln = str(cal_res[0]["vuln"])
        idx = -1

        for i, c in enumerate(CoT_json.get("candidates", [])):
            v = c.get("vuln")
            if isinstance(v, list):
                if Cal_vuln in map(str, v):
                    idx = i; break
            else:
                if str(v) == Cal_vuln:
                    idx = i; break

        if idx == -1:
            raise ValueError(f"Match Error!")
                
        cand = CoT_json["candidates"][idx]
        
        tasks = cand.get("tasks")
        
        return {
            "vuln": cand.get("vuln"),
            "tasks" : tasks,
        }
    
    def parsing_runs(self):
        CoT_json = self.load_json(fileName="CoT.json", default={})
        Cal_json = self.load_json(fileName="Cal.json", default={}) 
        
        cal_res = Cal_json.get("results", [])
      
        if not cal_res or "vuln" not in cal_res[0]:
            raise KeyError("Cal.json: results[0].vuln None")

        Cal_vuln = str(cal_res[0]["vuln"])
        idx = -1

        for i, c in enumerate(CoT_json.get("candidates", [])):
            v = c.get("vuln")
            if isinstance(v, list):
                if Cal_vuln in map(str, v):
                    idx = i; break
            else:
                if str(v) == Cal_vuln:
                    idx = i; break

        if idx == -1:
            raise ValueError(f"Match Error!")
        
        CoT_num = self.count_CoT_Num(field="runs")
        
        cand = CoT_json["candidates"][idx]
        
        tasks = cand.get("tasks")
        
        return {
            "CoT_num" : CoT_num,
            "vuln": cand.get("vuln"),
            "tasks" : tasks,
        }
        
    def parsing_artifacts(self):
        CoT_json = self.load_json(fileName="CoT.json", default={})
        Cal_json = self.load_json(fileName="Cal.json", default={}) 
        
        cal_res = Cal_json.get("results", [])
      
        if not cal_res or "vuln" not in cal_res[0]:
            raise KeyError("Cal.json: results[0].vuln None")

        Cal_vuln = str(cal_res[0]["vuln"])
        idx = -1

        for i, c in enumerate(CoT_json.get("candidates", [])):
            v = c.get("vuln")
            if isinstance(v, list):
                if Cal_vuln in map(str, v):
                    idx = i; break
            else:
                if str(v) == Cal_vuln:
                    idx = i; break

        if idx == -1:
            raise ValueError(f"Match Error!")
        
        cand = CoT_json["candidates"][idx]
        tasks = cand.get("tasks")
        
        artifacts = []
        
        for c in tasks:
            name = c.get("name")
            artifact = c.get("artifact")
            
            if name is not None or artifact is not None:
                artifacts.append({"name": name, "artifact": artifact})
            
        return artifacts

    def parsing_backlog(self):
        CoT_json = self.load_json(fileName="CoT.json", default={})
        Cal_json = self.load_json(fileName="Cal.json", default={})

        cal_res = Cal_json.get("results", [])
        
        if not cal_res or "vuln" not in cal_res[0]:
            raise KeyError("Cal.json: results[0].vuln None")

        cal_vuln = str(cal_res[0]["vuln"]).strip()
        backlogs = []
        
        for c in CoT_json.get("candidates", []): 
            
            if str(c.get("vuln")).strip() == cal_vuln:
                continue
            
            backlogs.append({
                "function": c.get("function"),
                "vuln": c.get("vuln"),
                "why": c.get("why"),
                "cot_now": c.get("cot_now"),
                "thought": c.get("thought"),
            })
        return backlogs
        
    def plan_update(self):
        parsing_todos = self.parsing_todos()
        parsing_runs  = self.parsing_runs()
        artifacts_list = self.parsing_artifacts()   
        backlog_list   = self.parsing_backlog()     
        
        plan_json = self.load_json(fileName="plan.json", default=DEFAULT_PLAN)

        plan_json["todos"] = parsing_todos
        plan_json["runs"].append(parsing_runs)

        art_map = {}
        for it in artifacts_list:
            name = it.get("name")
            art  = it.get("artifact")
            if name and art:
                art_map[name] = art
                
        plan_json["artifacts"].update(art_map)

        plan_json["backlog"].extend(backlog_list)

        self.save_json("plan.json", plan_json)

        
core = Core()

# print(core.parsing_artifacts())

core.state_update()