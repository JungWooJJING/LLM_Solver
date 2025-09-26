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
FEEDBACK_FILE = "feedback.json"

DEFAULT_STATE = {
  "challenge" : [],
  "constraints": ["no brute-force > 1000"],
  "env": {},
  "selected": {},
  "results": [],
  "exploit" : []
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
        targets = [COT_FILE, Cal_FILE, Cal_SCORED_FILE, INSTRUCTION_FILE, PLAN_FILE, FEEDBACK_FILE]
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
        
    def parsing_status(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})
        
        return feedback_json.get("status")

    def parsing_promote_facts(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        return feedback_json.get("promote_facts")

    def parsing_result_quality(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        return feedback_json.get("result_quality")
    
    def parsing_next_hint(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        return feedback_json.get("next_hint")   
    
    def parsing_next_what_to_find(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        return feedback_json.get("next_what_to_find")       
        
    def parsing_feedback(self):
        parsing_status = self.parsing_status()
        parsing_promote_facts = self.parsing_promote_facts()
        parsing_result_quality = self.parsing_result_quality()
        parsing_next_hint = self.parsing_next_hint()
        parsing_next_what_to_find = self.parsing_next_what_to_find()
    
        state = self.load_json(fileName="state.json", default={})
        plan = self.load_json(fileName="plan.json", default={})
        
        state_results = state.get("results", [])
        plan_runs = plan.get("runs", [])
        
        idx = len(state_results) - 1

        idx = None
        
        for i in range(len(state_results) - 1, -1, -1):
            if not state_results[i].get("success"):
                idx = i
                break
        if idx is None:
            idx = len(state_results) - 1  

        state_results[idx]["success"] = parsing_status
        state_results[idx]["results"] = parsing_promote_facts

        state["results"] = state_results
        
        state["selected"] = ""
        
        self.save_json(fileName="state.json", obj=state)
        
        plan_runs[idx]["success"] = parsing_status
        plan_runs[idx]["next_hint"] = parsing_next_hint
        plan_runs[idx]["next_what_to_find"] = parsing_next_what_to_find
        
        plan["runs"] = plan_runs
        
        plan["tasks"] = ""
        
        self.save_json(fileName="plan.json", obj=plan)
        
    def parsing_summary(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        return feedback_json.get("attempt_summary")     
    
    def parsing_state_delta_results(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        fb = feedback_json.get("state_delta", {})
        return fb["results"]["append"][0]
        
    def parsing_next_step(self):
        feedback_json = self.load_json(fileName="feedback.json", default={})

        return feedback_json["next_step"]

    def exploit_feedback(self):
        status = self.parsing_status()
        attempt_summary = self.parsing_summary()
        state_delta_results_append = self.parsing_state_delta_results()
        next_step = self.parsing_next_step()
        
        state = self.load_json(fileName="state.json", default={})
        plan = self.load_json(fileName="plan.json", default={})
        
        state_exploit = state.get("exploit", [])
        
        if not state_exploit:
            state_exploit.append([])
            idx = 0
        else:
            idx = len(state_exploit) - 1

        state_exploit[idx].append({
            "summary" : attempt_summary,
            "signals" : state_delta_results_append["signals"],
            "note" : state_delta_results_append["note"]
        })
        
        state["exploit"] = state_exploit
                
        CoT_num = self.count_CoT_Num(field="runs")
        plan["runs"].append({
            "CoT_num" : CoT_num,
            "success" : status,
            "summary" : attempt_summary,
            "next_hint" : next_step
        })

        self.save_json(fileName="state.json", obj=state)
        self.save_json(fileName="plan.json", obj=plan)