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
  "scenario" : [],
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

        # Add new backlog items with deduplication
        plan_json["backlog"] = self._deduplicate_backlog(plan_json["backlog"], backlog_list)

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
    
    def execute_instruction(self, instruction_json: dict) -> str:
        """
        Execute the instruction steps and return the results
        """
        import subprocess
        from datetime import datetime
        from rich.console import Console
        
        console = Console()
        results = []
        
        for step in instruction_json.get("steps", []):
            cmd = step.get("cmd", "")
            name = step.get("name", "unknown")
            artifact = step.get("artifact", "-")
            
            console.print(f"Executing: {name}", style="cyan")
            console.print(f"Command: {cmd}", style="dim")
            
            try:
                # Execute command
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                
                step_result = {
                    "name": name,
                    "cmd": cmd,
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Save artifact if specified
                if artifact != "-" and result.stdout:
                    with open(artifact, "w") as f:
                        f.write(result.stdout)
                    step_result["artifact_saved"] = artifact
                
                results.append(step_result)
                
                console.print(f"✓ Success: {name}" if result.returncode == 0 else f"✗ Failed: {name}", 
                            style="green" if result.returncode == 0 else "red")
                
            except subprocess.TimeoutExpired:
                step_result = {
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": "Command timed out",
                    "timestamp": datetime.now().isoformat()
                }
                results.append(step_result)
                console.print(f"✗ Timeout: {name}", style="red")
                
            except Exception as e:
                step_result = {
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                results.append(step_result)
                console.print(f"✗ Error: {name} - {e}", style="red")
        
        return json.dumps(results, ensure_ascii=False, indent=2)
    
    def update_state_with_parsing(self, state: dict, parsed_json: dict) -> dict:
        """
        Update state with parsed results
        """
        from datetime import datetime
        
        # Update facts with new information
        if "signals" in parsed_json:
            if "facts" not in state:
                state["facts"] = {}
            
            for signal in parsed_json["signals"]:
                signal_type = signal.get("type", "other")
                signal_name = signal.get("name", "unknown")
                signal_value = signal.get("value", "")
                
                # Add signal to facts
                fact_key = f"{signal_type}_{signal_name}"
                state["facts"][fact_key] = signal_value
        
        # Update artifacts
        if "artifacts" in parsed_json:
            if "artifacts" not in state:
                state["artifacts"] = {}
            
            for artifact in parsed_json["artifacts"]:
                artifact_name = artifact.get("name", "unknown")
                artifact_path = artifact.get("path", "")
                state["artifacts"][artifact_name] = artifact_path
        
        # Update results with latest execution
        if "results" not in state:
            state["results"] = []
        
        execution_result = {
            "timestamp": datetime.now().isoformat(),
            "type": "instruction_execution",
            "summary": parsed_json.get("summary", ""),
            "signals": parsed_json.get("signals", []),
            "artifacts": parsed_json.get("artifacts", []),
            "success": parsed_json.get("status") == "success"
        }
        
        state["results"].append(execution_result)
        
        # Update scenario progress if available
        if "scenario" in state:
            scenario = state["scenario"]
            # Check if any milestones were completed based on new signals
            for milestone in scenario.get("success_milestones", []):
                if milestone.get("status") == "pending":
                    # Check if success criteria are met
                    if self.check_milestone_completion(milestone, parsed_json):
                        milestone["status"] = "completed"
                        milestone["completed_at"] = datetime.now().isoformat()
                        from rich.console import Console
                        console = Console()
                        console.print(f"🎯 Milestone completed: {milestone.get('name', 'Unknown')}", style="bold green")
        
        return state
    
    def check_milestone_completion(self, milestone: dict, parsed_json: dict) -> bool:
        """
        Check if a milestone's success criteria are met based on parsed results
        """
        success_criteria = milestone.get("success_criteria", [])
        signals = parsed_json.get("signals", [])
        
        for criteria in success_criteria:
            criteria_met = False
            for signal in signals:
                if criteria.lower() in signal.get("value", "").lower() or \
                   criteria.lower() in signal.get("name", "").lower():
                    criteria_met = True
                    break
            if not criteria_met:
                return False
        
        return len(success_criteria) > 0
    
    def _deduplicate_backlog(self, existing_backlog: list, new_backlog: list) -> list:
        """
        Remove duplicate backlog items based on multiple criteria
        """
        import hashlib
        
        # Create a set of existing item hashes
        existing_hashes = set()
        for item in existing_backlog:
            item_hash = self._create_backlog_hash(item)
            existing_hashes.add(item_hash)
        
        # Add only new items that don't already exist
        deduplicated_backlog = existing_backlog.copy()
        
        for new_item in new_backlog:
            new_hash = self._create_backlog_hash(new_item)
            if new_hash not in existing_hashes:
                deduplicated_backlog.append(new_item)
                existing_hashes.add(new_hash)
        
        return deduplicated_backlog
    
    def _create_backlog_hash(self, backlog_item: dict) -> str:
        """
        Create a hash for backlog item based on key identifying fields
        """
        import hashlib
        
        # Use key fields that identify a unique plan
        key_fields = {
            "vuln": backlog_item.get("vuln", ""),
            "function": backlog_item.get("function", ""),
            "why": backlog_item.get("why", ""),
            "cot_now": backlog_item.get("cot_now", "")
        }
        
        # Create a consistent string representation
        key_string = "|".join([str(v).strip() for v in key_fields.values()])
        
        # Generate hash
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def clean_backlog(self, max_items: int = 50) -> list:
        """
        Clean backlog by removing old/duplicate items and keeping only recent ones
        """
        plan_json = self.load_json(fileName="plan.json", default=DEFAULT_PLAN)
        backlog = plan_json.get("backlog", [])
        
        if len(backlog) <= max_items:
            return backlog
        
        # Keep only the most recent items
        cleaned_backlog = backlog[-max_items:]
        
        # Update plan.json
        plan_json["backlog"] = cleaned_backlog
        self.save_json("plan.json", plan_json)
        
        return cleaned_backlog
    
    def remove_backlog_item(self, item_hash: str) -> bool:
        """
        Remove a specific backlog item by its hash
        """
        plan_json = self.load_json(fileName="plan.json", default=DEFAULT_PLAN)
        backlog = plan_json.get("backlog", [])
        
        original_length = len(backlog)
        
        # Remove items with matching hash
        backlog = [item for item in backlog if self._create_backlog_hash(item) != item_hash]
        
        if len(backlog) < original_length:
            plan_json["backlog"] = backlog
            self.save_json("plan.json", plan_json)
            return True
        
        return False
    
    def get_backlog_stats(self) -> dict:
        """
        Get statistics about the current backlog
        """
        plan_json = self.load_json(fileName="plan.json", default=DEFAULT_PLAN)
        backlog = plan_json.get("backlog", [])
        
        # Count by vulnerability type
        vuln_counts = {}
        for item in backlog:
            vuln = item.get("vuln", "unknown")
            vuln_counts[vuln] = vuln_counts.get(vuln, 0) + 1
        
        return {
            "total_items": len(backlog),
            "vulnerability_counts": vuln_counts,
            "unique_vulnerabilities": len(vuln_counts)
        }