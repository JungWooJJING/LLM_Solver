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
        # JSON 파일 저장 제거됨
        pass
    
    def init_plan(self):
        # JSON 파일 저장 제거됨
        pass    
    
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
        # JSON 파일 로드 제거됨 - 항상 default 반환
        return default

    
    def save_json(self, fileName, obj):
        # JSON 파일 저장 제거됨
        pass
    
    def make_json_serializable(self, obj):
        """직렬화 불가 객체를 제거하고 직렬화 가능한 형태로 변환"""
        import json
        
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                # StructuredTool 같은 객체는 제외하고 이름만 저장
                if hasattr(v, '__class__') and 'Tool' in str(type(v)):
                    continue
                result[k] = self.make_json_serializable(v)
            return result
        elif isinstance(obj, list):
            return [self.make_json_serializable(item) for item in obj if not (hasattr(item, '__class__') and 'Tool' in str(type(item)))]
        else:
            # 기본 타입은 그대로 반환
            try:
                json.dumps(obj)
                return obj
            except (TypeError, ValueError):
                # 직렬화 불가 객체는 문자열로 변환
                return str(obj)
    
    def clean_state_for_json(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """State에서 JSON 직렬화 가능한 형태로 변환 (ctx 제외, track_tools 정리)"""
        # ctx 제외
        state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        
        # track_tools 정리: toolset 객체 제거, tool_names만 유지
        if "track_tools" in state_for_json:
            cleaned_track_tools = {}
            for track_id, tool_info in state_for_json["track_tools"].items():
                if isinstance(tool_info, dict):
                    cleaned_track_tools[track_id] = {
                        "tool_category": tool_info.get("tool_category"),
                        "tool_names": tool_info.get("tool_names", [])
                    }
                else:
                    cleaned_track_tools[track_id] = tool_info
            state_for_json["track_tools"] = cleaned_track_tools
        
        # 최종적으로 직렬화 불가 객체 제거
        return self.make_json_serializable(state_for_json)

    
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
                
                console.print(f"Success: {name}" if result.returncode == 0 else f"Failed: {name}", 
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
                console.print(f"Timeout: {name}", style="red")
                
            except Exception as e:
                step_result = {
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                results.append(step_result)
                console.print(f"Error: {name} - {e}", style="red")
        
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
                        console.print(f"Milestone completed: {milestone.get('name', 'Unknown')}", style="bold green")
        
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
    
