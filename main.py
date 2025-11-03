import os, json, re

from rich.console import Console

from agent.planning import PlanningAgent
from agent.instruction import InstructionAgent 
from agent.parsing import ParserAgent
from agent.feedback import FeedbackAgent
from agent.exploit import ExploitAgent
from agent.scenario import ScenarioAgent

from utility.core_utility import Core

from langgraph.workflow import create_main_workflow
from langgraph.state import PlanningState


core = Core()
console = Console()

# === API Key Check ===
def test_API_KEY():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        console.print("Please set the OPENAI_API_KEY environment variable.", style='bold red')
        console.print('export OPENAI_API_KEY="<API_KEY>"', style='bold red')
        exit(1)
    
    # Remove any newline characters and whitespace from API key
    api_key = api_key.strip().replace('\n', '').replace('\r', '')
    
    # Validate API key format
    if not api_key.startswith('sk-'):
        console.print("Warning: API key doesn't start with 'sk-'", style='bold yellow')
    
    return api_key
        
def parsing_preInformation(category: str, flag : str, checksec: str):
    st = core.load_json("state.json", default="")

    if(category == "pwnable"):
        st["challenge"].append({
        "category": category,
        "flag format" : flag,
        "checksec": checksec
        })
    
    else:    
        st["challenge"].append({
            "category": category,
            "flag format" : flag
        })

    core.save_json(fileName="state.json", obj=st)  
        
# === Context Class for All Clients ===
class AppContext:
    def __init__(self, api_key):
        self.api_key = api_key
        self.planning = PlanningAgent(api_key)
        self.instruction = InstructionAgent(api_key)
        self.parsing = ParserAgent(api_key)
        self.feedback = FeedbackAgent(api_key)
        self.exploit = ExploitAgent(api_key)
        self.scenario = ScenarioAgent(api_key)
        self.core = core  # 노드에서 ctx.core 사용을 위해 추가

# === Setting: Initialize Context ===
def setting():
    api_key = test_API_KEY()
    return AppContext(api_key)

# === Main Program ===
def main():    
    # Context 설정
    ctx = setting()
    
    # 초기 상태 초기화
    core.init_state()
    core.init_plan()

    # 초기 정보 입력
    console.print("Enter the challenge title:", style="blue")
    title = input("> ")

    console.print("Enter the challenge description (Press <<<END>>> to finish):", style="blue")
    description = core.multi_line_input()

    console.print("Enter the challenge category:", style="blue")
    category = input("> ")
    
    category = category.lower()
    
    challenge_info = []
    if(category == "pwnable"):
        console.print("Enter the binary checksec:", style="blue")
        checksec = core.multi_line_input()
                
        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")

        challenge_info = [{
            "category": category,
            "flag format": format,
            "checksec": checksec
        }]
    else: 
        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")
        
        challenge_info = [{
            "category": category,
            "flag format": format
        }]
    
    # PlanningState 초기화
    initial_state: PlanningState = {
        "challenge": challenge_info,
        "scenario": {},
        "constraints": ["no brute-force > 1000"],
        "env": {},
        "selected": {},
        "results": [],
        "todos": [],
        "runs": [],
        "seen_cmd_hashes": [],
        "artifacts": {},
        "backlog": [],
        "option": "",
        "current_step": "",
        "user_input": "",
        "user_approval": False,
        "binary_path": "",
        "cot_result": "",
        "cot_json": {},
        "cal_result": "",
        "cal_json": {},
        "instruction_result": "",
        "instruction_json": {},
        "parsing_result": "",
        "feedback_result": "",
        "feedback_json": {},
        "ctx": ctx,
        "gpt_5": 1,
        "init_flow": 0,
        "approval_choice": "",
        "API_KEY": ctx.api_key
    }
    
    workflow = create_main_workflow()
    
    console.print("\n=== Starting LangGraph Workflow ===", style="bold green")
    console.print("Type '--help' for available commands\n", style="yellow")
    
    try:
        final_state = workflow.invoke(initial_state)
        
        console.print("\n=== Workflow Completed ===", style="bold green")
        
    except KeyboardInterrupt:
        console.print("\n\nWorkflow interrupted by user.", style="bold yellow")
    except Exception as e:
        console.print(f"\nError in workflow: {e}", style="bold red")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    main()
    