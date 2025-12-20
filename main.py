import os, json, re
import sys

# 현재 디렉토리를 Python 경로에 추가 (모듈 import를 위해)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console

from agent.planning import PlanningAgent
from agent.instruction import InstructionAgent 
from agent.parsing import ParserAgent
from agent.feedback import FeedbackAgent
from agent.exploit import ExploitAgent

from utility.core_utility import Core

from langgraph.workflow import create_main_workflow
from langgraph.state import PlanningState


core = Core()
console = Console()

# === API Key Check ===
def test_API_KEY():
    openai_api_key = os.getenv("OPENAI_API_KEY")
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    
    if not openai_api_key:
        console.print("Please set the OPENAI_API_KEY environment variable.", style='bold red')
        console.print('export OPENAI_API_KEY="<API_KEY>"', style='bold red')
        exit(1)
        
    if not gemini_api_key:
        console.print("Please set the GEMINI_API_KEY environment variable.", style='bold red')
        console.print('export GEMINI_API_KEY="<API_KEY>"', style='bold red')
        exit(1)
    
    # Remove any newline characters and whitespace from API key
    openai_api_key = openai_api_key.strip().replace('\n', '').replace('\r', '')
    gemini_api_key = gemini_api_key.strip().replace('\n', '').replace('\r', '')
    
    if openai_api_key and gemini_api_key:
        while(1):
            console.print("Both API keys are set.", style='bold green')
            console.print("Choose the API key to use.", style='bold yellow')
            console.print("1. OpenAI", style='bold yellow')
            console.print("2. Gemini", style='bold yellow')
            choice = input("> ")
            if choice == '1':
                console.print("OpenAI API key will be used.", style='bold green')
                api_key = openai_api_key
                model = "gpt-5.2"
                break
            elif choice == '2':
                console.print("Gemini API key will be used.", style='bold green')
                api_key = gemini_api_key
                model = "gemini-3-flash-preview"
                break
            else: 
                console.print("Invalid choice. Please enter 1 or 2.", style='bold red')
                continue
    
    return api_key, model
        
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

    # JSON 파일 저장 제거됨  
        
# === Context Class for All Clients ===
class AppContext:
    def __init__(self, api_key, model):
        self.api_key = api_key
        self.planning = PlanningAgent(api_key, model)
        self.instruction = InstructionAgent(api_key, model)
        self.parsing = ParserAgent(api_key, model)
        self.feedback = FeedbackAgent(api_key, model)
        self.exploit = ExploitAgent(api_key, model)
        self.core = core

# === Setting: Initialize Context ===
def setting():
    api_key, model = test_API_KEY()
    return AppContext(api_key, model)

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
        # Plan: 계획 저장 및 관리
        "cot_result": "",
        "cot_json": {},
        "cal_result": "",
        "cal_json": {},
        "instruction_result": "",
        "instruction_json": {},
        "multi_instructions": [],
        "plan": {},
        "todos": [],
        "runs": [],
        "backlog": [],
        "seen_cmd_hashes": [],
        "previous_plans": [],
        "previous_cot_results": [],
        "previous_cal_results": [],
        "plan_success_status": {},
        "plan_progress": {},
        "plan_attempts": {},
        "vulnerability_tracks": {},
        "track_tools": {},
        "current_track": "",
        "selected": {},
        
        # State: 타겟 정보 및 실행 결과
        "challenge": challenge_info,
        "binary_path": "",
        "url": "",
        "target_info": {},
        "protections": {},
        "mitigations": [],
        "facts": {},
        "artifacts": {},
        "signals": [],
        "errors": [],
        "results": [],
        "execution_results": {},
        "execution_output": "",
        "execution_status": "",
        "parsing_result": "",
        "multi_parsing_results": {},
        "flag_detected": False,
        "detected_flag": "",
        "all_detected_flags": [],
        "poc_result": "",
        "poc_json": {},
        "poc_script_path": "",
        "feedback_result": "",
        "feedback_json": {},
        
        # Context: 컨텍스트 및 제어 정보
        "user_input": "",
        "option": "",
        "current_step": "",
        "constraints": ["no brute-force > 1000"],
        "env": {},
        "user_approval": False,
        "approval_choice": "",
        "init_flow": 0,
        "ctx": ctx,
        "API_KEY": ctx.api_key,
        "scenario": {},
    }
    
    workflow = create_main_workflow()
    
    console.print("\n=== Starting LangGraph Workflow ===", style="bold green")
    console.print("Type '--help' for available commands\n", style="yellow")
    
    try:
        # 재귀 제한 설정 (기본값 25에서 50으로 증가)
        config = {"recursion_limit": 50}
        final_state = workflow.invoke(initial_state, config=config)
        
        console.print("\n=== Workflow Completed ===", style="bold green")
        
    except KeyboardInterrupt:
        console.print("\n\nWorkflow interrupted by user.", style="bold yellow")
    except Exception as e:
        console.print(f"\nError in workflow: {e}", style="bold red")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    main()
    