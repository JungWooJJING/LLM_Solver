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
    
    # Remove any newline characters and whitespace from API key
    if openai_api_key:
        openai_api_key = openai_api_key.strip().replace('\n', '').replace('\r', '')
    if gemini_api_key:
        gemini_api_key = gemini_api_key.strip().replace('\n', '').replace('\r', '')
    
    # 둘 다 없으면 에러
    if not openai_api_key and not gemini_api_key:
        console.print("Please set at least one API key:", style='bold red')
        console.print('export OPENAI_API_KEY="<API_KEY>"', style='bold red')
        console.print('export GEMINI_API_KEY="<API_KEY>"', style='bold red')
        exit(1)
    
    # 둘 다 있으면 선택
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
                model = "gpt-4o"
                break
            elif choice == '2':
                console.print("Gemini API key will be used.", style='bold green')
                api_key = gemini_api_key
                model = "gemini-3-flash-preview"
                break
            else: 
                console.print("Invalid choice. Please enter 1 or 2.", style='bold red')
                continue
    # OpenAI만 있으면 OpenAI 사용
    elif openai_api_key:
        console.print("Using OpenAI API key.", style='bold green')
        api_key = openai_api_key
        model = "gpt-4o"
    # Gemini만 있으면 Gemini 사용
    elif gemini_api_key:
        console.print("Using Gemini API key.", style='bold green')
        api_key = gemini_api_key
        model = "gemini-3-flash-preview"
    
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

    console.print("Enter the challenge category (web/pwnable/reversing/forensics/crypto/misc):", style="blue")
    category = input("> ")

    category = category.lower()

    challenge_info = []
    binary_path = ""
    url = ""

    # 카테고리별 입력 분기
    if category == "web":
        # Web 카테고리: URL과 파일 위치 입력
        console.print("Enter the target URL:", style="blue")
        url = input("> ")

        console.print("Enter the source file/directory path (optional, press Enter to skip):", style="blue")
        file_path = input("> ")

        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")

        challenge_info = [{
            "category": category,
            "title": title,
            "description": description,
            "flag format": format,
            "url": url,
            "source_path": file_path if file_path else ""
        }]
        binary_path = file_path  # source_path를 binary_path로도 저장

    elif category == "pwnable":
        # Pwnable 카테고리: 기존 방식 유지
        console.print("Enter the binary file path:", style="blue")
        binary_path = input("> ")

        console.print("Enter the binary checksec:", style="blue")
        checksec = core.multi_line_input()

        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")

        challenge_info = [{
            "category": category,
            "title": title,
            "description": description,
            "flag format": format,
            "checksec": checksec,
            "binary_path": binary_path
        }]

    elif category == "reversing":
        # Reversing 카테고리: 바이너리 경로 입력
        console.print("Enter the binary file path:", style="blue")
        binary_path = input("> ")

        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")

        challenge_info = [{
            "category": category,
            "title": title,
            "description": description,
            "flag format": format,
            "binary_path": binary_path
        }]

    else:
        # 기타 카테고리 (forensics, crypto, misc 등)
        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")

        challenge_info = [{
            "category": category,
            "title": title,
            "description": description,
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
        "binary_path": binary_path,
        "url": url,
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
        "privilege_escalated": False,
        "privilege_evidence": "",
        "poc_result": "",
        "poc_json": {},
        "poc_script_path": "",
        "feedback_result": "",
        "feedback_json": {},
        "instruction_retry_count": 0,
        "iteration_count": 0,
        "workflow_step_count": 0,  # Workflow step count (recursion_limit 체크용)
        
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

    # 조기 종료 카운터
    consecutive_failures = 0
    MAX_CONSECUTIVE_FAILURES = 3

    try:
        # 재귀 제한 설정 (무한 루프 방지)
        config = {
            "recursion_limit": 50,
            "max_failed_retries": 3,
            "enable_fallback": True
        }

        # Workflow 실행 전 후크: 연속 실패 감지
        original_invoke = workflow.invoke

        def monitored_invoke(state, config):
            nonlocal consecutive_failures

            # 실행
            result_state = original_invoke(state, config)

            # 실행 상태 확인
            execution_status = result_state.get("execution_status", "")

            if execution_status == "fail":
                consecutive_failures += 1
                console.print(f"\nConsecutive failures: {consecutive_failures}/{MAX_CONSECUTIVE_FAILURES}", style="yellow")

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    console.print(f"\nToo many consecutive failures ({consecutive_failures}). Stopping workflow.", style="bold red")
                    console.print("Suggestion: Review the challenge requirements or try a different approach.", style="yellow")
                    raise RuntimeError("Max consecutive failures reached")
            else:
                # 성공하면 카운터 리셋
                if execution_status in ["success", "partial"]:
                    consecutive_failures = 0

            return result_state

        # Monkey patch
        workflow.invoke = monitored_invoke

        final_state = workflow.invoke(initial_state, config=config)

        console.print("\n=== Workflow Completed ===", style="bold green")

    except KeyboardInterrupt:
        console.print("\n\nWorkflow interrupted by user.", style="bold yellow")
    except RuntimeError as e:
        if "Max consecutive failures" in str(e):
            console.print("\n\n=== Workflow stopped due to repeated failures ===", style="bold red")
        else:
            console.print(f"\nRuntime error in workflow: {e}", style="bold red")
            import traceback
            traceback.print_exc()
    except Exception as e:
        # GraphRecursionError 체크
        try:
            from langgraph.errors import GraphRecursionError
            is_recursion_error = isinstance(e, GraphRecursionError)
        except ImportError:
            is_recursion_error = False
        
        if is_recursion_error or "recursion_limit" in str(e).lower() or "GraphRecursionError" in str(type(e).__name__):
            console.print(f"\nRecursion limit (50) reached. Returning to option selection.", style="bold yellow")
            console.print("You can continue with --continue (resets counters) or try a different approach.", style="cyan")
            
            # workflow를 다시 실행하여 option_input으로 돌아가기
            console.print("\n=== Returning to option selection ===", style="bold magenta")
            
            try:
                # 현재 state를 최대한 보존하면서 workflow_step_count만 리셋
                # initial_state를 복사하되, 기존 state의 중요한 정보는 유지
                retry_state = initial_state.copy()
                
                # 기존 state에서 중요한 정보 유지 (challenge, binary_path, url 등)
                if "challenge" in initial_state:
                    retry_state["challenge"] = initial_state["challenge"]
                if "binary_path" in initial_state:
                    retry_state["binary_path"] = initial_state.get("binary_path", "")
                if "url" in initial_state:
                    retry_state["url"] = initial_state.get("url", "")
                if "ctx" in initial_state:
                    retry_state["ctx"] = initial_state["ctx"]
                if "API_KEY" in initial_state:
                    retry_state["API_KEY"] = initial_state["API_KEY"]
                
                # 옵션과 카운터 리셋
                retry_state["option"] = ""  # 옵션을 비워서 다시 입력받도록
                retry_state["workflow_step_count"] = 0  # step count 리셋
                retry_state["iteration_count"] = 0  # iteration count도 리셋
                
                # 새로운 config로 workflow 재실행 (recursion_limit을 약간 늘려서 재시도)
                retry_config = {
                    "recursion_limit": 50,  # 다시 50으로 설정
                    "max_failed_retries": 3,
                    "enable_fallback": True
                }
                
                # workflow를 다시 invoke
                final_state = workflow.invoke(retry_state, config=retry_config)
                console.print("\n=== Workflow Completed ===", style="bold green")
                
            except Exception as inner_e:
                # 재귀 에러가 다시 발생하면 그냥 종료
                inner_error_type = str(type(inner_e).__name__)
                if "recursion_limit" in str(inner_e).lower() or "GraphRecursionError" in inner_error_type:
                    console.print("\nRecursion limit reached again. Please restart the workflow manually.", style="bold red")
                    console.print("  Tip: Consider using --continue earlier or breaking down the task into smaller steps.", style="yellow")
                else:
                    console.print(f"Error handling recursion limit: {inner_e}", style="bold red")
                    import traceback
                    traceback.print_exc()
        else:
            console.print(f"\nError in workflow: {e}", style="bold red")
            import traceback
            traceback.print_exc()
        
if __name__ == "__main__":
    main()
    