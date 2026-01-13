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
from agent.detect import DetectAgent

from utility.core_utility import Core
from utility.auto_analysis import auto_analyze, format_analysis_summary

from langgraph.workflow import create_main_workflow
from langgraph.state import PlanningState


core = Core()
console = Console()


def run_auto_analysis(category: str, state: dict) -> dict:
    console.print("\n[Auto-Analysis] Running initial analysis...", style="cyan")

    try:
        analysis = auto_analyze(category, state)

        if analysis:
            summary = format_analysis_summary(analysis, category)
            if summary and "No significant findings" not in summary:
                console.print(summary, style="dim")

            # state에 분석 결과 추가
            state["auto_analysis"] = analysis

            # 제안된 취약점이 있으면 facts에 추가
            suggested_vulns = analysis.get("suggested_vuln", []) or analysis.get("potential_vulns", [])
            if suggested_vulns:
                state["facts"]["auto_detected_vulns"] = [
                    f"{v['type']} ({v['confidence']}): {v['evidence']}"
                    for v in suggested_vulns
                ]
                console.print(f"\n[Auto-Analysis] Detected {len(suggested_vulns)} potential vulnerability types", style="yellow")

        console.print("[Auto-Analysis] Done\n", style="cyan")

    except Exception as e:
        console.print(f"[Auto-Analysis] Error: {e}", style="dim red")

    return state

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
    # OpenAI만 있으면 OpenAI 사용
    elif openai_api_key:
        console.print("Using OpenAI API key.", style='bold green')
        api_key = openai_api_key
        model = "gpt-5.2"
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
        self.detect = DetectAgent(api_key, model)
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

        # 명령어 캐싱 (중복 실행 방지)
        "command_cache": {},  # {cmd_hash: {cmd, result, success, timestamp}}
        "failed_commands": {},  # {cmd_hash: {cmd, error, timestamp, attempt_count}}
        "all_track_outputs": {},  # {track_id: [{cmd, success, stdout, ...}]}

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
        "auto_analysis": {},

        # Exploit Readiness (Feedback에서 계산)
        "exploit_readiness": {
            "score": 0.0,
            "components": {
                "vuln_confirmed": False,
                "offset_known": False,
                "leak_obtained": False,
                "target_identified": False,
                "protections_known": False,
                "crash_confirmed": False,
                "payload_understood": False
            },
            "recommend_exploit": False,
            "exploit_priority": "low",
            "missing_for_exploit": []
        },
    }

    # 카테고리별 자동 초기 분석 수행
    if category in ["pwnable", "web", "reversing", "forensics"]:
        initial_state = run_auto_analysis(category, initial_state)

    workflow = create_main_workflow()

    console.print("\n=== Starting LangGraph Workflow ===", style="bold green")
    console.print("Type '--help' for available commands\n", style="yellow")

    # 조기 종료 카운터
    consecutive_failures = 0
    MAX_CONSECUTIVE_FAILURES = 3

    # 재귀 제한 설정
    config = {
        "recursion_limit": 50,
        "max_failed_retries": 3,
        "enable_fallback": True
    }

    # 현재 state 추적 (recursion error 복구용)
    current_state = initial_state.copy()

    # Workflow 실행 전 후크: 연속 실패 감지 (루프 밖에서 한 번만 설정)
    original_invoke = workflow.invoke

    def monitored_invoke(state, config):
        nonlocal consecutive_failures, current_state

        # 실행 (original_invoke 사용 - 재귀 방지)
        result_state = original_invoke(state, config)

        # 현재 state 업데이트 (복구용)
        current_state = result_state.copy()

        # 실행 상태 확인
        execution_status = result_state.get("execution_status", "")

        if execution_status == "fail":
            consecutive_failures += 1
            console.print(f"\nConsecutive failures: {consecutive_failures}/{MAX_CONSECUTIVE_FAILURES}", style="yellow")

            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                console.print(f"\nToo many consecutive failures ({consecutive_failures}). Returning to option selection.", style="bold yellow")
                consecutive_failures = 0  # 리셋
                raise RuntimeError("Max consecutive failures reached - returning to options")
        else:
            # 성공하면 카운터 리셋
            if execution_status in ["success", "partial"]:
                consecutive_failures = 0

        return result_state

    # Monkey patch (한 번만 설정)
    workflow.invoke = monitored_invoke

    # 메인 워크플로우 루프 - recursion limit 도달해도 계속 실행
    while True:
        try:
            final_state = workflow.invoke(current_state, config=config)

            # 워크플로우 완료 후 상태 업데이트
            current_state.update(final_state)

            # --quit 선택 시 프로그램 종료 (final_state와 current_state 모두 확인)
            option = current_state.get("option") or final_state.get("option", "")
            if option == "--quit":
                console.print("\n=== Exiting Program ===", style="bold yellow")
                break

            # Flag가 감지되었는지 확인
            if current_state.get("flag_detected") and current_state.get("detected_flag"):
                console.print("\n=== Challenge Solved! ===", style="bold green")
                console.print(f"Flag: {current_state.get('detected_flag')}", style="bold cyan")

            # 옵션 선택으로 돌아감
            console.print("\n=== Workflow Cycle Completed ===", style="bold green")
            current_state["option"] = ""  # 옵션 리셋하여 다시 선택하도록
            continue  # 루프 계속 - 옵션 선택으로 돌아감

        except KeyboardInterrupt:
            console.print("\n\nWorkflow interrupted by user.", style="bold yellow")
            break  # 사용자 중단

        except RuntimeError as e:
            # --quit 옵션 확인 (예외 발생 전에 설정되었을 수 있음)
            if current_state.get("option") == "--quit":
                console.print("\n=== Exiting Program ===", style="bold yellow")
                break
            # GraphRecursionError는 RuntimeError를 상속하므로 먼저 체크
            error_str = str(e).lower()
            error_type = type(e).__name__

            # 1. GraphRecursionError 체크 (먼저!)
            is_recursion_error = False
            try:
                from langgraph.errors import GraphRecursionError
                is_recursion_error = isinstance(e, GraphRecursionError)
            except ImportError:
                pass

            if is_recursion_error or "recursion_limit" in error_str or "graphrecursionerror" in error_type.lower():
                console.print(f"\n[!] Recursion limit (50) reached.", style="bold yellow")
                console.print("Automatically continuing with --continue...\n", style="cyan")

                # state 보존하면서 카운터만 리셋, --continue로 자동 계속 진행
                current_state["option"] = "--continue"
                current_state["workflow_step_count"] = 0
                current_state["iteration_count"] = 0  # 리셋해도 analysis_started가 true이면 진행 상태 유지
                consecutive_failures = 0

                # 중요 정보 보존 확인
                if "ctx" not in current_state or current_state["ctx"] is None:
                    current_state["ctx"] = initial_state["ctx"]
                if "API_KEY" not in current_state:
                    current_state["API_KEY"] = initial_state["API_KEY"]

                console.print("Counters reset. Continuing with preserved state...", style="bold green")
                continue  # 루프 계속 - --continue로 자동 진행

            # 2. Max consecutive failures 체크
            elif "max consecutive failures" in error_str or "returning to options" in error_str:
                console.print("\n=== Max failures reached. Continuing with --continue... ===", style="bold magenta")
                # --continue로 자동 계속 진행
                current_state["option"] = "--continue"
                current_state["workflow_step_count"] = 0
                current_state["iteration_count"] = 0
                consecutive_failures = 0
                continue  # 루프 계속

            # 3. 그 외 RuntimeError
            else:
                console.print(f"\nRuntime error in workflow: {e}", style="bold red")
                import traceback
                traceback.print_exc()
                break

        except Exception as e:
            # --quit 옵션 확인 (예외 발생 전에 설정되었을 수 있음)
            if current_state.get("option") == "--quit":
                console.print("\n=== Exiting Program ===", style="bold yellow")
                break
            
            # 그 외 모든 예외
            console.print(f"\nError in workflow: {e}", style="bold red")
            import traceback
            traceback.print_exc()
            break
        
if __name__ == "__main__":
    main()
    