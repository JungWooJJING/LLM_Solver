from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

# 상대 import로 변경 (langgraph 패키지 내에서 사용)
try:
    from langgraph.state import PlanningState, is_shell_acquired
except ImportError:
    # 같은 디렉토리에서 실행하는 경우
    from state import PlanningState, is_shell_acquired

try:
    from langgraph.node import CoT_node, Cal_node, instruction_node, tool_selection_node, multi_instruction_node, execution_node, track_update_node, parsing_node, feedback_node, exploit_node, poc_node, help_node, option_input_node, detect_node
except ImportError:
    # 같은 디렉토리에서 실행하는 경우
    from node import CoT_node, Cal_node, instruction_node, tool_selection_node, multi_instruction_node, execution_node, track_update_node, parsing_node, feedback_node, exploit_node, poc_node, help_node, option_input_node, detect_node

def route_by_option(state: PlanningState) -> str:
    # Recursion limit 체크
    workflow_step_count = state.get("workflow_step_count", 0)
    RECURSION_LIMIT = 50
    if workflow_step_count >= RECURSION_LIMIT:
        from rich.console import Console
        console = Console()
        console.print(f"Recursion limit ({RECURSION_LIMIT}) reached. Please choose an option.", style="bold yellow")
        console.print("  Use --continue to reset counters or --quit to exit.", style="cyan")
        # 옵션이 비어있으면 사용자 입력 대기
        option = state.get("option", "")
        if not option:
            return "invalid"  # help로 가서 옵션 안내

    option = state.get("option", "")
    has_cot_result = bool(state.get("cot_result"))

    # 이미 작업이 진행된 상태인지 확인
    # cot_result가 있어야 실제 분석이 시작된 것 (auto_analysis의 facts는 초기 분석일 뿐)
    has_progress = has_cot_result

    # 카테고리 확인
    challenge = state.get("challenge", [])
    category = ""
    if challenge and len(challenge) > 0:
        category = challenge[0].get("category", "").lower()

    # --ghidra는 pwnable/reversing에서 초기에만 허용
    if option == "--ghidra":
        if category in ["pwnable", "reversing"]:
            if not has_progress:
                return "first_workflow"
            else:
                return "invalid_loop"  # 이미 진행 중이면 사용 불가
        else:
            return "invalid_category"

    # --auto 모드: 자동으로 분석하고 해결 (초기에만 가능)
    if option == "--auto":
        if not has_progress:
            return "auto_workflow"
        else:
            return "invalid_loop"  # 이미 진행 중이면 --continue 사용

    if not has_progress:
        # 초기 실행: 아직 아무 작업도 진행되지 않음
        if option == "--help":
            return "help"
        elif option == "--file" or option == "--discuss":
            return "first_workflow"
        elif option == "--quit":
            return "end"
        elif option in ["--continue", "--exploit"]:
            return "invalid_init"
        else:
            return "invalid"
    else:
        # 루프 실행: CoT가 이미 실행됨
        if option == "--help":
            return "help"
        elif option in ["--discuss", "--continue", "--file"]:
            return "loop_workflow"
        elif option == "--exploit":
            return "exploit_flow"
        elif option == "--quit":
            return "end"
        else:
            return "invalid"

def route_after_parsing(state: PlanningState) -> str:
    from rich.console import Console
    console = Console()
    
    execution_status = state.get("execution_status", "unknown")
    flag_detected = state.get("flag_detected", False)
    privilege_escalated = state.get("privilege_escalated", False)
    parsing_json = state.get("parsing_result", "")
    
    # FLAG 감지 확인 (최우선)
    if flag_detected or execution_status == "flag_detected":
        console.print("🚩 Flag detected! Routing to PoC generation", style="bold green")
        return "flag_detected"
    
    # 관리자 권한 획득 확인 (Flag 다음 우선순위)
    if privilege_escalated or execution_status == "privilege_escalated":
        console.print("🔐 Privilege escalation detected! Routing to PoC generation", style="bold green")
        return "flag_detected"  # 같은 PoC 노드로 라우팅
    
    # Parsing JSON 파싱
    import json
    # Multi-Track 모드인지 확인
    multi_parsing_results = state.get("multi_parsing_results", {})
    is_multi_track = len(multi_parsing_results) > 1
    
    if is_multi_track:
        # Multi-Track 모드: 모든 트랙의 signals와 errors 수집
        ctx = state.get("ctx")
        core = ctx.core if ctx else None
        if not core:
            from utility.core_utility import Core
            core = Core()
        all_signals = []
        all_errors = []
        for track_id, track_parsing_result in multi_parsing_results.items():
            track_parsed_data = core.safe_json_loads(track_parsing_result)
            all_signals.extend(track_parsed_data.get("signals", []))
            all_errors.extend(track_parsed_data.get("errors", []))
        signals = all_signals
        errors = all_errors
        # 기본 parsed_data는 첫 번째 트랙 결과 사용 (하위 호환성)
        try:
            if isinstance(parsing_json, str):
                parsed_data = json.loads(parsing_json) if parsing_json else {}
            else:
                parsed_data = parsing_json
        except:
            parsed_data = {}
    else:
        # 단일 모드: 기존 로직
        try:
            if isinstance(parsing_json, str):
                parsed_data = json.loads(parsing_json) if parsing_json else {}
            else:
                parsed_data = parsing_json
        except:
            parsed_data = {}
        signals = parsed_data.get("signals", [])
        errors = parsed_data.get("errors", [])
    has_success_signal = any(s.get("type") in ["leak", "offset", "proof", "oracle"] for s in signals)
    # EIP 리다이렉션은 명확한 성공 신호
    has_eip_redirection = any(s.get("type") == "proof" and ("eip" in s.get("name", "").lower() or "redirection" in s.get("name", "").lower() or "exploit_success" in s.get("name", "").lower()) for s in signals)
    # 쉘 획득도 명확한 성공 신호
    has_shell_acquired = any(s.get("type") == "proof" and ("shell" in s.get("name", "").lower() or "acquired" in s.get("name", "").lower()) for s in signals)
    has_errors = len(errors) > 0

    # === Exploit 자동 트리거 조건 체크 ===
    # 자동 exploit 트리거 비활성화 - 사용자가 명시적으로 --exploit 선택 필요
    # exploit_trigger_types = {"offset", "leak", "crash", "oracle", "symbol", "proof"}
    # collected_signal_types = set()
    # ...
    # 자동 트리거 로직 비활성화됨

    # execution_output에서 직접 쉘 출력 확인 (is_shell_acquired 함수 사용)
    execution_output = state.get("execution_output", "")
    execution_results = state.get("execution_results", {})
    has_shell_in_output = False
    if execution_output:
        has_shell_in_output = is_shell_acquired(execution_output)
    if not has_shell_in_output:
        for result_text in execution_results.values():
            if is_shell_acquired(result_text):
                has_shell_in_output = True
                break

    # EIP 리다이렉션이나 쉘 획득이 있으면 명확한 성공 → PoC 코드 생성
    if has_eip_redirection:
        console.print("Execution successful - EIP redirection detected (exploit working!)", style="bold green")
        console.print("Generating PoC code", style="bold yellow")
        return "shell_acquired"  # PoC 노드로 라우팅
    elif has_shell_acquired or (execution_status == "success" and has_shell_in_output):
        console.print("Execution successful - Shell acquired (exploit working!)", style="bold green")
        console.print("Generating PoC code", style="bold yellow")
        return "shell_acquired"  # PoC 노드로 라우팅
    elif execution_status == "success" or (has_success_signal and not has_errors):
        console.print("Execution successful - saving results and continuing to Planning", style="bold green")
        return "success_continue"
    elif execution_status == "fail" or has_errors:
        # 재시도 횟수 확인
        retry_count = state.get("instruction_retry_count", 0)
        MAX_RETRIES = 5  # 최대 재시도 횟수
        
        if retry_count >= MAX_RETRIES:
            console.print(f"Maximum retry limit ({MAX_RETRIES}) reached. Stopping workflow.", style="bold red")
            console.print("  Consider reviewing the challenge or trying a different approach.", style="yellow")
            return "max_retries_reached"  # 워크플로우 종료
        
        # 재시도 횟수 증가
        state["instruction_retry_count"] = retry_count + 1
        console.print(f"Execution failed - retrying with new instruction (attempt {retry_count + 1}/{MAX_RETRIES})", style="bold red")
        return "retry_instruction"
    else:
        # partial 또는 unknown
        console.print("Execution partial - saving progress and continuing", style="yellow")
        return "success_continue"

def route_after_feedback(state: PlanningState) -> str:
    from rich.console import Console
    console = Console()
    
    feedback_json = state.get("feedback_json", {})
    tracks = state.get("vulnerability_tracks", {})
    results = state.get("results", [])
    
    # Workflow step count 추적 및 recursion limit 체크
    workflow_step_count = state.get("workflow_step_count", 0)
    workflow_step_count += 1
    state["workflow_step_count"] = workflow_step_count
    
    # 반복 횟수 추적 (--continue 시 리셋됨)
    iteration_count = state.get("iteration_count", 0)
    iteration_count += 1
    state["iteration_count"] = iteration_count
    
    # 최대 반복 횟수 체크 (무한 루프 방지) - 지속적인 진행을 위해 여유있게 설정
    MAX_ITERATIONS = 10  # 더 오래 지속적으로 진행하도록 증가
    RECURSION_LIMIT = 50  # 충분한 여유를 두어 지속적인 진행 허용

    if workflow_step_count >= RECURSION_LIMIT - 10:
        console.print(f"Approaching recursion limit: {workflow_step_count}/{RECURSION_LIMIT} steps", style="yellow")
        if workflow_step_count >= RECURSION_LIMIT:
            console.print(f"Recursion limit ({RECURSION_LIMIT}) reached. Ending workflow.", style="bold yellow")
            console.print("  Use --continue to reset counters or --quit to exit.", style="cyan")
            # option_input으로 돌아가기 위해 state에 플래그 설정
            state["option"] = ""  # 옵션을 비워서 다시 입력받도록
            return "end"  # end를 반환하면 main workflow로 돌아가서 option_input으로 이동

    if iteration_count >= MAX_ITERATIONS:
        console.print(f"Maximum iterations ({MAX_ITERATIONS}) reached. Ending workflow.", style="bold yellow")
        console.print(f"  Use --continue to reset and continue for another {MAX_ITERATIONS} iterations.", style="cyan")
        return "end"
    
    # === Exploit Readiness 기반 자동 Exploit 트리거 ===
    # 자동 exploit 트리거를 비활성화하고 사용자가 --exploit 옵션을 직접 선택하도록 함
    # exploit_readiness = state.get("exploit_readiness", {})
    # exploit_score = exploit_readiness.get("score", 0.0)
    # recommend_exploit = exploit_readiness.get("recommend_exploit", False)
    #
    # 자동 exploit 트리거는 비활성화됨 - 사용자가 명시적으로 --exploit 선택 필요

    # 성공 조건 확인
    status = feedback_json.get("status", "")
    if status == "success":
        # 성공했지만 더 탐색할 수 있으면 계속, 아니면 종료
        active_tracks = [t for t in tracks.values() if t.get("status") in ["in_progress", "pending"]]
        if not active_tracks:
            console.print("Objective achieved and no active tracks. Ending workflow.", style="bold green")
            return "end"
        # 자동으로 Planning으로 돌아가기 (--continue 옵션으로 설정하여 --file이 작동하지 않게 함)
        console.print("Objective achieved! Returning to Planning for next steps.", style="bold green")
        state["option"] = "--continue"  # 자동 진행을 위해 --continue로 설정
        return "continue_planning"
    
    # 활성 트랙 확인
    active_tracks = [t for t in tracks.values() if t.get("status") in ["in_progress", "pending"]]
    if not active_tracks:
        # 모든 트랙이 완료되었거나 실패
        completed_tracks = [t for t in tracks.values() if t.get("status") == "completed"]
        failed_tracks = [t for t in tracks.values() if t.get("status") == "failed"]

        if completed_tracks:
            console.print("All tracks completed. Ending workflow.", style="bold green")
            return "end"
        elif failed_tracks and len(failed_tracks) == len(tracks):
            console.print("All tracks failed. Ending workflow.", style="bold red")
            return "end"
        else:
            # active_tracks가 없을 때는 더 이상 Planning으로 돌아가지 않고 종료
            # (이미 모든 트랙을 시도했거나 새로운 트랙을 만들 수 없는 상황)
            console.print("No active tracks and no clear completion status. Ending workflow to prevent infinite loop.", style="yellow")
            console.print("  Use --continue to explore new attack vectors.", style="cyan")
            return "end"

    # 진행 중이면 자동으로 Planning으로 돌아가기 (MAX_ITERATIONS까지 지속적으로 진행)
    if status in ["partial", "in_progress"]:
        if iteration_count >= MAX_ITERATIONS:
            console.print(f"Maximum iterations ({MAX_ITERATIONS}) reached. Returning to option selection.", style="yellow")
            console.print("  Choose --continue to reset and continue exploration, or try a different option.", style="cyan")
            return "end"
        console.print(f"Progress made. Continuing to Planning (iteration {iteration_count}/{MAX_ITERATIONS}).", style="cyan")
        state["option"] = "--continue"  # 자동 진행을 위해 --continue로 설정
        return "continue_planning"

    # 실패해도 MAX_ITERATIONS까지는 계속 시도 (지속적인 진행)
    if status == "fail":
        if iteration_count >= MAX_ITERATIONS:
            console.print(f"Maximum iterations ({MAX_ITERATIONS}) reached after failures. Returning to option selection.", style="yellow")
            console.print("  Choose --continue to reset and try a new approach, or try a different option.", style="cyan")
            return "end"
        console.print(f"Current approach failed, but continuing to try new approach (iteration {iteration_count}/{MAX_ITERATIONS}).", style="yellow")
        state["option"] = "--continue"  # 자동 진행을 위해 --continue로 설정
        return "continue_planning"

    # 기본값: 무조건 종료하고 옵션 선택으로 복귀 (무한 루프 방지)
    console.print(f"Feedback status: {status}. Returning to option selection to prevent infinite loop.", style="yellow")
    console.print("  Choose --continue to continue exploration, or try a different option.", style="cyan")
    return "end"

def route_after_exploit(state: PlanningState) -> str:
    return "detect"


def route_after_detect(state: PlanningState) -> str:

    from rich.console import Console
    console = Console()

    decision = state.get("detect_decision", "continue")
    confidence = state.get("detect_confidence", 0.5)

    # 성공 케이스: PoC 생성
    if decision in ["flag_found", "shell_acquired", "privilege_escalated"]:
        console.print(f"🎉 Success detected ({decision})! Generating PoC code.", style="bold green")
        return "poc"

    # Exploit 준비 완료: Exploit 실행
    if decision == "exploit_ready":
        console.print("⚡ Ready for exploitation. Launching exploit.", style="bold yellow")
        return "exploit"

    # 계속 분석
    if decision == "continue":
        # Workflow step count 추적
        workflow_step_count = state.get("workflow_step_count", 0)
        iteration_count = state.get("iteration_count", 0)
        MAX_ITERATIONS = 10
        RECURSION_LIMIT = 50

        if workflow_step_count >= RECURSION_LIMIT or iteration_count >= MAX_ITERATIONS:
            console.print(f"Iteration limit reached. Ending workflow.", style="bold yellow")
            return "end"

        state["option"] = "--continue"
        console.print(f"Continuing analysis (iteration {iteration_count + 1}/{MAX_ITERATIONS}).", style="cyan")
        return "continue_planning"

    # 재시도
    if decision == "retry":
        retry_count = state.get("detect_retry_count", 0)
        MAX_RETRIES = 3

        if retry_count >= MAX_RETRIES:
            console.print(f"Maximum retries ({MAX_RETRIES}) reached. Ending.", style="bold red")
            return "end"

        state["detect_retry_count"] = retry_count + 1
        console.print(f"Retrying current approach (attempt {retry_count + 1}/{MAX_RETRIES}).", style="yellow")
        return "continue_planning"

    # 종료
    console.print("Ending workflow.", style="yellow")
    return "end"


def _create_analysis_workflow():
    graph = StateGraph(PlanningState)

    graph.add_node("tool_loading", tool_selection_node)  # 도구 로딩 (LLM 도구 선택 전)
    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("multi_instruction", multi_instruction_node)
    graph.add_node("execution", execution_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("track_update", track_update_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("detect", detect_node)  # Detect: 최종 결정자
    graph.add_node("poc", poc_node)

    graph.set_entry_point("tool_loading")  # 도구 로딩부터 시작
    graph.add_edge("tool_loading", "CoT")
    graph.add_edge("CoT", "Cal")
    graph.add_edge("Cal", "multi_instruction")
    graph.add_edge("multi_instruction", "execution")
    graph.add_edge("execution", "parsing")

    # Parsing 결과에 따라 다음 단계 결정
    graph.add_conditional_edges(
        "parsing",
        route_after_parsing,
        {
            "flag_detected": "poc",  # Flag 감지: PoC 코드 생성
            "shell_acquired": "poc",  # 쉘 획득: PoC 코드 생성
            "success_continue": "track_update",  # 성공: 결과 저장하고 Planning으로
            "retry_instruction": "multi_instruction",  # 실패: Instruction 재설정
            "max_retries_reached": END  # 최대 재시도 횟수 도달: 종료
        }
    )

    # PoC 생성 후 종료
    graph.add_edge("poc", END)

    graph.add_edge("track_update", "feedback")

    # Feedback → Detect (최종 결정자)
    graph.add_edge("feedback", "detect")

    # Exploit → Detect (최종 결정자)
    graph.add_edge("exploit", "detect")

    # Detect 결과에 따라 다음 단계 결정
    graph.add_conditional_edges(
        "detect",
        route_after_detect,
        {
            "poc": "poc",  # 성공: PoC 코드 생성
            "exploit": "exploit",  # Exploit 준비 완료: Exploit 실행
            "continue_planning": "CoT",  # 계속 분석
            "end": END  # 종료
        }
    )

    return graph.compile()

# 하위 호환성을 위한 별칭
def create_init_workflow():
    return _create_analysis_workflow()

def create_loop_workflow():
    return _create_analysis_workflow()

def _create_auto_workflow():
    graph = StateGraph(PlanningState)

    graph.add_node("tool_loading", tool_selection_node)  # 도구 로딩 먼저
    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("multi_instruction", multi_instruction_node)
    graph.add_node("execution", execution_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("track_update", track_update_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("detect", detect_node)  # Detect: 최종 결정자
    graph.add_node("poc", poc_node)

    graph.set_entry_point("tool_loading")  # 도구 로딩부터 시작
    graph.add_edge("tool_loading", "CoT")
    graph.add_edge("CoT", "Cal")
    graph.add_edge("Cal", "multi_instruction")
    graph.add_edge("multi_instruction", "execution")
    graph.add_edge("execution", "parsing")

    # Parsing 결과에 따라 다음 단계 결정
    graph.add_conditional_edges(
        "parsing",
        route_after_parsing,
        {
            "flag_detected": "poc",
            "shell_acquired": "poc",
            "success_continue": "track_update",
            "retry_instruction": "multi_instruction",
            "max_retries_reached": END
        }
    )

    graph.add_edge("poc", END)
    graph.add_edge("track_update", "feedback")

    # Feedback → Detect (최종 결정자)
    graph.add_edge("feedback", "detect")

    # Exploit → Detect (최종 결정자)
    graph.add_edge("exploit", "detect")

    # Auto 모드: Detect 결과에 따라 다음 단계 결정
    graph.add_conditional_edges(
        "detect",
        route_after_detect,
        {
            "poc": "poc",  # 성공: PoC 코드 생성
            "exploit": "exploit",  # Exploit 준비 완료: Exploit 실행
            "continue_planning": "CoT",  # 계속 분석
            "end": END  # 종료
        }
    )

    return graph.compile()

def create_main_workflow():
    workflow = StateGraph(PlanningState)

    # init_workflow와 loop_workflow는 동일한 워크플로우 사용
    analysis_graph = _create_analysis_workflow()
    auto_graph = _create_auto_workflow()

    workflow.add_node("init_workflow", analysis_graph)
    workflow.add_node("loop_workflow", analysis_graph)
    workflow.add_node("auto_workflow", auto_graph)
    workflow.add_node("help", help_node)
    workflow.add_node("option_input", option_input_node)
    workflow.add_node("exploit", exploit_node)

    workflow.set_entry_point("option_input")

    workflow.add_edge("help", "option_input")
    workflow.add_edge("init_workflow", "option_input")
    workflow.add_edge("loop_workflow", "option_input")
    workflow.add_edge("auto_workflow", "option_input")
    workflow.add_edge("exploit", "option_input")

    workflow.add_conditional_edges(
        "option_input",
        route_by_option,
        {
            "help": "help",
            "first_workflow": "init_workflow",
            "loop_workflow": "loop_workflow",
            "auto_workflow": "auto_workflow",
            "exploit_flow": "exploit",
            "end": END,
            "invalid": "help",
            "invalid_init": "help",
            "invalid_loop": "help",
            "invalid_category": "help"
        }
    )

    return workflow.compile()
