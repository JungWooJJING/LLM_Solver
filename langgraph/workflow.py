from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

# 상대 import로 변경 (langgraph 패키지 내에서 사용)
try:
    from langgraph.state import PlanningState
except ImportError:
    # 같은 디렉토리에서 실행하는 경우
    from state import PlanningState

try:
    from langgraph.node import CoT_node, Cal_node, instruction_node, tool_selection_node, multi_instruction_node, execution_node, track_update_node, parsing_node, feedback_node, exploit_node, poc_node, help_node, option_input_node
except ImportError:
    # 같은 디렉토리에서 실행하는 경우
    from node import CoT_node, Cal_node, instruction_node, tool_selection_node, multi_instruction_node, execution_node, track_update_node, parsing_node, feedback_node, exploit_node, poc_node, help_node, option_input_node

def route_by_option(state: PlanningState) -> str:
    option = state.get("option", "")
    has_cot_result = bool(state.get("cot_result"))
    
    if not has_cot_result:
        # 초기 실행: CoT가 아직 실행되지 않음
        if option == "--help":
            return "help"
        elif option == "--file" or option == "--ghidra" or option == "--discuss":
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
        elif option in ["--discuss", "--continue"]:
            return "loop_workflow"
        elif option == "--exploit":
            return "exploit_flow"
        elif option == "--quit":
            return "end"
        elif option in ["--file", "--ghidra"]:
            return "invalid_loop"
        else:
            return "invalid"

def route_loop_option(state: PlanningState) -> str:
    option = state.get("option", "")
    
    if option == "--help":
        return "help"
    elif option in ["--discuss", "--continue"]:
        return "loop_workflow"
    elif option == "--exploit":
        return "exploit_flow"
    elif option == "--quit":
        return "end"
    else:
        return "invalid"

def route_after_parsing(state: PlanningState) -> str:
    """
    Parsing 결과에 따라 다음 단계 결정:
    - Flag 감지: PoC 코드 작성으로 이동
    - 성공: 결과 저장하고 Planning으로 돌아가기
    - 실패: Instruction 재설정
    """
    from rich.console import Console
    console = Console()
    
    execution_status = state.get("execution_status", "unknown")
    flag_detected = state.get("flag_detected", False)
    parsing_json = state.get("parsing_result", "")
    
    # FLAG 감지 확인 (최우선)
    if flag_detected or execution_status == "flag_detected":
        console.print("🚩 Flag detected! Routing to PoC generation", style="bold green")
        return "flag_detected"
    
    # Parsing JSON 파싱
    import json
    try:
        if isinstance(parsing_json, str):
            parsed_data = json.loads(parsing_json) if parsing_json else {}
        else:
            parsed_data = parsing_json
    except:
        parsed_data = {}
    
    # 성공 조건 확인
    signals = parsed_data.get("signals", [])
    errors = parsed_data.get("errors", [])
    has_success_signal = any(s.get("type") in ["leak", "offset", "proof", "oracle"] for s in signals)
    has_errors = len(errors) > 0
    
    if execution_status == "success" or (has_success_signal and not has_errors):
        console.print("✓ Execution successful - saving results and continuing to Planning", style="bold green")
        return "success_continue"
    elif execution_status == "fail" or has_errors:
        console.print("✗ Execution failed - retrying with new instruction", style="bold red")
        return "retry_instruction"
    else:
        # partial 또는 unknown
        console.print("~ Execution partial - saving progress and continuing", style="yellow")
        return "success_continue"

def route_after_feedback(state: PlanningState) -> str:
    """
    Feedback 후 다음 단계 결정:
    - 성공/진행 중이면 Planning으로 돌아가서 더 깊이 파거나 새로운 방법 찾기
    - 실패/중단이면 종료
    """
    from rich.console import Console
    console = Console()
    
    feedback_json = state.get("feedback_json", {})
    tracks = state.get("vulnerability_tracks", {})
    results = state.get("results", [])
    
    # 최대 반복 횟수 체크 (무한 루프 방지)
    MAX_ITERATIONS = 10
    if len(results) >= MAX_ITERATIONS:
        console.print(f"Maximum iterations ({MAX_ITERATIONS}) reached. Ending workflow.", style="bold yellow")
        return "end"
    
    # 성공 조건 확인
    status = feedback_json.get("status", "")
    if status == "success":
        # 성공했지만 더 탐색할 수 있으면 계속, 아니면 종료
        active_tracks = [t for t in tracks.values() if t.get("status") in ["in_progress", "pending"]]
        if not active_tracks:
            console.print("✓ Objective achieved and no active tracks. Ending workflow.", style="bold green")
            return "end"
        console.print("✓ Objective achieved! Returning to Planning for next steps.", style="bold green")
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
            console.print("No active tracks. Returning to Planning to explore new attack vectors.", style="yellow")
            return "continue_planning"
    
    # 진행 중이면 계속 (하지만 최대 반복 횟수 체크)
    if status in ["partial", "in_progress"]:
        console.print("Progress made. Returning to Planning for deeper exploration or new vectors.", style="cyan")
        return "continue_planning"
    
    # 실패면 종료 조건 확인
    if status == "fail":
        # 연속 실패 횟수 확인
        consecutive_failures = sum(t.get("consecutive_failures", 0) for t in tracks.values())
        if consecutive_failures >= 5:  # 5번 연속 실패하면 종료
            console.print("Too many consecutive failures. Ending workflow.", style="bold red")
            return "end"
        console.print("Current approach failed. Trying new approach...", style="yellow")
        return "continue_planning"
    
    # 기본값: Planning으로 돌아가기 (하지만 안전장치)
    console.print("Returning to Planning for next iteration.", style="cyan")
    return "continue_planning"

def create_init_workflow():
    graph = StateGraph(PlanningState)

    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("tool_selection", tool_selection_node)
    graph.add_node("multi_instruction", multi_instruction_node)
    graph.add_node("execution", execution_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("track_update", track_update_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("poc", poc_node)

    graph.set_entry_point("CoT")
    graph.add_edge("CoT", "Cal")
    graph.add_edge("Cal", "tool_selection")
    graph.add_edge("tool_selection", "multi_instruction")
    graph.add_edge("multi_instruction", "execution")
    graph.add_edge("execution", "parsing")
    
    # Parsing 결과에 따라 다음 단계 결정
    graph.add_conditional_edges(
        "parsing",
        route_after_parsing,
        {
            "flag_detected": "poc",  # Flag 감지: PoC 코드 생성
            "success_continue": "track_update",  # 성공: 결과 저장하고 Planning으로
            "retry_instruction": "multi_instruction"  # 실패: Instruction 재설정
        }
    )
    
    # PoC 생성 후 종료
    graph.add_edge("poc", END)

    graph.add_edge("track_update", "feedback")
    
    # Feedback 후 Planning으로 돌아가거나 종료
    graph.add_conditional_edges(
        "feedback",
        route_after_feedback,
        {
            "continue_planning": "CoT",  # Planning으로 돌아가서 더 깊이 파거나 새로운 방법 찾기
            "end": END
        }
    )
    
    return graph.compile()

def create_loop_workflow():
    graph = StateGraph(PlanningState)

    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("tool_selection", tool_selection_node)
    graph.add_node("multi_instruction", multi_instruction_node)
    graph.add_node("execution", execution_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("track_update", track_update_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("poc", poc_node)

    graph.set_entry_point("CoT")
    graph.add_edge("CoT", "Cal")
    graph.add_edge("Cal", "tool_selection")
    graph.add_edge("tool_selection", "multi_instruction")
    graph.add_edge("multi_instruction", "execution")
    graph.add_edge("execution", "parsing")
    
    # Parsing 결과에 따라 다음 단계 결정
    graph.add_conditional_edges(
        "parsing",
        route_after_parsing,
        {
            "flag_detected": "poc",  # Flag 감지: PoC 코드 생성
            "success_continue": "track_update",  # 성공: 결과 저장하고 Planning으로
            "retry_instruction": "multi_instruction"  # 실패: Instruction 재설정
        }
    )
    
    # PoC 생성 후 종료
    graph.add_edge("poc", END)

    graph.add_edge("track_update", "feedback")
    
    # Feedback 후 Planning으로 돌아가거나 종료
    graph.add_conditional_edges(
        "feedback",
        route_after_feedback,
        {
            "continue_planning": "CoT",  # Planning으로 돌아가서 더 깊이 파거나 새로운 방법 찾기
            "end": END
        }
    )

    return graph.compile()

def create_main_workflow():
    workflow = StateGraph(PlanningState)

    init_graph = create_init_workflow()
    loop_graph = create_loop_workflow()

    workflow.add_node("init_workflow", init_graph)
    workflow.add_node("loop_workflow", loop_graph)
    workflow.add_node("help", help_node)
    workflow.add_node("option_input", option_input_node)
    workflow.add_node("exploit", exploit_node)

    workflow.set_entry_point("option_input")
    
    workflow.add_edge("help", "option_input")
    
    workflow.add_edge("init_workflow", "option_input")
    
    workflow.add_edge("loop_workflow", "option_input")
    
    workflow.add_edge("exploit", "option_input")
    
    workflow.add_conditional_edges(
        "option_input",
        route_by_option,
        {
            "help": "help",
            "first_workflow": "init_workflow",
            "loop_workflow": "loop_workflow",
            "exploit_flow": "exploit",
            "end": END,
            "invalid": "help",
            "invalid_init": "help",
            "invalid_loop": "help"
        }
    )
    
    return workflow.compile()
