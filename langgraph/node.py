from typing import Dict, Any
import os
import re
from rich.console import Console

try:
    from langgraph.state import PlanningState as State, get_state_for_cot, get_state_for_cal, get_state_for_instruction, get_state_for_parsing, get_state_for_feedback
except ImportError:
    from state import PlanningState as State, get_state_for_cot, get_state_for_cal, get_state_for_instruction, get_state_for_parsing, get_state_for_feedback

# 전역 console 객체
console = Console()

# build_query import
try:
    from utility.build_query import build_query
except ImportError:
    # utility 모듈이 없는 경우를 대비
    def build_query(*args, **kwargs):
        raise RuntimeError("build_query is not available. Check utility.build_query module.")

# ghdira_API import
try:
    from utility.ghidra import ghdira_API
except ImportError:
    def ghdira_API(*args, **kwargs):
        raise RuntimeError("ghdira_API is not available. Ghidra is not configured.")

def CoT_node(state: State) -> State:
    ctx = state["ctx"]
    option = state["option"]
    core = ctx.core

    console.print("=== Planning Agent ===", style='bold magenta')

    # 사용자 입력 수집 (시나리오 노드 기능 통합)
    if not state.get("user_input") and not state.get("binary_path"):
        if option == "--file":
            console.print("Paste the challenge's source code. Type <<<END>>> on a new line to finish.", style="blue")
            planning_code = core.multi_line_input()
            state["user_input"] = planning_code
        
        elif option == "--ghidra":
            console.print("Enter the binary path: ", style="blue", end="")
            binary_path = input()
            state["binary_path"] = binary_path
            
            console.print("=== Ghidra Run ===", style='bold green')
            try:
                binary_code = ghdira_API(binary_path)
                state["user_input"] = binary_code
            except Exception as e:
                console.print(f"Error running Ghidra: {e}", style="bold red")
                console.print("Continuing without decompilation...", style="yellow")
        
        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_discuss = core.multi_line_input()
            state["user_input"] = planning_discuss

    console.print("=== CoT Run ===", style='bold green')
    
    # 기존 트랙과 결과 정보 수집
    tracks = state.get("vulnerability_tracks", {})
    facts = state.get("facts", {})
    artifacts = state.get("artifacts", {})
    results = state.get("results", [])
    
    # Planning 컨텍스트: 기존 트랙 상태 요약
    planning_context = {
        "existing_tracks": {
            track_id: {
                "vuln": track.get("vuln"),
                "status": track.get("status"),
                "progress": track.get("progress", 0.0),
                "signals": track.get("signals", []),
                "attempts": track.get("attempts", 0)
            }
            for track_id, track in tracks.items()
        },
        "discovered_facts": facts,
        "generated_artifacts": list(artifacts.keys()),
        "recent_results": results[-5:] if results else []  # 최근 5개 결과만
    }
    
    if option == "--file" or option == "--ghidra":
        user_input = state.get("user_input", "") or state.get("binary_path", "")
        # 초기 실행이면 planning_context 없음, 반복 실행이면 포함
        if tracks or facts or artifacts:
            CoT_query = build_query(option = option, code = user_input, state = state, planning_context = planning_context)
        else:
            CoT_query = build_query(option = option, code = user_input, state = state)

    elif option == "--discuss" or option == "--continue":
        user_input = state.get("user_input", "")
        CoT_query = build_query(option = option, code = user_input, state = state, plan = state.get("plan", {}), planning_context = planning_context)
    
    # CoT Agent에 필요한 정보만 필터링
    filtered_state = get_state_for_cot(state)
    CoT_return = ctx.planning.run_CoT(prompt_query = CoT_query, ctx = ctx, state = filtered_state)

    state["cot_result"] = CoT_return
    state["cot_json"] = core.safe_json_loads(CoT_return)
    
    # 이전 CoT 결과 저장
    if "previous_cot_results" not in state:
        state["previous_cot_results"] = []
    state["previous_cot_results"].append(CoT_return)
    
    # 최대 10개만 유지
    if len(state["previous_cot_results"]) > 10:
        state["previous_cot_results"] = state["previous_cot_results"][-10:]

    return state

def Cal_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    Cal_query = build_query(option = "--Cal", state = state, CoT = state["cot_result"])

    console.print("=== Cal Run ===", style='bold green')

    # Cal Agent에 필요한 정보만 필터링
    filtered_state = get_state_for_cal(state)
    Cal_return = ctx.planning.run_Cal(prompt_query = Cal_query, state = filtered_state)

    console.print(f"{Cal_return}", style='bold yellow')
    
    state["cal_result"] = Cal_return
    state["cal_json"] = core.safe_json_loads(Cal_return)
    
    # 이전 Cal 결과 저장
    if "previous_cal_results" not in state:
        state["previous_cal_results"] = []
    state["previous_cal_results"].append(Cal_return)
    
    # 최대 10개만 유지
    if len(state["previous_cal_results"]) > 10:
        state["previous_cal_results"] = state["previous_cal_results"][-10:]

    return state

def instruction_node(state: State) -> State:
    """기존 단일 instruction 노드 (하위 호환성)"""
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Instruction Agent ===", style='bold magenta')

    instruction_query = build_query(option = "--instruction", CoT = state["cot_json"], Cal = state["cal_json"])

    console.print("=== Instruction Run ===", style='bold green')

    # Instruction Agent에 필요한 정보만 필터링
    filtered_state = get_state_for_instruction(state)
    instruction_return = ctx.instruction.run_instruction(prompt_query = instruction_query, state = filtered_state)

    state["instruction_result"] = instruction_return
    state["instruction_json"] = core.safe_json_loads(instruction_return)

    return state


def tool_selection_node(state: State) -> State:
    """
    Cal 후, Instruction 전: 각 트랙에 적합한 도구 선택
    """
    from datetime import datetime
    from tool import create_pwnable_tools, create_reversing_tools, create_web_tools

    console.print("=== Tool Selection Node ===", style='bold magenta')

    cot_json = state.get("cot_json", {})
    cal_json = state.get("cal_json", {})
    tracks = state.get("vulnerability_tracks", {})
    binary_path = state.get("binary_path", "")
    challenge = state.get("challenge", [])

    # Challenge 카테고리 확인
    challenge_category = challenge[0].get("category", "").lower() if challenge else ""

    # Cal 결과에서 상위 candidates 선택 (최대 3개)
    cal_results = cal_json.get("results", [])
    if not cal_results:
        console.print("No Cal results available. Skipping tool selection.", style="yellow")
        return state

    # 실패율 기반 우선순위 조정
    def calculate_failure_rate(track):
        """트랙의 실패율 계산"""
        attempts = track.get("attempts", 0)
        consecutive_failures = track.get("consecutive_failures", 0)
        if attempts == 0:
            return 0.0
        return consecutive_failures / max(attempts, 1)

    # 기존 트랙의 실패율을 기반으로 우선순위 조정
    for track_id, track in tracks.items():
        failure_rate = calculate_failure_rate(track)
        if failure_rate > 0.5:
            # 실패율이 50% 이상이면 우선순위 반감
            current_priority = track.get("priority", 1.0)
            track["priority"] = current_priority * 0.5
            console.print(f"  Adjusted priority for {track_id} (failure rate: {failure_rate:.1%}) -> {track['priority']:.2f}", style="yellow")

    # 점수 순으로 정렬
    sorted_results = sorted(cal_results, key=lambda x: x.get("final", 0), reverse=True)
    
    # 최대 3개 선택
    MAX_TRACKS = 3
    threshold = 0.6
    selected_candidates = []
    
    for result in sorted_results:
        if len(selected_candidates) >= MAX_TRACKS:
            break
        if result.get("final", 0) >= threshold:
            selected_candidates.append(result)
    
    if not selected_candidates:
        selected_candidates = sorted_results[:1]
    
    # 각 candidate에 대해 도구 선택
    track_tools = {}
    
    for candidate in selected_candidates:
        idx = candidate.get("idx", -1)
        if idx < 0 or idx >= len(cot_json.get("candidates", [])):
            continue
        
        cot_candidate = cot_json["candidates"][idx]
        track_id = f"track_{idx:03d}"
        vuln = cot_candidate.get("vuln", "").lower()
        
        # 취약점 유형에 따라 도구 선택
        selected_toolset = None
        tool_category = None
        
        # 취약점 키워드 기반 도구 선택
        if any(keyword in vuln for keyword in ["stack", "heap", "rop", "ret2", "format", "uaf", "double free", "pwn", "bof"]):
            tool_category = "pwnable"
            selected_toolset = create_pwnable_tools(binary_path=binary_path if binary_path else None)
            console.print(f"  {track_id}: Selected pwnable_tool (vuln: {cot_candidate.get('vuln')})", style="cyan")
        
        elif any(keyword in vuln for keyword in ["sql", "xss", "csrf", "ssrf", "ssti", "web", "http", "api"]):
            tool_category = "web"
            # URL은 state에서 가져오거나 기본값 사용
            url = state.get("url", "")
            selected_toolset = create_web_tools(url=url if url else None)
            console.print(f"  {track_id}: Selected web_tool (vuln: {cot_candidate.get('vuln')})", style="cyan")
        
        elif any(keyword in vuln for keyword in ["reverse", "decompile", "disassemble", "ghidra", "angr", "symbolic"]):
            tool_category = "reversing"
            selected_toolset = create_reversing_tools(binary_path=binary_path if binary_path else None)
            console.print(f"  {track_id}: Selected reversing_tool (vuln: {cot_candidate.get('vuln')})", style="cyan")
        
        else:
            # Challenge 카테고리 기반 기본 도구 선택
            if challenge_category == "pwnable" or challenge_category == "pwn":
                tool_category = "pwnable"
                selected_toolset = create_pwnable_tools(binary_path=binary_path if binary_path else None)
            elif challenge_category == "web":
                tool_category = "web"
                url = state.get("url", "")
                selected_toolset = create_web_tools(url=url if url else None)
            elif challenge_category == "reversing" or challenge_category == "rev":
                tool_category = "reversing"
                selected_toolset = create_reversing_tools(binary_path=binary_path if binary_path else None)
            else:
                # 기본값: pwnable
                tool_category = "pwnable"
                selected_toolset = create_pwnable_tools(binary_path=binary_path if binary_path else None)
            
            console.print(f"  {track_id}: Selected {tool_category}_tool (based on challenge category)", style="cyan")
        
        # 트랙에 도구 정보 저장
        if track_id not in tracks:
            tracks[track_id] = {
                "track_id": track_id,
                "vuln": cot_candidate.get("vuln", "Unknown"),
                "status": "pending",
                "progress": 0.0,
                "attempts": 0,
                "consecutive_failures": 0,
                "created_at": datetime.now().isoformat(),
                "artifacts": {},
                "signals": []
            }
        
        tracks[track_id]["tool_category"] = tool_category
        tracks[track_id]["available_tools"] = [tool.name for tool in selected_toolset]
        tracks[track_id]["vuln"] = cot_candidate.get("vuln", tracks[track_id].get("vuln", "Unknown"))  # vuln 정보 보존
        track_tools[track_id] = {
            "toolset": selected_toolset,
            "tool_category": tool_category,
            "tool_names": [tool.name for tool in selected_toolset]
        }
    
    # State에 도구 정보 저장
    state["vulnerability_tracks"] = tracks
    state["track_tools"] = track_tools
    
    console.print(f"\n=== Tool Selection Complete: {len(track_tools)} track(s) ===", style="bold green")
    
    return state


def multi_instruction_node(state: State) -> State:
    """
    Multi-Track Planning: 최대 3개 트랙에 대한 instruction 생성
    도구 선택 후 실행됨
    """
    from datetime import datetime
    import json
    
    ctx = state["ctx"]
    core = ctx.core
    
    console.print("=== Multi-Instruction Agent (Max 3 Tracks) ===", style='bold magenta')
    
    # 기존 트랙들 가져오기
    tracks = state.get("vulnerability_tracks", {})
    track_tools = state.get("track_tools", {})
    cot_json = state.get("cot_json", {})
    cal_json = state.get("cal_json", {})
    
    # Cal 결과에서 상위 candidates 선택 (최대 3개)
    cal_results = cal_json.get("results", [])
    if not cal_results:
        console.print("No Cal results available. Falling back to single instruction.", style="yellow")
        return instruction_node(state)
    
    # 점수 순으로 정렬
    sorted_results = sorted(cal_results, key=lambda x: x.get("final", 0), reverse=True)
    
    # 최대 3개 선택 (threshold: 0.6 이상)
    MAX_TRACKS = 3
    threshold = 0.6
    selected_candidates = []
    
    for result in sorted_results:
        if len(selected_candidates) >= MAX_TRACKS:
            break
        if result.get("final", 0) >= threshold:
            selected_candidates.append(result)
    
    if not selected_candidates:
        console.print("No candidates above threshold. Using top candidate.", style="yellow")
        selected_candidates = sorted_results[:1]
    
    console.print(f"Selected {len(selected_candidates)} track(s) for parallel exploration", style="bold green")
    
    # 각 candidate에 대해 instruction 생성
    multi_instructions = []
    
    for candidate in selected_candidates:
        idx = candidate.get("idx", -1)
        if idx < 0 or idx >= len(cot_json.get("candidates", [])):
            continue
        
        cot_candidate = cot_json["candidates"][idx]
        track_id = f"track_{idx:03d}"
        
        # 기존 트랙이 있으면 업데이트, 없으면 새로 생성
        if track_id not in tracks:
            # 새 트랙 생성
            tracks[track_id] = {
                "track_id": track_id,
                "vuln": cot_candidate.get("vuln", "Unknown"),
                "status": "in_progress",
                "priority": candidate.get("final", 0),
                "progress": 0.0,
                "created_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "cot_idx": idx,
                "why": cot_candidate.get("why", ""),
                "cot_now": cot_candidate.get("cot_now", ""),
                "completed_steps": [],
                "current_step": None,
                "next_steps": [],
                "artifacts": {},
                "signals": [],
                "success_criteria": [],
                "failure_conditions": [],
                "attempts": 0,
                "consecutive_failures": 0,
                "estimated_completion": 0.0
            }
            vuln_name = tracks[track_id].get('vuln', 'Unknown')
            priority = tracks[track_id].get('priority', 0)
            console.print(f"  Created new track: {track_id} - {vuln_name} (priority: {priority:.2f})", style="cyan")
        else:
            # 기존 트랙 업데이트
            tracks[track_id]["priority"] = candidate.get("final", 0)
            tracks[track_id]["last_updated"] = datetime.now().isoformat()
            vuln_name = tracks[track_id].get('vuln', 'Unknown')
            progress = tracks[track_id].get('progress', 0.0)
            console.print(f"  Continuing track: {track_id} - {vuln_name} (progress: {progress:.1%})", style="cyan")
        
        # 해당 트랙의 instruction 생성
        # 기존 트랙이 있으면 다음 단계, 없으면 첫 단계
        track = tracks[track_id]

        # 해당 트랙의 도구 정보 가져오기
        track_tool_info = track_tools.get(track_id, {})
        available_tools = track_tool_info.get("tool_names", [])
        tool_category = track_tool_info.get("tool_category", "unknown")

        # Fallback 전략: 실패 횟수에 따라 접근 방식 변경
        retry_count = state.get("instruction_retry_count", 0)
        consecutive_failures = track.get("consecutive_failures", 0)

        # Fallback 로직
        if consecutive_failures >= 3:
            # 3번 연속 실패: 완전히 다른 접근 방식 제안
            console.print(f"  {track_id} has failed {consecutive_failures} times. Switching to alternative approach.", style="yellow")
            instruction_query = build_query(
                option="--instruction_fallback",
                CoT={"candidates": [cot_candidate]},
                Cal={"results": [candidate]},
                available_tools=available_tools,
                tool_category=tool_category,
                fallback_mode="alternative"
            )
        elif consecutive_failures >= 2:
            # 2번 연속 실패: 단순한 접근으로 전환
            console.print(f"  {track_id} has failed {consecutive_failures} times. Using simpler approach.", style="yellow")
            instruction_query = build_query(
                option="--instruction_fallback",
                CoT={"candidates": [cot_candidate]},
                Cal={"results": [candidate]},
                available_tools=available_tools,
                tool_category=tool_category,
                fallback_mode="simple"
            )
        else:
            # 정상 실행
            instruction_query = build_query(
                option="--instruction",
                CoT={"candidates": [cot_candidate]},  # 해당 candidate만
                Cal={"results": [candidate]},  # 해당 result만
                available_tools=available_tools,  # 사용 가능한 도구 목록
                tool_category=tool_category  # 도구 카테고리
            )

        # Instruction Agent에 필요한 정보만 필터링
        filtered_state = get_state_for_instruction(state)
        # 트랙 정보 + 도구 정보 추가
        filtered_state["current_track"] = track_id
        filtered_state["current_track_info"] = track
        filtered_state["available_tools"] = available_tools
        filtered_state["tool_category"] = tool_category
        filtered_state["fallback_mode"] = "alternative" if consecutive_failures >= 3 else "simple" if consecutive_failures >= 2 else "normal"

        instruction_return = ctx.instruction.run_instruction(
            prompt_query=instruction_query,
            state=filtered_state
        )

        instruction_json = core.safe_json_loads(instruction_return)
        
        multi_instructions.append({
            "track_id": track_id,
            "instruction_result": instruction_return,
            "instruction_json": instruction_json,
            "priority": candidate.get("final", 0)
        })
        
        console.print(f"    Generated instruction for {track_id}", style="green")
    
    # State 업데이트
    state["vulnerability_tracks"] = tracks
    state["multi_instructions"] = multi_instructions
    
    # 하위 호환성을 위해 첫 번째 instruction을 기본값으로 설정
    if multi_instructions:
        state["instruction_result"] = multi_instructions[0]["instruction_result"]
        state["instruction_json"] = multi_instructions[0]["instruction_json"]
    
    console.print(f"\n=== Multi-Instruction Complete: {len(multi_instructions)} track(s) ===", style="bold green")
    
    return state


def execution_node(state: State) -> State:
    """
    multi_instructions의 각 트랙에 대해 명령을 자동으로 실행
    """
    import subprocess
    from datetime import datetime
    
    ctx = state["ctx"]
    core = ctx.core
    
    console.print("=== Execution Node ===", style='bold magenta')
    
    multi_instructions = state.get("multi_instructions", [])
    
    if not multi_instructions:
        console.print("No instructions to execute.", style="yellow")
        return state
    
    execution_results = {}
    all_outputs = []
    
    # 각 트랙의 instruction 실행
    for inst_data in multi_instructions:
        track_id = inst_data.get("track_id", "unknown")
        instruction_json = inst_data.get("instruction_json", {})
        
        console.print(f"\n=== Executing {track_id} ===", style='bold green')
        
        steps = instruction_json.get("steps", [])
        if not steps:
            console.print(f"  No steps found for {track_id}", style="yellow")
            continue
        
        track_output = []
        
        for step in steps:
            cmd = step.get("cmd", "")
            name = step.get("name", "unknown")
            artifact = step.get("artifact", "-")
            
            if not cmd:
                continue
            
            console.print(f"  Executing: {name}", style="cyan")
            console.print(f"  Command: {cmd}", style="dim")
            
            # 도구 호출인지 확인
            track_tools = state.get("track_tools", {})
            track_tool_info = track_tools.get(track_id, {})
            toolset = track_tool_info.get("toolset", [])
            tool_names = track_tool_info.get("tool_names", [])
            
            # cmd가 도구 이름으로 시작하는지 확인
            is_tool_call = False
            tool_name = None
            tool_instance = None
            
            # 도구 이름 확인 (예: "ghidra_decompile", "checksec_analysis" 등)
            for tool in toolset:
                if cmd.strip().startswith(tool.name):
                    is_tool_call = True
                    tool_name = tool.name
                    tool_instance = tool
                    break
            
            try:
                if is_tool_call and tool_instance:
                    # LangChain 도구 호출
                    console.print(f"    Detected tool call: {tool_name}", style="yellow")
                    
                    # cmd에서 도구 인자 파싱 시도
                    # 예: "ghidra_decompile /path/to/binary 0x4019a6" 또는
                    #     "ghidra_decompile(binary_path='/path/to/binary', function_address='0x4019a6')"
                    tool_args = {}
                    
                    # 방법 1: 함수 호출 형식 파싱 (예: tool_name(arg1=val1, arg2=val2))
                    func_call_pattern = rf"{re.escape(tool_name)}\s*\(([^)]+)\)"
                    func_match = re.search(func_call_pattern, cmd)
                    if func_match:
                        args_str = func_match.group(1)
                        # 간단한 파싱: key='value' 또는 key="value" 형식
                        arg_pattern = r"(\w+)\s*=\s*['\"]([^'\"]+)['\"]"
                        for arg_match in re.finditer(arg_pattern, args_str):
                            key = arg_match.group(1)
                            value = arg_match.group(2)
                            tool_args[key] = value
                    else:
                        # 방법 2: 옵션 형식 파싱 (예: tool_name --param1 value1 --param2 value2)
                        args_str = cmd.replace(tool_name, "").strip()
                        if args_str:
                            # --param value 형식 파싱
                            option_pattern = r"--(\w+)\s+([^\s]+(?:\s+[^\s]+)*?)(?=\s+--|\s*$)"
                            option_matches = re.finditer(option_pattern, args_str)
                            
                            # 도구 스키마 확인하여 인자 매핑
                            param_mapping = {}
                            if hasattr(tool_instance, 'args_schema'):
                                schema = tool_instance.args_schema
                                if hasattr(schema, 'schema'):
                                    schema_dict = schema.schema()
                                    properties = schema_dict.get('properties', {})
                                    # 옵션 이름을 파라미터 이름으로 매핑 (예: --binary -> binary_path)
                                    for prop_name, prop_info in properties.items():
                                        # 일반적인 매핑 규칙
                                        if 'binary' in prop_name.lower() or 'file' in prop_name.lower():
                                            param_mapping['binary'] = prop_name
                                            param_mapping['file'] = prop_name
                                        elif 'address' in prop_name.lower() or 'addr' in prop_name.lower():
                                            param_mapping['address'] = prop_name
                                            param_mapping['addr'] = prop_name
                                        elif 'function' in prop_name.lower() or 'func' in prop_name.lower():
                                            param_mapping['function'] = prop_name
                                            param_mapping['func'] = prop_name
                                        elif 'name' in prop_name.lower():
                                            param_mapping['name'] = prop_name
                                        # 직접 매핑
                                        param_mapping[prop_name] = prop_name
                            
                            for match in option_matches:
                                option_name = match.group(1)
                                option_value = match.group(2).strip().strip('"\'')
                                # 매핑된 파라미터 이름 사용
                                param_name = param_mapping.get(option_name, option_name)
                                tool_args[param_name] = option_value
                            
                            # 옵션 형식이 아니면 방법 3: 공백으로 구분된 인자 파싱
                            if not tool_args:
                                parts = args_str.split()
                                if hasattr(tool_instance, 'args_schema'):
                                    schema = tool_instance.args_schema
                                    if hasattr(schema, 'schema'):
                                        schema_dict = schema.schema()
                                        properties = schema_dict.get('properties', {})
                                        prop_names = list(properties.keys())
                                        
                                        # 위치 기반 인자 매핑
                                        for i, part in enumerate(parts):
                                            if i < len(prop_names):
                                                prop_name = prop_names[i]
                                                # 경로나 주소인지 확인
                                                if '/' in part or part.startswith('0x'):
                                                    tool_args[prop_name] = part
                                                else:
                                                    tool_args[prop_name] = part
                    
                    # 도구 호출
                    try:
                        if tool_args:
                            tool_result = tool_instance.invoke(tool_args)
                        else:
                            # 인자가 없으면 빈 딕셔너리로 호출
                            tool_result = tool_instance.invoke({})
                        
                        # 결과를 문자열로 변환
                        if isinstance(tool_result, str):
                            stdout_text = tool_result
                        else:
                            import json
                            stdout_text = json.dumps(tool_result, indent=2, ensure_ascii=False)
                        
                        stderr_text = ""
                        returncode = 0
                        
                        # subprocess 결과 형식으로 변환
                        class ToolResult:
                            def __init__(self, stdout, stderr, returncode):
                                self.stdout = stdout.encode('utf-8') if isinstance(stdout, str) else stdout
                                self.stderr = stderr.encode('utf-8') if isinstance(stderr, str) else stderr
                                self.returncode = returncode
                        
                        result = ToolResult(stdout_text, stderr_text, returncode)
                        
                    except Exception as e:
                        # 도구 호출 실패
                        stdout_text = f"Tool execution error: {str(e)}"
                        stderr_text = str(e)
                        returncode = 1
                        
                        class ToolResult:
                            def __init__(self, stdout, stderr, returncode):
                                self.stdout = stdout.encode('utf-8') if isinstance(stdout, str) else stdout
                                self.stderr = stderr.encode('utf-8') if isinstance(stderr, str) else stderr
                                self.returncode = returncode
                        
                        result = ToolResult(stdout_text, stderr_text, returncode)
                else:
                    # 일반 커맨드 실행
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=False,  # 바이너리 모드로 먼저 받기
                        timeout=60  # 60초 타임아웃
                    )
                    
                    # stdout/stderr를 안전하게 디코딩 (UTF-8 에러 무시)
                    try:
                        stdout_text = result.stdout.decode('utf-8', errors='replace')
                    except (UnicodeDecodeError, AttributeError):
                        stdout_text = result.stdout.decode('latin-1', errors='replace') if result.stdout else ""
                    
                    try:
                        stderr_text = result.stderr.decode('utf-8', errors='replace')
                    except (UnicodeDecodeError, AttributeError):
                        stderr_text = result.stderr.decode('latin-1', errors='replace') if result.stderr else ""
                
                # 쉘 획득 여부 직접 확인 (파이프 사용 시 출력 확인)
                # 더 엄격한 검증: 여러 인디케이터를 조합해서 확인
                def is_shell_acquired(text: str) -> bool:
                    """쉘 획득 여부를 엄격하게 검증"""
                    if not text:
                        return False
                    
                    text_lower = text.lower()
                    
                    # 1. 쉘 프롬프트 확인 (가장 확실한 신호)
                    shell_prompts = ["$ ", "# ", "> ", "bash:", "sh:", "zsh:", "csh:"]
                    has_prompt = any(prompt in text for prompt in shell_prompts)
                    
                    # 2. 실제 명령어 실행 결과 패턴 확인
                    # "id" 명령어의 전체 출력 패턴: "uid=0(root) gid=0(root) groups=0(root)"
                    id_pattern = r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)"
                    has_id_output = bool(re.search(id_pattern, text))
                    
                    # 3. "whoami" 명령어 결과 확인
                    whoami_pattern = r"^(root|admin|user|www-data|nobody|daemon)\s*$"
                    has_whoami = bool(re.search(whoami_pattern, text, re.MULTILINE))
                    
                    # 4. 쉘 환경 변수 확인
                    env_vars = ["PATH=", "HOME=", "USER=", "SHELL="]
                    has_env_vars = sum(1 for var in env_vars if var in text) >= 2  # 최소 2개 이상
                    
                    # 5. 실제 쉘 명령어 실행 결과 (ls -la 출력 패턴)
                    # "drwx" 또는 "-rwx"가 있고, 그 다음에 파일명이나 디렉토리명이 있는 경우
                    ls_pattern = r"[d-][rwx-]{9}\s+\d+\s+\w+\s+\w+\s+\d+\s+[A-Za-z]{3}\s+\d+\s+[\d:]+\s+[^\s]+"
                    has_ls_output = bool(re.search(ls_pattern, text))
                    
                    # 6. 쉘 세션 시작 신호
                    session_indicators = ["welcome", "last login", "login:", "password:", "command not found"]
                    has_session = any(ind in text_lower for ind in session_indicators)
                    
                    # 최소 2개 이상의 강한 신호가 있어야 쉘 획득으로 판단
                    strong_signals = [
                        has_prompt,  # 쉘 프롬프트
                        has_id_output,  # id 명령어 출력
                        (has_whoami and has_env_vars),  # whoami + 환경 변수
                        (has_ls_output and has_env_vars),  # ls 출력 + 환경 변수
                    ]
                    
                    # 또는 쉘 프롬프트가 있고 추가 신호가 하나라도 있으면
                    if has_prompt and (has_id_output or has_whoami or has_ls_output or has_env_vars):
                        return True
                    
                    # 또는 강한 신호가 2개 이상
                    if sum(strong_signals) >= 2:
                        return True
                    
                    return False
                
                has_shell_output = is_shell_acquired(stdout_text)
                
                step_output = {
                    "name": name,
                    "cmd": cmd,
                    "success": result.returncode == 0 or has_shell_output,  # 쉘 출력이 있으면 성공으로 간주
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "returncode": result.returncode,
                    "timestamp": datetime.now().isoformat(),
                    "shell_acquired": has_shell_output  # 쉘 획득 플래그 추가
                }
                
                if has_shell_output:
                    console.print(f"    🐚 Shell output detected in {name}", style="bold green")
                
                # 아티팩트 저장 (바이너리 모드로 저장 가능하도록)
                if artifact != "-" and result.stdout:
                    try:
                        artifact_path = f"./artifacts/{artifact}"
                        os.makedirs("./artifacts", exist_ok=True)
                        # 바이너리 데이터일 수 있으므로 바이너리 모드로 저장
                        with open(artifact_path, "wb") as f:
                            f.write(result.stdout)
                        step_output["artifact_saved"] = artifact_path
                        
                        # State의 artifacts에 추가
                        if "artifacts" not in state:
                            state["artifacts"] = {}
                        state["artifacts"][artifact] = artifact_path
                    except Exception as e:
                        console.print(f"    Warning: Failed to save artifact {artifact}: {e}", style="yellow")
                
                track_output.append(step_output)
                # 출력 미리보기 (안전하게)
                preview = stdout_text[:200] if stdout_text else ""
                all_outputs.append(f"[{track_id}] {name}: {preview}...")
                
                # 쉘 출력이 있으면 returncode와 관계없이 성공으로 처리
                if has_shell_output:
                    status_style = "green"
                    console.print(f"    {name} (shell acquired, returncode: {result.returncode})", style=status_style)
                else:
                    status_style = "green" if result.returncode == 0 else "red"
                    console.print(f"    {name} (returncode: {result.returncode})", style=status_style)
                
            except subprocess.TimeoutExpired:
                console.print(f"    {name} (timeout)", style="red")
                track_output.append({
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": "Timeout after 60 seconds",
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                console.print(f"    {name} (error: {e})", style="red")
                track_output.append({
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
        
        # 트랙별 결과 저장 및 쉘 획득 확인
        track_has_shell = any(step.get('shell_acquired', False) for step in track_output)
        
        execution_results[track_id] = "\n".join([
            f"=== {step['name']} ===\n"
            f"Command: {step['cmd']}\n"
            f"Return code: {step.get('returncode', 'N/A')}\n"
            f"Shell acquired: {step.get('shell_acquired', False)}\n"
            f"Stdout:\n{step.get('stdout', '')}\n"
            f"Stderr:\n{step.get('stderr', '')}\n"
            for step in track_output
        ])
        
        # 쉘 획득이 있으면 execution_status를 success로 설정
        if track_has_shell:
            state["execution_status"] = "success"
            console.print(f"  {track_id}: Shell acquired - marking as success", style="bold green")
    
    # State 업데이트
    state["execution_results"] = execution_results
    state["execution_output"] = "\n".join(all_outputs) if all_outputs else ""
    
    # execution_status가 아직 설정되지 않았으면 기본값 설정
    if "execution_status" not in state or state.get("execution_status") == "":
        if execution_results:
            state["execution_status"] = "partial"  # 기본값, parsing에서 업데이트
        else:
            state["execution_status"] = "fail"
    
    console.print(f"\n=== Execution Complete: {len(execution_results)} track(s) ===", style="bold green")
    
    return state


def track_update_node(state: State) -> State:
    """
    각 트랙의 진행 상황 업데이트 및 결과 저장
    """
    from datetime import datetime
    import json
    
    console.print("=== Track Update Node ===", style='bold magenta')
    
    tracks = state.get("vulnerability_tracks", {})
    multi_parsing_results = state.get("multi_parsing_results", {})
    parsing_result = state.get("parsing_result", "")
    execution_status = state.get("execution_status", "")
    execution_results = state.get("execution_results", {})
    
    # Parsing 결과를 JSON으로 파싱
    parsing_json = {}
    try:
        if isinstance(parsing_result, str):
            parsing_json = json.loads(parsing_result) if parsing_result else {}
        else:
            parsing_json = parsing_result
    except:
        parsing_json = {}
    
    # Parsing 결과를 각 트랙에 적용 및 results에 저장
    for track_id, track in tracks.items():
        track["last_updated"] = datetime.now().isoformat()
        track["attempts"] += 1
        
        # 해당 트랙의 parsing 결과가 있으면 사용
        track_parsing_result = multi_parsing_results.get(track_id, parsing_result)
        track_parsing_json = {}
        try:
            if isinstance(track_parsing_result, str):
                track_parsing_json = json.loads(track_parsing_result) if track_parsing_result else {}
            else:
                track_parsing_json = track_parsing_result
        except:
            track_parsing_json = {}
        
        # 실행 결과를 results에 저장
        execution_output = execution_results.get(track_id, "")
        if execution_output:
            result_entry = {
                "timestamp": datetime.now().isoformat(),
                "track_id": track_id,
                "status": execution_status,
                "execution_output": execution_output,
                "parsing_result": track_parsing_json,
                "signals": track_parsing_json.get("signals", []),
                "artifacts": track_parsing_json.get("artifacts", []),
                "errors": track_parsing_json.get("errors", [])
            }
            if "results" not in state:
                state["results"] = []
            state["results"].append(result_entry)
        
        # Progress 업데이트
        if execution_status == "success":
            track["progress"] = min(track["progress"] + 0.3, 1.0)
            track["consecutive_failures"] = 0
        elif execution_status == "fail":
            track["consecutive_failures"] = track.get("consecutive_failures", 0) + 1
        elif execution_status == "partial":
            track["progress"] = min(track["progress"] + 0.1, 1.0)
        
        # Plan의 plan_progress와 plan_success_status 업데이트
        if "plan_progress" not in state:
            state["plan_progress"] = {}
        if "plan_success_status" not in state:
            state["plan_success_status"] = {}
        if "plan_attempts" not in state:
            state["plan_attempts"] = {}
        
        state["plan_progress"][track_id] = track["progress"]
        state["plan_success_status"][track_id] = execution_status
        state["plan_attempts"][track_id] = track["attempts"]
        
        # Signals를 트랙에 저장
        signals = track_parsing_json.get("signals", [])
        if signals:
            if "signals" not in track:
                track["signals"] = []
            track["signals"].extend(signals)
        
        # Artifacts를 트랙에 저장
        artifacts = track_parsing_json.get("artifacts", [])
        if artifacts:
            if "artifacts" not in track:
                track["artifacts"] = {}
            for artifact in artifacts:
                track["artifacts"][artifact.get("name", "unknown")] = artifact.get("path", "")
        
        # 트랙 상태 확인
        if track["progress"] >= 1.0:
            track["status"] = "completed"
            console.print(f"  Track {track_id} completed!", style="bold green")
        elif track.get("consecutive_failures", 0) >= 3:
            track["status"] = "failed"
            console.print(f"  Track {track_id} failed (3 consecutive failures)", style="bold red")
    
    # 활성 트랙만 유지
    active_tracks = {k: v for k, v in tracks.items() if v["status"] in ["in_progress", "pending"]}
    
    state["vulnerability_tracks"] = tracks
    
    console.print(f"=== Track Update Complete: {len(active_tracks)} active track(s) ===", style="bold green")
    
    return state

def human_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    # Multi-Track 모드인지 확인
    multi_instructions = state.get("multi_instructions", [])
    
    if multi_instructions and len(multi_instructions) > 1:
        # Multi-Track 모드: 여러 instruction 표시
        console.print("=== Human Translation (Multi-Track) ===", style='bold green')
        
        for inst_data in multi_instructions:
            track_id = inst_data["track_id"]
            instruction_result = inst_data["instruction_result"]
            
            console.print(f"\n--- Track: {track_id} ---", style="bold cyan")
            human_query = build_query(option="--human", Instruction=instruction_result)
            human_return = ctx.parsing.Human__translation_run(prompt_query=human_query)
            console.print(f"{human_return}", style='bold yellow')
    else:
        # 단일 instruction 모드
        human_query = build_query(option="--human", Instruction=state.get("instruction_result", ""))

        console.print("=== Human Translation ===", style='bold green')

        human_return = ctx.parsing.Human__translation_run(prompt_query=human_query)

        console.print(f"{human_return}", style='bold yellow')

    console.print("\nShould we proceed like this? ", style="blue")
    console.print("ex) yes, y || no, n ", style="blue", end="")

    return state

def parsing_node(state: State) -> State:
    """
    실행 결과를 자동으로 파싱하고 성공/실패 판단
    """
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Parsing Agent ===", style='bold magenta')
    
    # 실행 결과 가져오기
    execution_results = state.get("execution_results", {})
    execution_output = state.get("execution_output", "")
    multi_instructions = state.get("multi_instructions", [])
    
    if not execution_results and not execution_output:
        console.print("No execution results to parse.", style="yellow")
        return state
    
    # Multi-Track 모드인지 확인
    if execution_results and len(execution_results) > 1:
        # Multi-Track 모드: 각 트랙별로 파싱
        console.print(f"Multi-Track mode: {len(execution_results)} track(s) active", style="bold yellow")
        
        parsed_results = {}
        for track_id, result_output in execution_results.items():
            console.print(f"\n=== LLM_translation for {track_id} ===", style='bold green')
            # Parsing Agent에 필요한 정보만 필터링
            filtered_state = get_state_for_parsing(state)
            LLM_translation = ctx.parsing.LLM_translation_run(prompt_query=result_output, state=filtered_state)
            parsed_results[track_id] = LLM_translation
        
        state["multi_parsing_results"] = parsed_results
        # 첫 번째 결과를 기본값으로 설정
        if parsed_results:
            first_track = list(parsed_results.keys())[0]
            state["parsing_result"] = parsed_results[first_track]
    else:
        # 단일 instruction 모드
        result_to_parse = execution_output if execution_output else list(execution_results.values())[0] if execution_results else ""
        
        if not result_to_parse:
            console.print("No execution output to parse.", style="yellow")
            return state
        
        console.print("=== LLM_translation ===", style='bold green')
        # Parsing Agent에 필요한 정보만 필터링
        filtered_state = get_state_for_parsing(state)
        LLM_translation = ctx.parsing.LLM_translation_run(prompt_query=result_to_parse, state=filtered_state)
        state["parsing_result"] = LLM_translation
    
    # 파싱 결과에서 성공/실패 판단
    parsing_json = core.safe_json_loads(state.get("parsing_result", "{}"))
    
    # 성공 조건 확인
    signals = parsing_json.get("signals", [])
    errors = parsing_json.get("errors", [])
    summary = parsing_json.get("summary", "")
    
    # 실행 결과에서 직접 쉘 출력 확인 (parsing이 놓쳤을 수 있음)
    execution_output = state.get("execution_output", "")
    execution_results = state.get("execution_results", {})
    
    # 쉘 출력 직접 확인 (엄격한 검증)
    def is_shell_acquired_strict(text: str) -> bool:
        """쉘 획득 여부를 엄격하게 검증"""
        if not text:
            return False
        
        text_lower = text.lower()
        
        # 1. 쉘 프롬프트 확인 (가장 확실한 신호)
        shell_prompts = ["$ ", "# ", "> ", "bash:", "sh:", "zsh:", "csh:"]
        has_prompt = any(prompt in text for prompt in shell_prompts)
        
        # 2. 실제 명령어 실행 결과 패턴 확인
        # "id" 명령어의 전체 출력 패턴: "uid=0(root) gid=0(root) groups=0(root)"
        id_pattern = r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)"
        has_id_output = bool(re.search(id_pattern, text))
        
        # 3. "whoami" 명령어 결과 확인
        whoami_pattern = r"^(root|admin|user|www-data|nobody|daemon)\s*$"
        has_whoami = bool(re.search(whoami_pattern, text, re.MULTILINE))
        
        # 4. 쉘 환경 변수 확인
        env_vars = ["PATH=", "HOME=", "USER=", "SHELL="]
        has_env_vars = sum(1 for var in env_vars if var in text) >= 2  # 최소 2개 이상
        
        # 5. 실제 쉘 명령어 실행 결과 (ls -la 출력 패턴)
        ls_pattern = r"[d-][rwx-]{9}\s+\d+\s+\w+\s+\w+\s+\d+\s+[A-Za-z]{3}\s+\d+\s+[\d:]+\s+[^\s]+"
        has_ls_output = bool(re.search(ls_pattern, text))
        
        # 최소 2개 이상의 강한 신호가 있어야 쉘 획득으로 판단
        strong_signals = [
            has_prompt,  # 쉘 프롬프트
            has_id_output,  # id 명령어 출력
            (has_whoami and has_env_vars),  # whoami + 환경 변수
            (has_ls_output and has_env_vars),  # ls 출력 + 환경 변수
        ]
        
        # 또는 쉘 프롬프트가 있고 추가 신호가 하나라도 있으면
        if has_prompt and (has_id_output or has_whoami or has_ls_output or has_env_vars):
            return True
        
        # 또는 강한 신호가 2개 이상
        if sum(strong_signals) >= 2:
            return True
        
        return False
    
    has_shell_in_output = False
    if execution_output:
        has_shell_in_output = is_shell_acquired_strict(execution_output)
    if not has_shell_in_output:
        for result_text in execution_results.values():
            if is_shell_acquired_strict(result_text):
                has_shell_in_output = True
                break
    
    # FLAG 감지 확인 (최우선)
    # 중요: 코드 분석 결과가 아닌 실제 실행 결과에서만 플래그를 감지
    flag_signals = [s for s in signals if s.get("type") == "flag"]

    # 플래그 형식 정보 가져오기
    challenge_info = state.get("challenge", [])
    flag_format = challenge_info[0].get("flag format", "") if challenge_info else ""

    if flag_signals:
        # 실행 결과에서 플래그가 감지되었는지 확인
        # 코드 분석 도구(ghidra_decompile, objdump 등)의 결과에서는 플래그를 신뢰하지 않음
        execution_output = state.get("execution_output", "")
        execution_results = state.get("execution_results", {})
        
        # 플래그 형식 검증 함수
        def matches_flag_format(flag_value: str, flag_format: str) -> bool:
            """플래그가 지정된 형식과 일치하는지 확인"""
            if not flag_format or not flag_value:
                return True  # 형식 정보가 없으면 패스

            # flag_format: "csawctf{}", "flag{}", "HTB{}" 등
            import re

            # 형식에서 prefix 추출 (예: "csawctf{}" -> "csawctf{")
            if "{}" in flag_format or "{" in flag_format:
                prefix = flag_format.split("{")[0] + "{"
                suffix = "}"
            else:
                # 형식이 명확하지 않으면 패스
                return True

            # 플래그가 prefix{...}suffix 패턴인지 확인
            pattern = re.escape(prefix) + r".+" + re.escape(suffix)
            return bool(re.match(pattern, flag_value, re.IGNORECASE))

        # 실행 결과에서 플래그 패턴 확인
        def is_flag_in_execution_output(flag_value: str, output_text: str) -> bool:
            """실행 결과에서 플래그가 실제로 출력되었는지 확인"""
            if not flag_value or not output_text:
                return False

            # 1. 플래그 형식 검증 (가장 먼저)
            if flag_format and not matches_flag_format(flag_value, flag_format):
                console.print(f"⚠️  Flag format mismatch: Expected '{flag_format}', got '{flag_value[:50]}...'", style="yellow")
                return False

            # 플래그가 실행 결과에 직접 포함되어 있는지 확인
            # 코드 분석 결과의 하드코딩 문자열이 아닌 실제 출력인지 확인
            flag_lower = flag_value.lower()
            output_lower = output_text.lower()
            
            # 플래그가 실행 결과에 포함되어 있고, 코드 분석 컨텍스트가 아닌 경우
            if flag_value in output_text or flag_lower in output_lower:
                # 코드 분석 도구 출력 패턴 제외
                analysis_patterns = [
                    "decompiled_code",
                    "assembly_code",
                    "disassembly",
                    "std::string",
                    "char",
                    "wanted =",
                    "expected =",
                    "target =",
                    "correct =",
                    "if (",
                    "for (",
                    "void ",
                    "int main",
                    "def ",
                    "class ",
                    "const ",
                    "#include",
                    "//",  # C++ 주석
                    "/*",  # C 블록 주석
                    ".cpp",  # 소스 파일 경로
                    ".c:",
                    ".h:",
                    "→",  # Read 도구의 라인 번호 마커
                ]
                
                # 플래그 주변 컨텍스트 확인 (코드 분석 결과인지 판단)
                flag_index = output_lower.find(flag_lower)
                if flag_index >= 0:
                    # 플래그 앞뒤 200자 확인
                    start = max(0, flag_index - 200)
                    end = min(len(output_text), flag_index + len(flag_value) + 200)
                    context = output_text[start:end].lower()
                    
                    # 코드 분석 결과 패턴이 있으면 무시
                    if any(pattern in context for pattern in analysis_patterns):
                        console.print(f"⚠️  Flag pattern found in code analysis output (ignoring): {flag_value[:50]}...", style="yellow")
                        return False
                
                return True
            
            return False
        
        # 실행 결과에서 실제로 플래그가 출력되었는지 확인
        valid_flags = []
        for flag_signal in flag_signals:
            flag_value = flag_signal.get("value", "")
            if not flag_value:
                continue

            # execution_output에서 확인
            if execution_output and is_flag_in_execution_output(flag_value, execution_output):
                valid_flags.append(flag_value)
                continue

            # execution_results에서 확인 (각 트랙별 결과)
            found_in_results = False
            for track_id, result_text in execution_results.items():
                # 소스코드 읽기 명령어 제외
                if any(keyword in result_text.lower() for keyword in ["read", "cat ", "source code", "file contents", ".cpp", ".c:", ".h:", "→"]):
                    console.print(f"Skipping {track_id}: Contains source code or file read output", style="dim")
                    continue

                if is_flag_in_execution_output(flag_value, result_text):
                    valid_flags.append(flag_value)
                    found_in_results = True
                    break

            if not found_in_results:
                console.print(f"⚠️  Flag pattern found but not in execution output (ignoring): {flag_value[:50]}...", style="yellow")
                console.print("   This might be a hardcoded string in source code, not an actual flag.", style="dim")
        
        # 유효한 플래그가 있으면 처리
        if valid_flags:
            state["detected_flag"] = valid_flags[0]  # 첫 번째 flag 저장
            state["all_detected_flags"] = valid_flags  # 모든 flag 저장
            state["flag_detected"] = True
            console.print(f"🚩 FLAG DETECTED (from execution output): {valid_flags[0]}", style="bold green")
            console.print("Stopping workflow to generate PoC code", style="bold yellow")
            state["execution_status"] = "flag_detected"
            return state
        else:
            console.print("⚠️  Flag patterns found in analysis but not in execution output. Continuing workflow.", style="yellow")
    
    # 관리자 권한 획득 감지 확인 (Flag 다음 우선순위)
    privilege_signals = [s for s in signals if s.get("type") == "privilege"]
    if privilege_signals:
        # 관리자 권한이 획득됨 - state에 저장하고 플래그 설정
        privilege_evidences = [s.get("value", "") for s in privilege_signals if s.get("value")]
        if privilege_evidences:
            state["privilege_evidence"] = privilege_evidences[0]  # 첫 번째 증거 저장
            state["privilege_escalated"] = True
            console.print(f"PRIVILEGE ESCALATION DETECTED: {privilege_evidences[0]}", style="bold green")
            console.print("Stopping workflow to generate PoC code", style="bold yellow")
            state["execution_status"] = "privilege_escalated"
            return state
    
    # 성공/실패 판단 로직
    # proof 타입은 EIP 리다이렉션, 쉘 획득 등 익스플로잇 성공 신호
    has_success_signal = any(s.get("type") in ["leak", "offset", "proof", "oracle"] for s in signals)
    # EIP 리다이렉션은 명확한 성공 신호
    has_eip_redirection = any(s.get("type") == "proof" and ("eip" in s.get("name", "").lower() or "redirection" in s.get("name", "").lower()) for s in signals)
    # 쉘 획득도 명확한 성공 신호 (LLM이 parsing에서 감지한 경우)
    has_shell_acquired_signal = any(s.get("type") == "proof" and s.get("name") == "shell_acquired" for s in signals)
    # 쉘 획득도 명확한 성공 신호 (기존 로직)
    has_shell_acquired = any(s.get("type") == "proof" and ("shell" in s.get("name", "").lower() or "acquired" in s.get("name", "").lower()) for s in signals)
    has_errors = len(errors) > 0
    
    # execution_status는 이미 execution_node에서 설정되었을 수 있음
    current_status = state.get("execution_status", "")
    
    # EIP 리다이렉션이나 쉘 획득이 있으면 명확한 성공 (우선순위: EIP > Shell > 기타 성공 신호)
    if has_eip_redirection:
        state["execution_status"] = "success"
        state["instruction_retry_count"] = 0
        console.print("Execution successful - EIP redirection detected (exploit working!)", style="bold green")
    elif has_shell_acquired or has_shell_in_output:
        state["execution_status"] = "success"
        state["instruction_retry_count"] = 0
        console.print("Execution successful - Shell acquired (exploit working!)", style="bold green")
    elif has_success_signal and not has_errors:
        state["execution_status"] = "success"
        # 성공 시 재시도 횟수 리셋
        state["instruction_retry_count"] = 0
        console.print("Execution successful - useful signals found", style="bold green")
    elif has_errors or current_status == "fail":
        state["execution_status"] = "fail"
        console.print("Execution failed - errors detected", style="bold red")
    else:
        state["execution_status"] = "partial"
        console.print("Execution partial - some progress made", style="yellow")
    
    return state

def feedback_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Feedback Agent ===", style='bold magenta')
    
    feedback_query = build_query(option = "--feedback", Instruction = state["parsing_result"])

    console.print("=== Feedback Run ===", style='bold green')

    # Feedback Agent에 필요한 정보만 필터링
    filtered_state = get_state_for_feedback(state)
    feedback_return = ctx.feedback.feedback_run(prompt_query = feedback_query, state = filtered_state)

    state["feedback_result"] = feedback_return
    state["feedback_json"] = core.safe_json_loads(feedback_return)
    
    # Feedback 결과를 facts에 반영
    feedback_json = state["feedback_json"]
    if "promote_facts" in feedback_json:
        if "facts" not in state:
            state["facts"] = {}
        state["facts"].update(feedback_json["promote_facts"])
        console.print(f"  Promoted {len(feedback_json['promote_facts'])} fact(s) to stable knowledge", style="cyan")

    return state

def poc_node(state: State) -> State:
    """
    PoC 코드 생성 노드: Flag가 감지된 후 최종 PoC 스크립트 생성
    """
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== PoC Code Generation ===", style='bold magenta')

    import json
    
    # 감지된 flag 정보
    detected_flag = state.get("detected_flag", "")
    all_flags = state.get("all_detected_flags", [])
    
    # 관리자 권한 획득 정보
    privilege_escalated = state.get("privilege_escalated", False)
    privilege_evidence = state.get("privilege_evidence", "")
    
    # 실행 이력 및 발견된 사실들
    results = state.get("results", [])
    facts = state.get("facts", {})
    artifacts = state.get("artifacts", {})
    signals = state.get("signals", [])
    execution_results = state.get("execution_results", {})
    parsing_result = state.get("parsing_result", "")
    
    # PoC 생성을 위한 컨텍스트 구성
    poc_context = {
        "detected_flag": detected_flag,
        "all_flags": all_flags,
        "privilege_escalated": privilege_escalated,
        "privilege_evidence": privilege_evidence,
        "execution_history": results[-5:] if results else [],  # 최근 5개 결과
        "discovered_facts": facts,
        "artifacts": artifacts,
        "signals": signals,
        "execution_results": execution_results,
        "parsing_result": parsing_result,
        "challenge": state.get("challenge", []),
        "binary_path": state.get("binary_path", ""),
        "url": state.get("url", ""),
        "protections": state.get("protections", {}),
        "mitigations": state.get("mitigations", [])
    }
    
    # PoC 생성 이유 표시
    if privilege_escalated:
        console.print(f"🔐 Privilege escalation detected: {privilege_evidence}", style="cyan")
    elif detected_flag:
        console.print(f"Flag detected: {detected_flag}", style="cyan")
    
    # PoC 프롬프트 생성
    poc_query = json.dumps(poc_context, ensure_ascii=False, indent=2)
    
    console.print("=== Generating PoC Script ===", style='bold green')
    
    # PoC Agent 실행
    try:
        poc_result = ctx.exploit.poc_run(prompt_query="[CONTEXT]\n" + poc_query)
        
        # PoC 결과 파싱 및 저장
        poc_json = core.safe_json_loads(poc_result)
        state["poc_result"] = poc_result
        state["poc_json"] = poc_json
        
        # PoC 스크립트 저장
        if "poc_script" in poc_json:
            poc_script = poc_json["poc_script"]
            script_lang = poc_json.get("script_language", "python")
            script_ext = {
                "python": ".py",
                "bash": ".sh",
                "c": ".c",
                "other": ".txt"
            }.get(script_lang, ".py")
            
            script_path = f"./artifacts/poc{script_ext}"
            os.makedirs("./artifacts", exist_ok=True)
            with open(script_path, "w") as f:
                f.write(poc_script)
            
            state["poc_script_path"] = script_path
            console.print(f"PoC script saved to: {script_path}", style="bold green")
        
        console.print("=== PoC Generation Complete ===", style="bold green")
        console.print(f"Technique: {poc_json.get('technique', 'Unknown')}", style="cyan")
        console.print(f"Flag: {poc_json.get('flag', detected_flag)}", style="cyan")
        
    except Exception as e:
        console.print(f"Error generating PoC: {e}", style="bold red")
        state["poc_result"] = f"Error: {str(e)}"
        state["poc_json"] = {}
    
    return state

def exploit_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Exploit Agent ===", style='bold magenta')

    import json
    
    # JSON 직렬화 가능한 state 생성 (직렬화 불가 객체 제거)
    state_for_json = core.clean_state_for_json(state)
    
    plan = state.get("plan", {})
    
    exploit_query = build_query(
        option = "--exploit", 
        state = json.dumps(state_for_json, ensure_ascii=False, indent=2), 
        plan = json.dumps(plan, ensure_ascii=False, indent=2) if isinstance(plan, dict) else plan
    )
    console.print("=== Exploit Run ===", style='bold green')

    exploit_return = ctx.exploit.exploit_run(prompt_query = exploit_query)
    
    # Exploit 결과 저장
    state["exploit_result"] = exploit_return
    
    # 결과 출력
    console.print("\n=== Exploit Result ===", style='bold green')
    console.print(exploit_return, style='cyan')
    
    # PoC 코드 생성
    console.print("\n=== Generating PoC Code ===", style='bold magenta')
    
    import os
    # PoC 생성을 위한 컨텍스트 구성
    poc_context = {
        "exploit_result": exploit_return,
        "execution_history": state.get("results", [])[-5:] if state.get("results") else [],
        "discovered_facts": state.get("facts", {}),
        "artifacts": state.get("artifacts", {}),
        "signals": state.get("signals", []),
        "execution_results": state.get("execution_results", {}),
        "parsing_result": state.get("parsing_result", ""),
        "challenge": state.get("challenge", []),
        "binary_path": state.get("binary_path", ""),
        "url": state.get("url", ""),
        "protections": state.get("protections", {}),
        "mitigations": state.get("mitigations", []),
        "plan": plan
    }
    
    poc_query = json.dumps(poc_context, ensure_ascii=False, indent=2)
    
    try:
        poc_result = ctx.exploit.poc_run(prompt_query="[CONTEXT]\n" + poc_query)
        
        # PoC 결과 파싱 및 저장
        poc_json = core.safe_json_loads(poc_result)
        state["poc_result"] = poc_result
        state["poc_json"] = poc_json
        
        # PoC 스크립트 저장
        poc_script = None
        script_lang = "python"
        
        # JSON에서 PoC 스크립트 추출 시도
        if isinstance(poc_json, dict):
            poc_script = poc_json.get("poc_script") or poc_json.get("script_py")
            script_lang = poc_json.get("script_language") or poc_json.get("language", "python")
        else:
            # JSON 파싱 실패 시 원본 텍스트에서 코드 블록 추출
            import re
            # Python 코드 블록 찾기
            python_match = re.search(r'```(?:python|py)?\n(.*?)```', poc_result, re.DOTALL)
            if not python_match:
                # 일반 코드 블록 찾기
                python_match = re.search(r'```\n(.*?)```', poc_result, re.DOTALL)
            if python_match:
                poc_script = python_match.group(1).strip()
                script_lang = "python"
        
        if poc_script:
            script_lang = str(script_lang).lower()
            script_ext = {
                "python": ".py",
                "bash": ".sh",
                "c": ".c",
                "other": ".txt"
            }.get(script_lang, ".py")
            
            script_path = f"./artifacts/poc{script_ext}"
            os.makedirs("./artifacts", exist_ok=True)
            with open(script_path, "w", encoding='utf-8') as f:
                f.write(poc_script)
            
            state["poc_script_path"] = script_path
            console.print(f"PoC script saved to: {script_path}", style="bold green")
        else:
            console.print("Warning: PoC script not found in response. Saving raw result.", style="yellow")
            # 원본 결과를 파일로 저장
            script_path = "./artifacts/poc_result.txt"
            os.makedirs("./artifacts", exist_ok=True)
            with open(script_path, "w", encoding='utf-8') as f:
                f.write(poc_result)
            state["poc_script_path"] = script_path
            console.print(f"Raw PoC result saved to: {script_path}", style="cyan")
        
        console.print("\n=== PoC Generation Complete ===", style='bold green')
        if isinstance(poc_json, dict) and "technique" in poc_json:
            console.print(f"Technique: {poc_json.get('technique', 'Unknown')}", style="cyan")
        
    except Exception as e:
        console.print(f"Error generating PoC: {e}", style="bold red")
        state["poc_result"] = f"Error: {str(e)}"
        state["poc_json"] = {}
    
    console.print("\n=== Exploit & PoC Generation Complete ===", style='bold green')

    return state

def approval_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("How would you like to proceed?", style="blue")
    console.print("1) continue - Proceed with feedback", style="yellow")
    console.print("2) restart - Start from the beginning", style="yellow")
    console.print("3) end - Exit the program", style="yellow")
    console.print("Enter your choice (1/2/3 or continue/restart/end): ", style="blue", end="")

    select = input().strip().lower()

    if select in ["1", "continue", "c", "yes", "y"]:
        state["approval_choice"] = "continue"
        state["user_approval"] = True
    elif select in ["2", "restart", "r", "no", "n"]:
        state["approval_choice"] = "restart"
        state["user_approval"] = False
    elif select in ["3", "end", "e", "quit", "q"]:
        state["approval_choice"] = "end"
        state["user_approval"] = False
    else:
        console.print("Invalid choice. Defaulting to continue.", style="yellow")
        state["approval_choice"] = "continue"
        state["user_approval"] = True

    return state

def help_node(state: State) -> State:
    has_cot_result = bool(state.get("cot_result"))
    
    if not has_cot_result:
        console.print("=== Available Commands (Initial) ===", style='bold yellow')
        console.print("--help : Display the available commands.", style="bold yellow")
        console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
        console.print("--ghidra : Generate a plan based on decompiled and disassembled results.", style="bold yellow")
        console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
        console.print("--quit : Exit the program.", style="bold yellow")
    else:
        console.print("=== Available Commands (After Initial Setup) ===", style='bold yellow')
        console.print("--help : Display the available commands.", style="bold yellow")
        console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
        console.print("--continue : Continue using LLM with the latest feedback and proceed to the next step.", style="bold yellow")
        console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")
        console.print("--quit : Exit the program.", style="bold yellow")
    
    console.print("")  
    
    return state

def option_input_node(state: State) -> State:
    # Workflow step count 추적 (recursion_limit 체크용)
    workflow_step_count = state.get("workflow_step_count", 0)
    workflow_step_count += 1
    state["workflow_step_count"] = workflow_step_count
    
    # Recursion limit 체크 (50에 가까워지면 경고)
    RECURSION_LIMIT = 50
    if workflow_step_count >= RECURSION_LIMIT - 5:
        console.print(f"Approaching recursion limit: {workflow_step_count}/{RECURSION_LIMIT} steps", style="yellow")
        if workflow_step_count >= RECURSION_LIMIT:
            console.print(f"Recursion limit ({RECURSION_LIMIT}) reached. Please choose an option.", style="bold yellow")
            console.print("  Consider using --continue to reset or --quit to exit.", style="cyan")
    
    console.print("Please choose which option you want to choose.", style="blue")
    option = input("> ").strip()
    state["option"] = option
    
    # --continue 옵션 선택 시 반복 횟수 및 step count 리셋
    if option == "--continue":
        state["iteration_count"] = 0
        state["workflow_step_count"] = 0
        console.print("Iteration count and workflow step count reset. Starting fresh cycle.", style="bold green")
    
    return state
