from typing import Dict, Any
import os
import re
from rich.console import Console

try:
    from langgraph.state import PlanningState as State, get_state_for_cot, get_state_for_cal, get_state_for_instruction, get_state_for_parsing, get_state_for_feedback, get_state_for_detect, is_shell_acquired, is_privilege_escalated
except ImportError:
    from state import PlanningState as State, get_state_for_cot, get_state_for_cal, get_state_for_instruction, get_state_for_parsing, get_state_for_feedback, get_state_for_detect, is_shell_acquired, is_privilege_escalated

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
    # --discuss 옵션은 항상 새로운 입력을 받아야 함
    if option == "--discuss":
        console.print("Ask questions or describe your intended approach.", style="blue")
        planning_discuss = core.multi_line_input()
        state["user_input"] = planning_discuss
    elif not state.get("user_input") and not state.get("binary_path"):
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
    
    # available_tools 가져오기 (tool_selection_node에서 설정됨)
    available_tools = state.get("available_tools", [])

    if option == "--file" or option == "--ghidra":
        user_input = state.get("user_input", "") or state.get("binary_path", "")
        # 초기 실행이면 planning_context 없음, 반복 실행이면 포함
        if tracks or facts or artifacts:
            CoT_query = build_query(option = option, code = user_input, state = state, planning_context = planning_context, available_tools = available_tools)
        else:
            CoT_query = build_query(option = option, code = user_input, state = state, available_tools = available_tools)

    elif option == "--discuss" or option == "--continue":
        user_input = state.get("user_input", "")
        CoT_query = build_query(option = option, code = user_input, state = state, plan = state.get("plan", {}), planning_context = planning_context, available_tools = available_tools)

    elif option == "--auto":
        # Auto 모드: 자동으로 분석 시작 (--file과 유사하게 처리)
        user_input = state.get("user_input", "") or state.get("binary_path", "")
        if tracks or facts or artifacts:
            CoT_query = build_query(option = "--file", code = user_input, state = state, planning_context = planning_context, available_tools = available_tools)
        else:
            CoT_query = build_query(option = "--file", code = user_input, state = state, available_tools = available_tools)

    else:
        # 기본값: --continue로 처리
        user_input = state.get("user_input", "")
        CoT_query = build_query(option = "--continue", code = user_input, state = state, plan = state.get("plan", {}), planning_context = planning_context, available_tools = available_tools)
    
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

    # available_tools 가져오기
    available_tools = state.get("available_tools", [])

    Cal_query = build_query(option = "--Cal", state = state, CoT = state["cot_result"], available_tools = available_tools)

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
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Instruction Agent ===", style='bold magenta')

    # available_tools 가져오기
    available_tools = state.get("available_tools", [])

    instruction_query = build_query(
        option = "--instruction",
        CoT = state["cot_json"],
        Cal = state["cal_json"],
        available_tools = available_tools,
        state = state
    )

    console.print("=== Instruction Run ===", style='bold green')

    # Instruction Agent에 필요한 정보만 필터링
    filtered_state = get_state_for_instruction(state)
    instruction_return = ctx.instruction.run_instruction(prompt_query = instruction_query, state = filtered_state)

    state["instruction_result"] = instruction_return
    state["instruction_json"] = core.safe_json_loads(instruction_return)

    return state


def tool_selection_node(state: State) -> State:
    """
    모든 도구를 로드하고 AVAILABLE_TOOLS 목록을 state에 저장.
    실제 도구 선택은 LLM이 CoT → Cal → Instruction 단계에서 수행.
    """
    from datetime import datetime
    from tool import create_pwnable_tools, create_reversing_tools, create_web_tools

    console.print("=== Tool Loading Node ===", style='bold magenta')

    binary_path = state.get("binary_path", "")
    challenge = state.get("challenge", [])
    url = state.get("url", "")

    # 모든 도구 카테고리 로드
    all_tools = {}
    all_tool_names = []

    # Pwnable tools
    try:
        pwn_tools = create_pwnable_tools(binary_path=binary_path if binary_path else None)
        for tool in pwn_tools:
            all_tools[tool.name] = {"tool": tool, "category": "pwnable"}
            all_tool_names.append(tool.name)
        console.print(f"  Loaded {len(pwn_tools)} pwnable tools", style="cyan")
    except Exception as e:
        console.print(f"  Failed to load pwnable tools: {e}", style="yellow")

    # Web tools
    try:
        web_tools = create_web_tools(url=url if url else None)
        for tool in web_tools:
            all_tools[tool.name] = {"tool": tool, "category": "web"}
            all_tool_names.append(tool.name)
        console.print(f"  Loaded {len(web_tools)} web tools", style="cyan")
    except Exception as e:
        console.print(f"  Failed to load web tools: {e}", style="yellow")

    # Reversing tools
    try:
        rev_tools = create_reversing_tools(binary_path=binary_path if binary_path else None, challenge_info=challenge)
        for tool in rev_tools:
            all_tools[tool.name] = {"tool": tool, "category": "reversing"}
            all_tool_names.append(tool.name)
        console.print(f"  Loaded {len(rev_tools)} reversing tools", style="cyan")
    except Exception as e:
        console.print(f"  Failed to load reversing tools: {e}", style="yellow")

    # State에 저장
    state["all_tools"] = all_tools  # {tool_name: {"tool": tool_obj, "category": str}}
    state["available_tools"] = all_tool_names  # ["checksec", "gdb_run", ...]

    # 도구 설명 생성 (LLM에게 전달할 용도)
    tool_descriptions = []
    for name, info in all_tools.items():
        tool = info["tool"]
        desc = getattr(tool, "description", "No description")
        # 설명이 너무 길면 자르기
        if len(desc) > 100:
            desc = desc[:100] + "..."
        tool_descriptions.append(f"- {name} [{info['category']}]: {desc}")

    state["tool_descriptions"] = "\n".join(tool_descriptions)

    console.print(f"\n=== Tool Loading Complete: {len(all_tools)} tools available ===", style="bold green")
    console.print(f"  Tools: {', '.join(all_tool_names[:10])}{'...' if len(all_tool_names) > 10 else ''}", style="dim")

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
    cot_json = state.get("cot_json", {})
    cal_json = state.get("cal_json", {})

    # tool_selection_node에서 설정한 available_tools 가져오기
    global_available_tools = state.get("available_tools", [])

    # ===== Fallback: 서브그래프 state 격리 문제 해결 =====
    # available_tools가 비어있으면 직접 로드
    if not global_available_tools:
        console.print("  [FALLBACK] available_tools is empty, loading tools directly...", style="yellow")
        try:
            from tool import create_pwnable_tools, create_reversing_tools, create_web_tools

            binary_path = state.get("binary_path", "")
            challenge_info = state.get("challenge", [])
            url = state.get("url", "")

            # binary_path fallback
            if not binary_path and challenge_info:
                binary_path = challenge_info[0].get("binary_path", "")

            all_tools = {}

            # Pwnable tools 로드
            try:
                pwn_tools = create_pwnable_tools(binary_path=binary_path if binary_path else None)
                for tool in pwn_tools:
                    all_tools[tool.name] = {"tool": tool, "category": "pwnable"}
            except Exception as e:
                console.print(f"    Failed to load pwnable tools: {e}", style="dim")

            # Web tools 로드
            try:
                web_tools = create_web_tools(url=url if url else None)
                for tool in web_tools:
                    all_tools[tool.name] = {"tool": tool, "category": "web"}
            except Exception as e:
                console.print(f"    Failed to load web tools: {e}", style="dim")

            # Reversing tools 로드
            try:
                rev_tools = create_reversing_tools(binary_path=binary_path if binary_path else None, challenge_info=challenge_info)
                for tool in rev_tools:
                    all_tools[tool.name] = {"tool": tool, "category": "reversing"}
            except Exception as e:
                console.print(f"    Failed to load reversing tools: {e}", style="dim")

            global_available_tools = list(all_tools.keys())
            state["available_tools"] = global_available_tools
            state["all_tools"] = all_tools

            console.print(f"  [FALLBACK] Loaded {len(global_available_tools)} tools: {global_available_tools[:5]}...", style="green")
        except Exception as e:
            console.print(f"  [FALLBACK] Failed to load tools: {e}", style="bold red")
    # ===== End Fallback =====
    
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

        # global available_tools 사용 (tool_selection_node에서 설정됨)
        available_tools = global_available_tools

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
                state=state,  # state 전달 (command_cache, failed_commands 포함)
                available_tools=available_tools,
                fallback_mode="alternative"
            )
        elif consecutive_failures >= 2:
            # 2번 연속 실패: 단순한 접근으로 전환
            console.print(f"  {track_id} has failed {consecutive_failures} times. Using simpler approach.", style="yellow")
            instruction_query = build_query(
                option="--instruction_fallback",
                CoT={"candidates": [cot_candidate]},
                Cal={"results": [candidate]},
                state=state,  # state 전달 (command_cache, failed_commands 포함)
                available_tools=available_tools,
                fallback_mode="simple"
            )
        else:
            # 정상 실행
            instruction_query = build_query(
                option="--instruction",
                CoT={"candidates": [cot_candidate]},  # 해당 candidate만
                Cal={"results": [candidate]},  # 해당 result만
                state=state,  # state 전달 (command_cache, failed_commands 포함)
                available_tools=available_tools  # 사용 가능한 도구 목록
            )

        # Instruction Agent에 필요한 정보만 필터링
        filtered_state = get_state_for_instruction(state)
        # 트랙 정보 + 도구 정보 추가
        filtered_state["current_track"] = track_id
        filtered_state["current_track_info"] = track
        filtered_state["available_tools"] = available_tools
        filtered_state["fallback_mode"] = "alternative" if consecutive_failures >= 3 else "simple" if consecutive_failures >= 2 else "normal"

        instruction_return = ctx.instruction.run_instruction(
            prompt_query=instruction_query,
            state=filtered_state
        )

        instruction_json = core.safe_json_loads(instruction_return)

        # 디버그: instruction_json 내용 확인
        steps = instruction_json.get("steps", [])
        if not steps:
            console.print(f"    [DEBUG] {track_id}: No steps in instruction_json!", style="bold red")
            console.print(f"    [DEBUG] instruction_json keys: {list(instruction_json.keys())}", style="dim")

            # MISSING_TOOL 에러 처리: alternative 명령어를 step으로 변환
            if instruction_json.get("error") == "MISSING_TOOL":
                missing_tools = instruction_json.get("missing", [])
                alternative = instruction_json.get("alternative", "")
                console.print(f"    [RECOVERY] MISSING_TOOL: {missing_tools}", style="yellow")

                if alternative:
                    console.print(f"    [RECOVERY] Using alternative command: {alternative[:80]}...", style="cyan")
                    # alternative 명령어를 step으로 변환
                    instruction_json = {
                        "selected_candidate_idx": 0,
                        "what_to_find": f"Execute alternative command (missing: {', '.join(missing_tools)})",
                        "use_tools": ["shell"],
                        "steps": [
                            {
                                "name": f"alternative_for_{missing_tools[0] if missing_tools else 'unknown'}",
                                "tool": "shell",
                                "cmd": alternative,
                                "success": "output",
                                "artifact": "-"
                            }
                        ]
                    }
                    steps = instruction_json.get("steps", [])
                    console.print(f"    [RECOVERY] Converted to {len(steps)} step(s)", style="green")
            elif "error" in instruction_json:
                console.print(f"    [DEBUG] Error: {instruction_json.get('error')}", style="red")
                # Raw 응답 일부 출력 (처음 300자)
                console.print(f"    [DEBUG] Raw response (first 300 chars): {instruction_return[:300] if instruction_return else 'EMPTY'}", style="dim")
        else:
            console.print(f"    [DEBUG] {track_id}: {len(steps)} step(s) found", style="dim")

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
    실패한 명령어는 캐시에 저장하여 반복 실행 방지
    """
    import subprocess
    from datetime import datetime
    import hashlib

    # 명령어 중복 체크 유틸리티 import
    try:
        from utility.command_cache import check_command_before_execution, add_command_to_cache
        has_command_cache = True
    except ImportError:
        has_command_cache = False

    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Execution Node ===", style='bold magenta')

    multi_instructions = state.get("multi_instructions", [])

    if not multi_instructions:
        console.print("No instructions to execute.", style="yellow")
        return state

    # Challenge 디렉토리 결정 (binary_path 또는 challenge 정보에서)
    binary_path = state.get("binary_path", "")
    challenge_info = state.get("challenge", [])

    # challenge_dir 결정
    challenge_dir = None
    if binary_path and os.path.exists(binary_path):
        challenge_dir = os.path.dirname(os.path.abspath(binary_path))
        binary_name = os.path.basename(binary_path)
        console.print(f"  Challenge directory: {challenge_dir}", style="dim")
    elif challenge_info and len(challenge_info) > 0:
        # challenge_info에서 binary_path 가져오기
        ch_binary = challenge_info[0].get("binary_path", "")
        if ch_binary and os.path.exists(ch_binary):
            challenge_dir = os.path.dirname(os.path.abspath(ch_binary))
            binary_name = os.path.basename(ch_binary)
            console.print(f"  Challenge directory: {challenge_dir}", style="dim")

    # 명령어 캐시 초기화 (없으면 생성)
    if "command_cache" not in state:
        state["command_cache"] = {}  # {command_hash: {cmd, result, success, timestamp}}
    if "failed_commands" not in state:
        state["failed_commands"] = {}  # {command_hash: {cmd, error, timestamp, attempt_count}}
    if "seen_cmd_hashes" not in state:
        state["seen_cmd_hashes"] = []  # 실행한 모든 명령어 해시 목록

    command_cache = state["command_cache"]
    failed_commands = state["failed_commands"]
    seen_cmd_hashes = state["seen_cmd_hashes"]

    def normalize_command(cmd: str) -> str:
        if not cmd:
            return ""
        # 공백 정규화
        normalized = " ".join(cmd.split())
        # 따옴표 정규화
        normalized = normalized.replace("'", '"')
        return normalized.strip()
    
    def get_command_hash(cmd: str) -> str:
        normalized = normalize_command(cmd)
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()
    
    execution_results = {}
    all_outputs = []
    all_track_outputs = {}  # 각 트랙의 실행된 명령어 리스트 저장 (중복 방지용)
    track_statuses = {}  # 각 트랙별 실행 상태 (success, fail, partial, shell_acquired)

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
            
            # 명령어 캐시 확인
            cmd_hash = get_command_hash(cmd)
            
            # 실패한 명령어 확인
            if cmd_hash in failed_commands:
                failed_info = failed_commands[cmd_hash]
                attempt_count = failed_info.get("attempt_count", 0)
                
                console.print(f"  ⚠️  Skipping previously failed command: {name}", style="yellow")
                console.print(f"  Command: {cmd}", style="dim")
                console.print(f"  Previous error: {failed_info.get('error', 'Unknown error')[:100]}...", style="dim")
                console.print(f"  Failed {attempt_count} time(s) before", style="dim")
                
                # 실패한 명령어의 캐시된 결과 사용
                track_output.append({
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": f"Previously failed command (attempted {attempt_count} times): {failed_info.get('error', 'Unknown error')}",
                    "cached": True,
                    "timestamp": datetime.now().isoformat()
                })
                continue
            
            # 성공한 명령어 캐시 확인 (성공한 명령어도 재실행 방지)
            if cmd_hash in command_cache:
                cached_result = command_cache[cmd_hash]
                if cached_result.get("success", False):
                    console.print(f"  ✓ Using cached successful result for: {name}", style="green")
                    track_output.append({
                        "name": name,
                        "cmd": cmd,
                        "success": True,
                        "stdout": cached_result.get("result", ""),
                        "stderr": "",
                        "returncode": 0,
                        "cached": True,
                        "timestamp": datetime.now().isoformat()
                    })
                    continue
            
            console.print(f"  Executing: {name}", style="cyan")
            console.print(f"  Command: {cmd}", style="dim")

            # 강화된 중복 체크 (무한 루프 방지)
            if has_command_cache:
                should_exec, reason, cached = check_command_before_execution(cmd, state)
                if not should_exec:
                    console.print(f"  [SKIP] {reason}", style="yellow")
                    if cached:
                        track_output.append({
                            "name": name,
                            "cmd": cmd,
                            "success": cached.get("ok", False),
                            "stdout": cached.get("stdout", ""),
                            "stderr": cached.get("stderr", ""),
                            "cached": True,
                            "skip_reason": reason,
                            "timestamp": datetime.now().isoformat()
                        })
                    continue

            # seen_cmd_hashes에 추가 (중복 방지를 위해)
            if cmd_hash not in seen_cmd_hashes:
                seen_cmd_hashes.append(cmd_hash)
            
            # 도구 호출인지 확인 - all_tools에서 가져오기
            all_tools = state.get("all_tools", {})  # {tool_name: {"tool": tool_obj, "category": str}}
            available_tool_names = state.get("available_tools", [])

            # ===== Fallback: 서브그래프 state 격리 문제 해결 =====
            # LangGraph 서브그래프가 parent state를 완전히 공유하지 않는 경우를 대비
            if not all_tools:
                console.print("    [FALLBACK] all_tools is empty, loading tools directly...", style="yellow")
                try:
                    from tool import create_pwnable_tools, create_reversing_tools, create_web_tools

                    # binary_path 결정
                    _binary = binary_path
                    if not _binary and challenge_info:
                        _binary = challenge_info[0].get("binary_path", "")

                    # URL 결정 (web tools용)
                    _url = state.get("url", "")

                    all_tools = {}

                    # Pwnable tools 로드
                    try:
                        pwn_tools = create_pwnable_tools(binary_path=_binary if _binary else None)
                        for tool in pwn_tools:
                            all_tools[tool.name] = {"tool": tool, "category": "pwnable"}
                        console.print(f"      Loaded {len(pwn_tools)} pwnable tools", style="dim")
                    except Exception as e:
                        console.print(f"      Failed to load pwnable tools: {e}", style="dim")

                    # Web tools 로드
                    try:
                        web_tools = create_web_tools(url=_url if _url else None)
                        for tool in web_tools:
                            all_tools[tool.name] = {"tool": tool, "category": "web"}
                        console.print(f"      Loaded {len(web_tools)} web tools", style="dim")
                    except Exception as e:
                        console.print(f"      Failed to load web tools: {e}", style="dim")

                    # Reversing tools 로드
                    try:
                        rev_tools = create_reversing_tools(binary_path=_binary if _binary else None, challenge_info=challenge_info)
                        for tool in rev_tools:
                            all_tools[tool.name] = {"tool": tool, "category": "reversing"}
                        console.print(f"      Loaded {len(rev_tools)} reversing tools", style="dim")
                    except Exception as e:
                        console.print(f"      Failed to load reversing tools: {e}", style="dim")

                    # State에 저장 (다음 실행을 위해)
                    state["all_tools"] = all_tools
                    available_tool_names = list(all_tools.keys())
                    state["available_tools"] = available_tool_names

                    console.print(f"    [FALLBACK] Successfully loaded {len(all_tools)} tools", style="green")
                except Exception as e:
                    console.print(f"    [FALLBACK] Failed to load tools: {e}", style="bold red")
            # ===== End Fallback =====

            # toolset 구성: all_tools에서 실제 tool 객체들 추출
            toolset = [info["tool"] for info in all_tools.values()]
            tool_names = available_tool_names

            # 디버그: 도구 상태 확인
            if not toolset:
                console.print(f"    [DEBUG] WARNING: toolset is still empty after fallback!", style="bold red")
            else:
                console.print(f"    [DEBUG] Available tools ({len(toolset)}): {[t.name for t in toolset[:5]]}...", style="dim")

            # Shell 명령어 → 도구 매핑 (LLM이 shell 명령어를 사용해도 도구로 변환)
            # 실제 도구 이름: checksec_analysis, rop_gadget_search, objdump_disassemble,
            #                strings_extract, readelf_info, one_gadget_search, gdb_debug, ghidra_decompile
            shell_to_tool_mapping = {
                "ropper": "rop_gadget_search",
                "ROPgadget": "rop_gadget_search",
                "checksec": "checksec_analysis",
                "readelf": "readelf_info",
                "objdump": "objdump_disassemble",
                "gdb": "gdb_debug",
                "strings": "strings_extract",
                "nm ": "readelf_info",
                "ghidra": "ghidra_decompile",
                # LLM이 잘못된 이름을 사용할 때 실제 이름으로 매핑
                "list_symbols": "readelf_info",
                "ropgadget_search": "rop_gadget_search",
                "gdb_run": "gdb_debug",
                "decompile_function": "ghidra_decompile",
                "strings_analysis": "strings_extract",
                "disassemble": "objdump_disassemble",
            }

            # cmd가 도구 이름으로 시작하는지 확인
            is_tool_call = False
            tool_name = None
            tool_instance = None

            # 1단계: 명시적 도구 호출 확인 (예: "checksec_analysis(...)")
            cmd_stripped = cmd.strip()
            console.print(f"    [DEBUG] Checking cmd: '{cmd_stripped[:60]}...'", style="dim")
            for tool in toolset:
                if cmd_stripped.startswith(tool.name):
                    is_tool_call = True
                    tool_name = tool.name
                    tool_instance = tool
                    console.print(f"    [DEBUG] Matched tool: {tool.name}", style="green")
                    break

            if not is_tool_call:
                console.print(f"    [DEBUG] No direct tool match. Trying shell mapping...", style="dim")

            # 2단계: shell 명령어를 도구로 매핑 시도
            if not is_tool_call:
                for shell_cmd, mapped_tool_name in shell_to_tool_mapping.items():
                    if cmd.strip().startswith(shell_cmd):
                        # 매핑된 도구가 toolset에 있는지 확인
                        for tool in toolset:
                            if tool.name == mapped_tool_name:
                                is_tool_call = True
                                tool_name = tool.name
                                tool_instance = tool
                                console.print(f"    Auto-mapping shell command to tool: {shell_cmd} → {tool_name}", style="yellow")
                                break
                        break
            
            try:
                if is_tool_call and tool_instance:
                    # LangChain 도구 호출
                    console.print(f"    Detected tool call: {tool_name}", style="yellow")

                    # cmd에서 도구 인자 파싱 시도
                    tool_args = {}

                    # 방법 0: shell 명령어에서 인자 추출 (ropper --file /path --search "pattern")
                    # 실제 도구 이름 사용
                    shell_arg_patterns = {
                        "rop_gadget_search": {
                            r"--file\s+([^\s]+)": "binary_path",
                            r"--search\s+[\"']?([^\"'\s]+(?:\s+[^\"'\s]+)*)[\"']?": "search_pattern",
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                            r"search_pattern=['\"]?([^'\")\s]+)['\"]?": "search_pattern",
                        },
                        "checksec_analysis": {
                            r"checksec\s+(?:--file\s+)?([^\s]+)": "binary_path",
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                        },
                        "readelf_info": {
                            r"readelf\s+-[a-zA-Z]*\s+([^\s]+)": "binary_path",
                            r"nm\s+([^\s]+)": "binary_path",
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                            r"info_type=['\"]?([^'\")\s]+)['\"]?": "info_type",
                        },
                        "gdb_debug": {
                            r"gdb\s+(?:-q\s+)?([^\s]+)": "binary_path",
                            r"-ex\s+[\"']([^\"']+)[\"']": "command",
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                            r"command=['\"]?([^'\")\s]+)['\"]?": "command",
                        },
                        "ghidra_decompile": {
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                            r"function_name=['\"]?([^'\")\s]+)['\"]?": "function_name",
                            r"function_address=['\"]?([^'\")\s]+)['\"]?": "function_address",
                        },
                        "objdump_disassemble": {
                            r"objdump\s+(?:-[a-zA-Z]+\s+)?([^\s]+)": "binary_path",
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                            r"function_name=['\"]?([^'\")\s]+)['\"]?": "function_name",
                        },
                        "strings_extract": {
                            r"strings\s+([^\s]+)": "binary_path",
                            r"binary_path=['\"]?([^'\")\s]+)['\"]?": "binary_path",
                        },
                    }

                    if tool_name in shell_arg_patterns:
                        for pattern, param_name in shell_arg_patterns[tool_name].items():
                            match = re.search(pattern, cmd)
                            if match:
                                tool_args[param_name] = match.group(1)
                                console.print(f"      Extracted {param_name}: {match.group(1)}", style="dim")

                    # 파라미터 이름 정규화 매핑 (LLM이 잘못된 이름을 쓸 수 있음)
                    param_name_mapping = {
                        "file_path": "binary_path",
                        "file": "binary_path",
                        "path": "binary_path",
                        "bin_path": "binary_path",
                        "pattern": "search_pattern",
                        "addr": "address",
                        "func": "function_name",
                        "fn": "function_name",
                    }

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
                            # 파라미터 이름 정규화
                            normalized_key = param_name_mapping.get(key, key)
                            tool_args[normalized_key] = value
                            if normalized_key != key:
                                console.print(f"      Normalized param: {key} -> {normalized_key}", style="dim")
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
                        
                    except FileNotFoundError as e:
                        # 바이너리/파일을 찾을 수 없음 (영구적 오류)
                        stdout_text = f"Tool error (file not found): {str(e)}"
                        stderr_text = str(e)
                        returncode = 2  # 파일 없음
                        console.print(f"    ❌ File not found: {e}", style="red")

                        class ToolResult:
                            def __init__(self, stdout, stderr, returncode):
                                self.stdout = stdout.encode('utf-8') if isinstance(stdout, str) else stdout
                                self.stderr = stderr.encode('utf-8') if isinstance(stderr, str) else stderr
                                self.returncode = returncode

                        result = ToolResult(stdout_text, stderr_text, returncode)

                    except (ConnectionError, TimeoutError) as e:
                        # 네트워크/타임아웃 오류 (일시적 - 재시도 가능)
                        stdout_text = f"Tool error (network/timeout): {str(e)}"
                        stderr_text = str(e)
                        returncode = 3  # 네트워크 오류
                        console.print(f"    ⚠️ Network/timeout error (retryable): {e}", style="yellow")

                        class ToolResult:
                            def __init__(self, stdout, stderr, returncode):
                                self.stdout = stdout.encode('utf-8') if isinstance(stdout, str) else stdout
                                self.stderr = stderr.encode('utf-8') if isinstance(stderr, str) else stderr
                                self.returncode = returncode

                        result = ToolResult(stdout_text, stderr_text, returncode)

                    except ValueError as e:
                        # 잘못된 인자 (영구적 오류)
                        stdout_text = f"Tool error (invalid args): {str(e)}"
                        stderr_text = str(e)
                        returncode = 4  # 잘못된 인자
                        console.print(f"    ❌ Invalid arguments: {e}", style="red")

                        class ToolResult:
                            def __init__(self, stdout, stderr, returncode):
                                self.stdout = stdout.encode('utf-8') if isinstance(stdout, str) else stdout
                                self.stderr = stderr.encode('utf-8') if isinstance(stderr, str) else stderr
                                self.returncode = returncode

                        result = ToolResult(stdout_text, stderr_text, returncode)

                    except Exception as e:
                        # 기타 오류
                        error_type = type(e).__name__
                        stdout_text = f"Tool execution error ({error_type}): {str(e)}"
                        stderr_text = str(e)
                        returncode = 1
                        console.print(f"    ❌ Tool error ({error_type}): {e}", style="red")

                        class ToolResult:
                            def __init__(self, stdout, stderr, returncode):
                                self.stdout = stdout.encode('utf-8') if isinstance(stdout, str) else stdout
                                self.stderr = stderr.encode('utf-8') if isinstance(stderr, str) else stderr
                                self.returncode = returncode

                        result = ToolResult(stdout_text, stderr_text, returncode)
                else:
                    # 상대 경로를 절대 경로로 변환
                    exec_cmd = cmd
                    if challenge_dir:
                        # ./ 로 시작하는 바이너리 경로를 절대 경로로 변환
                        exec_cmd = re.sub(
                            r'(?<!["\'])\.\/([a-zA-Z0-9_\-\.]+)',
                            lambda m: os.path.join(challenge_dir, m.group(1)),
                            cmd
                        )
                        # 변환된 경우 로그 출력
                        if exec_cmd != cmd:
                            console.print(f"  Resolved path: {exec_cmd}", style="dim")

                    # 일반 커맨드 실행 (challenge_dir에서 실행)
                    result = subprocess.run(
                        exec_cmd,
                        shell=True,
                        capture_output=True,
                        text=False,  # 바이너리 모드로 먼저 받기
                        timeout=60,  # 60초 타임아웃
                        cwd=challenge_dir  # challenge 디렉토리에서 실행
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
                
                # 쉘 획득 여부 직접 확인 (state.py의 is_shell_acquired 함수 사용)
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
                
                # 명령어 실행 결과 캐시에 저장
                # 성공한 명령어는 캐시에 저장 (선택사항)
                if result.returncode == 0 or has_shell_output:
                    command_cache[cmd_hash] = {
                        "cmd": normalize_command(cmd),
                        "result": stdout_text[:1000],  # 결과 일부만 저장
                        "success": True,
                        "timestamp": datetime.now().isoformat()
                    }
                # 실패한 명령어는 failed_commands에 저장
                elif result.returncode != 0:
                    if cmd_hash not in failed_commands:
                        failed_commands[cmd_hash] = {
                            "cmd": normalize_command(cmd),
                            "error": stderr_text[:500] if stderr_text else f"Return code: {result.returncode}",
                            "timestamp": datetime.now().isoformat(),
                            "attempt_count": 1
                        }
                    else:
                        # 이미 실패한 적이 있으면 attempt_count 증가
                        failed_commands[cmd_hash]["attempt_count"] += 1
                        failed_commands[cmd_hash]["timestamp"] = datetime.now().isoformat()
                    
                    console.print(f"    ⚠️  Command failed - cached to prevent retry", style="yellow")
                
            except subprocess.TimeoutExpired:
                console.print(f"    {name} (timeout)", style="red")
                error_msg = "Timeout after 60 seconds"
                
                # 타임아웃도 실패한 명령어로 캐시
                cmd_hash = get_command_hash(cmd)
                if cmd_hash not in failed_commands:
                    failed_commands[cmd_hash] = {
                        "cmd": normalize_command(cmd),
                        "error": error_msg,
                        "timestamp": datetime.now().isoformat(),
                        "attempt_count": 1
                    }
                else:
                    failed_commands[cmd_hash]["attempt_count"] += 1
                    failed_commands[cmd_hash]["timestamp"] = datetime.now().isoformat()
                
                track_output.append({
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": error_msg,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                console.print(f"    {name} (error: {e})", style="red")
                error_msg = str(e)
                
                # 예외도 실패한 명령어로 캐시
                cmd_hash = get_command_hash(cmd)
                if cmd_hash not in failed_commands:
                    failed_commands[cmd_hash] = {
                        "cmd": normalize_command(cmd),
                        "error": error_msg[:500],
                        "timestamp": datetime.now().isoformat(),
                        "attempt_count": 1
                    }
                else:
                    failed_commands[cmd_hash]["attempt_count"] += 1
                    failed_commands[cmd_hash]["timestamp"] = datetime.now().isoformat()
                
                track_output.append({
                    "name": name,
                    "cmd": cmd,
                    "success": False,
                    "error": error_msg,
                    "timestamp": datetime.now().isoformat()
                })
        
        # 트랙별 결과 저장 및 쉘 획득 확인
        track_has_shell = any(step.get('shell_acquired', False) for step in track_output)
        track_has_success = any(step.get('success', False) for step in track_output)
        track_all_failed = all(not step.get('success', False) for step in track_output) if track_output else True

        # track_output을 all_track_outputs에 저장 (중복 방지용)
        all_track_outputs[track_id] = track_output

        execution_results[track_id] = "\n".join([
            f"=== {step['name']} ===\n"
            f"Command: {step['cmd']}\n"
            f"Return code: {step.get('returncode', 'N/A')}\n"
            f"Shell acquired: {step.get('shell_acquired', False)}\n"
            f"Stdout:\n{step.get('stdout', '')}\n"
            f"Stderr:\n{step.get('stderr', '')}\n"
            for step in track_output
        ])

        # 트랙별 상태 저장
        if track_has_shell:
            track_statuses[track_id] = "shell_acquired"
            console.print(f"  {track_id}: Shell acquired!", style="bold green")
        elif track_has_success:
            track_statuses[track_id] = "success"
        elif track_all_failed:
            track_statuses[track_id] = "fail"
        else:
            track_statuses[track_id] = "partial"

    # State 업데이트
    state["execution_results"] = execution_results
    state["execution_output"] = "\n".join(all_outputs) if all_outputs else ""
    state["command_cache"] = command_cache
    state["failed_commands"] = failed_commands
    state["seen_cmd_hashes"] = seen_cmd_hashes
    state["all_track_outputs"] = all_track_outputs  # 실행된 명령어 리스트 (중복 방지용)
    state["track_statuses"] = track_statuses  # 트랙별 상태 저장

    # 실행 상태 요약 출력
    if failed_commands:
        console.print(f"\n  ⚠️  Failed commands cached: {len(failed_commands)}", style="yellow")

    # 종합 execution_status 계산 (모든 트랙 고려)
    shell_count = sum(1 for s in track_statuses.values() if s == "shell_acquired")
    success_count = sum(1 for s in track_statuses.values() if s in ["success", "shell_acquired"])
    fail_count = sum(1 for s in track_statuses.values() if s == "fail")
    total_tracks = len(track_statuses)

    if shell_count > 0:
        state["execution_status"] = "success"  # 쉘 획득 = 성공
        console.print(f"  Overall: {shell_count}/{total_tracks} track(s) acquired shell", style="bold green")
    elif success_count > 0 and fail_count > 0:
        state["execution_status"] = "partial"  # 일부 성공, 일부 실패
        console.print(f"  Overall: {success_count}/{total_tracks} succeeded, {fail_count}/{total_tracks} failed", style="yellow")
    elif success_count > 0:
        state["execution_status"] = "success"
        console.print(f"  Overall: {success_count}/{total_tracks} track(s) succeeded", style="green")
    elif fail_count == total_tracks and total_tracks > 0:
        state["execution_status"] = "fail"
        console.print(f"  Overall: All {total_tracks} track(s) failed", style="red")
    else:
        state["execution_status"] = "partial"
    
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
        all_track_outputs = state.get("all_track_outputs", {})
        track_outputs_list = all_track_outputs.get(track_id, [])

        if execution_output or track_outputs_list:
            result_entry = {
                "timestamp": datetime.now().isoformat(),
                "track_id": track_id,
                "status": execution_status,
                "execution_output": execution_output,
                "parsing_result": track_parsing_json,
                "signals": track_parsing_json.get("signals", []),
                "artifacts": track_parsing_json.get("artifacts", []),
                "errors": track_parsing_json.get("errors", []),
                # 실행된 명령어 리스트 추가 (중복 방지용)
                "track_outputs": track_outputs_list
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

def parsing_node(state: State) -> State:
    """
    실행 결과를 자동으로 파싱하고 성공/실패 판단
    """
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Parsing Agent ===", style='bold magenta')

    # signals 초기화 (KeyError 방지)
    if "signals" not in state:
        state["signals"] = []

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
            # Rate limit은 _generate_with_retry에서 자동으로 처리됨
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
    # Multi-Track 모드인지 확인
    multi_parsing_results = state.get("multi_parsing_results", {})
    is_multi_track = len(multi_parsing_results) > 1
    
    if is_multi_track:
        # Multi-Track 모드: 모든 트랙의 signals 수집
        all_signals = []
        all_errors = []
        for track_id, track_parsing_result in multi_parsing_results.items():
            track_parsing_json = core.safe_json_loads(track_parsing_result)
            all_signals.extend(track_parsing_json.get("signals", []))
            all_errors.extend(track_parsing_json.get("errors", []))
        signals = all_signals
        errors = all_errors
        # 기본 parsing_json은 첫 번째 트랙 결과 사용 (하위 호환성)
        parsing_json = core.safe_json_loads(state.get("parsing_result", "{}"))
    else:
        # 단일 모드: 기존 로직
        parsing_json = core.safe_json_loads(state.get("parsing_result", "{}"))
        signals = parsing_json.get("signals", [])
        errors = parsing_json.get("errors", [])
    
    summary = parsing_json.get("summary", "")
    
    # 실행 결과에서 직접 쉘 출력 확인 (parsing이 놓쳤을 수 있음)
    # state.py의 is_shell_acquired 함수 사용
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
    
    # FLAG 감지 확인 (최우선)
    # 중요: 코드 분석 결과가 아닌 실제 실행 결과에서만 플래그를 감지
    flag_signals = [s for s in signals if s.get("type") == "flag"]

    # 플래그 형식 정보 가져오기
    challenge_info = state.get("challenge", [])
    challenge = challenge_info[0] if challenge_info else {}
    flag_format = challenge.get("flag format", "") if challenge_info else ""
    challenge_description = challenge.get("description", "").lower() if challenge else ""

    # Challenge description에서 입력값 관련 힌트 확인
    is_input_value_challenge = any(keyword in challenge_description for keyword in [
        "입력값", "입력", "input", "correct를 출력", "correct 출력", "올바른 입력", "올바른 값을 찾",
        "찾으세요", "입력값을 찾아", "입력값을 찾아서", "dh{} 포맷에 넣어", "포맷에 넣어",
        "검증하여", "문자열 입력", "정해진 방법", "인증해주세요"
    ])

    # Challenge description을 state에 저장 (없으면 user_input에서 가져오기)
    if not challenge_description:
        user_input = state.get("user_input", "").lower()
        is_input_value_challenge = any(keyword in user_input for keyword in [
            "입력값", "입력", "input", "correct를 출력", "correct 출력", "올바른 입력", "올바른 값을 찾",
            "찾으세요", "입력값을 찾아", "입력값을 찾아서", "dh{} 포맷에 넣어", "포맷에 넣어",
            "검증하여", "문자열 입력", "정해진 방법", "인증해주세요"
        ])

    if flag_signals:
        # 실행 결과에서 플래그가 감지되었는지 확인
        # 코드 분석 도구(ghidra_decompile, objdump 등)의 결과에서는 플래그를 신뢰하지 않음
        execution_output = state.get("execution_output", "")
        execution_results = state.get("execution_results", {})
        
        # 플래그 형식 검증 함수
        def matches_flag_format(flag_value: str, flag_format: str) -> bool:
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
        
        # 입력값인지 확인하는 함수 (challenge description 기반)
        def could_be_input_value(value: str, output_text: str) -> bool:
            if not value or not output_text:
                return False

            value_lower = value.lower()
            output_lower = output_text.lower()

            # 1. execution output에서 "correct" 또는 "정답" 키워드와 함께 발견
            if any(keyword in output_lower for keyword in ["correct", "정답", "success"]) and value in output_text:
                return True

            # 2. 명령어 라인에서 입력으로 사용된 경우 (echo, <<<, printf 등)
            # 예: echo "Apple_Banana" | ./binary
            if any(pattern in output_text for pattern in [
                f'echo "{value}"', f"echo '{value}'", f'echo {value}',
                f'<<< "{value}"', f"<<< '{value}'", f'<<< {value}',
                f'printf "{value}"', f"printf '{value}'"
            ]):
                return True

            # 3. "wrong" 또는 "fail"과 함께 발견 (반대 의미지만 입력값일 가능성)
            if any(word in output_lower for word in ["wrong", "fail", "error", "incorrect"]) and value in output_text:
                return True

            # 4. 실행 결과에서 직접 출력된 문자열 (코드 분석이 아닌)
            # 코드 분석 패턴 제외
            analysis_patterns = [
                "decompiled_code", "assembly_code", "disassembly", "std::string",
                "char", "wanted =", "expected =", "target =", "correct =", "if (",
                "for (", "void ", "int main", "def ", "class ", "const ", "#include",
                "→"  # Read 도구의 라인 번호 마커
            ]

            value_index = output_lower.find(value_lower)
            if value_index >= 0:
                # 주변 컨텍스트 확인
                start = max(0, value_index - 200)
                end = min(len(output_text), value_index + len(value) + 200)
                context = output_text[start:end].lower()

                # 코드 분석 패턴이 없으면 실제 출력일 가능성
                if not any(pattern in context for pattern in analysis_patterns):
                    return True

            return False

        # 실행 결과에서 플래그 패턴 확인
        def is_flag_in_execution_output(flag_value: str, output_text: str) -> bool:
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
        potential_input_values = []  # 플래그 형식은 아니지만 입력값일 가능성이 있는 값들
        
        for flag_signal in flag_signals:
            flag_value = flag_signal.get("value", "")
            if not flag_value:
                continue

            # 플래그 형식이 맞는지 확인
            format_matches = matches_flag_format(flag_value, flag_format) if flag_format else True
            
            # execution_output에서 확인
            found_in_output = False
            if execution_output:
                if is_flag_in_execution_output(flag_value, execution_output):
                    valid_flags.append(flag_value)
                    found_in_output = True
                    continue
                elif not format_matches and could_be_input_value(flag_value, execution_output):
                    # 플래그 형식은 아니지만 입력값일 가능성
                    potential_input_values.append(flag_value)
                    found_in_output = True

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
                elif not format_matches and could_be_input_value(flag_value, result_text):
                    potential_input_values.append(flag_value)
                    found_in_results = True
                    break

            if not found_in_results and not found_in_output:
                console.print(f"⚠️  Flag pattern found but not in execution output (ignoring): {flag_value[:50]}...", style="yellow")
                console.print("   This might be a hardcoded string in source code, not an actual flag.", style="dim")
        
        # 입력값 후보들을 플래그 형식으로 변환
        if potential_input_values and is_input_value_challenge and flag_format:
            console.print(f"💡 Found potential input values that need to be wrapped in flag format: {len(potential_input_values)}", style="cyan")
            
            # execution output에서 "correct" 키워드 확인
            has_correct_in_output = False
            if execution_output:
                has_correct_in_output = "correct" in execution_output.lower()
            
            for result_text in execution_results.values():
                if "correct" in result_text.lower():
                    has_correct_in_output = True
                    break
            
            if has_correct_in_output:
                console.print("  ✓ 'correct' keyword found in execution output - high confidence for input values", style="green")
            
            for input_value in potential_input_values:
                # 플래그 형식 추출 (예: "DH{}" -> "DH{" + input_value + "}")
                if "{}" in flag_format:
                    prefix = flag_format.split("{}")[0]
                    formatted_flag = f"{prefix}{{{input_value}}}"
                    console.print(f"  ✓ Converting input value to flag format: {formatted_flag}", style="bold green")
                    valid_flags.append(formatted_flag)
                elif "{" in flag_format:
                    # "DH{" 같은 형식
                    formatted_flag = flag_format + input_value + "}"
                    console.print(f"  ✓ Converting input value to flag format: {formatted_flag}", style="bold green")
                    valid_flags.append(formatted_flag)
                else:
                    # 형식이 명확하지 않으면 그냥 추가
                    console.print(f"  Using input value as-is (flag format unclear): {input_value}", style="yellow")
                    valid_flags.append(input_value)
        
        # 입력값 후보가 있지만 flag_format이 없는 경우도 처리
        elif potential_input_values and is_input_value_challenge:
            console.print(f"⚠️  Found potential input values but flag format is not specified: {potential_input_values}", style="yellow")
            console.print("   Adding as potential flags anyway.", style="dim")
            valid_flags.extend(potential_input_values)
        
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
    
    # 입력값 감지 추가 로직: LLM이 놓친 경우를 대비하여 직접 "correct" 키워드 검사
    if is_input_value_challenge and flag_format:
        console.print("💡 Input value challenge detected. Scanning for 'correct' output...", style="cyan")

        # execution output에서 "correct" 검사 (대소문자 무시)
        execution_output = state.get("execution_output", "")
        execution_results = state.get("execution_results", {})

        # "correct" 출력이 있는 명령어 찾기
        correct_found_in = []
        for track_id, result_text in execution_results.items():
            result_lower = result_text.lower()
            # "correct" 또는 "정답" 찾기 (코드 분석 결과는 제외)
            if ("correct" in result_lower or "정답" in result_lower) and "decompiled_code" not in result_lower:
                # 코드 분석이 아닌 실제 실행 결과인지 확인
                if not any(pattern in result_lower for pattern in ["std::string", "char ", "wanted =", "if (", "void "]):
                    correct_found_in.append((track_id, result_text))
                    console.print(f"  ✓ 'correct' output found in {track_id}", style="green")

        # "correct"가 발견되면 실행 결과에서 입력값 추출 시도 (flag_signals 유무와 관계없이)
        if correct_found_in:
            console.print("  Attempting to extract input value from execution output...", style="cyan")

            # 명령어에서 입력으로 사용된 값 찾기
            # 예: echo "Apple_Banana" | ./binary 또는 ./binary <<< "Apple_Banana"
            for track_id, result_text in correct_found_in:
                # 명령어 라인 찾기
                lines = result_text.split("\n")
                for i, line in enumerate(lines):
                    # "Command:" 라인 찾기
                    if "Command:" in line and i + 1 < len(lines):
                        cmd_line = lines[i + 1] if i + 1 < len(lines) else line

                        # echo "..." | ./binary 패턴
                        echo_pattern = r'echo\s+["\']([^"\']+)["\']'
                        match = re.search(echo_pattern, cmd_line)
                        if match:
                            input_value = match.group(1)
                            formatted_flag = f"{flag_format.replace('{}', '')}{{{input_value}}}"
                            console.print(f"  ✓ Extracted input value from echo command: {input_value}", style="bold green")
                            console.print(f"  ✓ Formatted flag: {formatted_flag}", style="bold green")

                            state["detected_flag"] = formatted_flag
                            state["all_detected_flags"] = [formatted_flag]
                            state["flag_detected"] = True
                            console.print(f"🚩 FLAG DETECTED (from correct output): {formatted_flag}", style="bold green")
                            console.print("Stopping workflow to generate PoC code", style="bold yellow")
                            state["execution_status"] = "flag_detected"
                            return state

                        # printf/cat/here-string 패턴도 추가 가능
                        heredoc_pattern = r'<<<\s*["\']([^"\']+)["\']'
                        match = re.search(heredoc_pattern, cmd_line)
                        if match:
                            input_value = match.group(1)
                            formatted_flag = f"{flag_format.replace('{}', '')}{{{input_value}}}"
                            console.print(f"  ✓ Extracted input value from here-string: {input_value}", style="bold green")
                            console.print(f"  ✓ Formatted flag: {formatted_flag}", style="bold green")

                            state["detected_flag"] = formatted_flag
                            state["all_detected_flags"] = [formatted_flag]
                            state["flag_detected"] = True
                            console.print(f"🚩 FLAG DETECTED (from correct output): {formatted_flag}", style="bold green")
                            console.print("Stopping workflow to generate PoC code", style="bold yellow")
                            state["execution_status"] = "flag_detected"
                            return state

    # 관리자 권한 획득 감지 확인 (Flag 다음 우선순위)
    # 1. LLM 파싱 결과에서 privilege signal 확인
    privilege_signals = [s for s in signals if s.get("type") == "privilege"]
    if privilege_signals:
        privilege_evidences = [s.get("value", "") for s in privilege_signals if s.get("value")]
        if privilege_evidences:
            state["privilege_evidence"] = privilege_evidences[0]
            state["privilege_escalated"] = True
            console.print(f"PRIVILEGE ESCALATION DETECTED (from signal): {privilege_evidences[0]}", style="bold green")
            console.print("Stopping workflow to generate PoC code", style="bold yellow")
            state["execution_status"] = "privilege_escalated"
            return state

    # 2. 직접 패턴 검사 (LLM 파싱이 놓쳤을 수 있음)
    has_priv_in_output = False
    priv_evidence = ""
    if execution_output:
        has_priv_in_output = is_privilege_escalated(execution_output)
        if has_priv_in_output:
            priv_evidence = execution_output[:200]
    if not has_priv_in_output:
        for result_text in execution_results.values():
            if is_privilege_escalated(result_text):
                has_priv_in_output = True
                priv_evidence = result_text[:200]
                break

    if has_priv_in_output:
        state["privilege_evidence"] = priv_evidence
        state["privilege_escalated"] = True
        console.print(f"PRIVILEGE ESCALATION DETECTED (direct pattern): {priv_evidence[:100]}...", style="bold green")
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

    # 카운터 증가 (라우팅 함수가 아닌 여기서 처리)
    workflow_step_count = state.get("workflow_step_count", 0) + 1
    iteration_count = state.get("iteration_count", 0) + 1
    state["workflow_step_count"] = workflow_step_count
    state["iteration_count"] = iteration_count
    console.print(f"  [Iteration {iteration_count}, Step {workflow_step_count}]", style="dim")

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

    # Exploit Readiness 처리
    if "exploit_readiness" in feedback_json:
        exploit_readiness = feedback_json["exploit_readiness"]
        state["exploit_readiness"] = exploit_readiness

        score = exploit_readiness.get("score", 0.0)
        recommend_exploit = exploit_readiness.get("recommend_exploit", False)
        priority = exploit_readiness.get("exploit_priority", "low")

        # Exploit Readiness 정보 출력
        if score >= 0.6:
            console.print(f" Exploit Readiness: {score:.0%} (Priority: {priority})", style="bold green")
        elif score >= 0.4:
            console.print(f" Exploit Readiness: {score:.0%} (Building up...)", style="yellow")
        else:
            console.print(f" Exploit Readiness: {score:.0%}", style="dim")

        if recommend_exploit:
            console.print(" RECOMMENDATION: Ready to exploit! Switch to exploitation phase.", style="bold green")

            # 부족한 항목 출력
            missing = exploit_readiness.get("missing_for_exploit", [])
            if missing:
                console.print(f" Still helpful to have: {', '.join(missing[:3])}", style="dim")
        else:
            # 부족한 항목 출력
            missing = exploit_readiness.get("missing_for_exploit", [])
            if missing:
                console.print(f" Missing for exploit: {', '.join(missing[:3])}", style="yellow")

    # 진전도 체크 및 전략 변경 제안
    try:
        from utility.progress_tracker import should_change_strategy, format_stuck_message
        is_stuck, reason = should_change_strategy(state)
        if is_stuck:
            console.print(format_stuck_message(state), style="bold yellow")
            # 막힘 상태를 state에 기록
            state["is_stuck"] = True
            state["stuck_reason"] = reason
    except ImportError:
        pass  # progress_tracker가 없으면 무시

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
        console.print(f"Privilege escalation detected: {privilege_evidence}", style="cyan")
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

def help_node(state: State) -> State:
    has_cot_result = bool(state.get("cot_result"))

    # 이미 작업이 진행된 상태인지 확인 (workflow.py의 has_progress와 동일한 조건)
    # cot_result가 있어야 실제 분석이 시작된 것
    has_progress = has_cot_result

    # 카테고리 확인
    challenge = state.get("challenge", [])
    category = ""
    if challenge and len(challenge) > 0:
        category = challenge[0].get("category", "").lower()

    if not has_progress:
        # 초기 상태: 카테고리별 옵션
        if category == "web":
            console.print("=== Available Commands (Web Category - Initial) ===", style='bold yellow')
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--auto : Let LLM automatically analyze and solve the challenge.", style="bold green")
            console.print("--file : Analyze the source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")
        elif category in ["pwnable", "reversing"]:
            console.print(f"=== Available Commands ({category.capitalize()} Category - Initial) ===", style='bold yellow')
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--auto : Let LLM automatically analyze and solve the challenge.", style="bold green")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--ghidra : Generate a plan based on decompiled and disassembled results.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")
        else:
            console.print("=== Available Commands (Initial) ===", style='bold yellow')
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--auto : Let LLM automatically analyze and solve the challenge.", style="bold green")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")
    else:
        # CoT 결과 있음: 후속 옵션 (--ghidra는 초기에만 가능)
        if category == "web":
            console.print("=== Available Commands (Web Category - After Analysis) ===", style='bold yellow')
        elif category in ["pwnable", "reversing"]:
            console.print(f"=== Available Commands ({category.capitalize()} Category - After Analysis) ===", style='bold yellow')
        else:
            console.print("=== Available Commands (After Initial Setup) ===", style='bold yellow')

        console.print("--help : Display the available commands.", style="bold yellow")
        console.print("--file : Analyze additional source code.", style="bold yellow")
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

    # 카테고리 확인
    challenge = state.get("challenge", [])
    category = ""
    if challenge and len(challenge) > 0:
        category = challenge[0].get("category", "").lower()

    # Recursion limit 체크 (50에 가까워지면 경고)
    RECURSION_LIMIT = 50
    if workflow_step_count >= RECURSION_LIMIT - 5:
        console.print(f"Approaching recursion limit: {workflow_step_count}/{RECURSION_LIMIT} steps", style="yellow")
        if workflow_step_count >= RECURSION_LIMIT:
            console.print(f"Recursion limit ({RECURSION_LIMIT}) reached.", style="bold yellow")
            console.print("Automatically continuing with --continue to loop_workflow...", style="cyan")
            # 자동으로 --continue 설정하고 카운터 리셋
            option = "--continue"
            state["iteration_count"] = 0
            state["workflow_step_count"] = 0
            console.print("Iteration count and workflow step count reset. Starting fresh cycle.", style="bold green")
        else:
            console.print("Please choose which option you want to choose.", style="blue")
            option = input("> ").strip()
    else:
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ").strip()

    # 카테고리별 옵션 유효성 검사
    if option == "--ghidra" and category not in ["pwnable", "reversing"]:
        console.print(f"--ghidra option is not available for '{category}' category.", style="bold red")
        console.print("Available options: --file, --discuss", style="yellow")
        option = ""  # 옵션 초기화하여 다시 입력받도록

    state["option"] = option

    # --continue 옵션 선택 시 반복 횟수 및 step count 리셋
    if option == "--continue":
        state["iteration_count"] = 0
        state["workflow_step_count"] = 0
        console.print("Iteration count and workflow step count reset. Starting fresh cycle.", style="bold green")

    return state


def detect_node(state: State) -> State:
    """
    Detect Agent 노드: 최종 결정자
    - Feedback 또는 Exploit 결과를 종합하여 다음 행동 결정
    - flag 발견, 쉘 획득, 계속 진행, 종료 등 최종 판단
    - 모든 판단은 LLM이 직접 수행 (하드코딩 없음)
    """
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Detect Agent (Final Decision) ===", style='bold magenta')

    import json

    # 모든 실행 결과 수집
    execution_output = state.get("execution_output", "")
    execution_results = state.get("execution_results", {})
    all_outputs = [execution_output] + list(execution_results.values())
    combined_output = "\n".join(str(o) for o in all_outputs if o)

    # LLM에게 전달할 컨텍스트 구성 (프롬프트 스키마에 맞춤)
    detect_context = {
        "source": "feedback" if state.get("feedback_result") else "exploit",
        "state": {
            "challenge": state.get("challenge", []),
            "facts": state.get("facts", {}),
            "artifacts": state.get("artifacts", {}),
        },
        "feedback": state.get("feedback_json", {}),
        "exploit_result": {
            "status": state.get("execution_status", "unknown"),
            "signals": state.get("signals", []),
        },
        "parsed": {
            "signals": state.get("signals", []),
        },
        # 실행 결과 전체 전달 (LLM이 직접 분석)
        "execution_output": combined_output[-8000:] if len(combined_output) > 8000 else combined_output,
        "exploit_readiness": state.get("exploit_readiness", {}),
    }

    console.print("=== Detect Run (LLM Analysis) ===", style='bold green')

    # Detect Agent 실행 (LLM이 직접 판단)
    detect_query = json.dumps(detect_context, ensure_ascii=False, indent=2)
    detect_return = ctx.detect.detect_run(prompt_query=detect_query)

    state["detect_result"] = detect_return

    # 결과 파싱
    detect_json = core.safe_json_loads(detect_return)
    state["detect_json"] = detect_json

    # LLM 응답에서 결정 추출 (프롬프트 출력 스키마에 맞춤)
    if isinstance(detect_json, dict):
        # Flag 감지 여부
        flag_detected = detect_json.get("flag_detected", False)
        detected_flag = detect_json.get("detected_flag")
        flag_confidence = detect_json.get("flag_confidence", 0.0)

        # Exploit 성공 여부
        exploit_success = detect_json.get("exploit_success", False)
        exploit_evidence = detect_json.get("exploit_evidence", {})
        shell_acquired = exploit_evidence.get("shell_acquired", False) if isinstance(exploit_evidence, dict) else False
        privilege_escalated = exploit_evidence.get("privilege_escalated", False) if isinstance(exploit_evidence, dict) else False
        evidence_text = exploit_evidence.get("evidence_text", "") if isinstance(exploit_evidence, dict) else ""

        # 다음 행동 및 상태
        next_action = detect_json.get("next_action", "continue_exploration")
        status = detect_json.get("status", "in_progress")
        reasoning = detect_json.get("reasoning", "")

        # 결과 출력
        console.print(f"Status: {status}", style="cyan")
        console.print(f"Flag detected: {flag_detected} (confidence: {flag_confidence:.0%})", style="green" if flag_detected else "dim")
        console.print(f"Exploit success: {exploit_success}", style="green" if exploit_success else "dim")
        console.print(f"Next action: {next_action}", style="bold yellow")
        if reasoning:
            console.print(f"Reasoning: {reasoning}", style="dim")

        # state 업데이트 및 decision 결정
        # 우선순위: flag_detected > exploit_success > shell/privilege > next_action

        # 1. Flag 감지 (최우선 - next_action과 관계없이)
        if flag_detected and detected_flag:
            state["flag_detected"] = True
            state["detected_flag"] = detected_flag
            state["detect_decision"] = "flag_found"
            state["detect_confidence"] = float(flag_confidence) if flag_confidence else 1.0
            console.print(f"🚩 FLAG DETECTED: {detected_flag}", style="bold green")
            console.print("Routing to PoC generation...", style="bold yellow")

        # 2. Shell 획득
        elif shell_acquired or (exploit_success and "shell" in str(evidence_text).lower()):
            state["detect_decision"] = "shell_acquired"
            state["detect_confidence"] = 0.9
            console.print(f"🐚 SHELL ACQUIRED: {evidence_text}", style="bold green")
            console.print("Routing to PoC generation...", style="bold yellow")

        # 3. 권한 상승
        elif privilege_escalated or (exploit_success and "root" in str(evidence_text).lower()):
            state["privilege_escalated"] = True
            state["detect_decision"] = "privilege_escalated"
            state["detect_confidence"] = 0.9
            console.print(f"🔐 PRIVILEGE ESCALATED: {evidence_text}", style="bold green")
            console.print("Routing to PoC generation...", style="bold yellow")

        # 4. Exploit 성공 (flag/shell 없이도 성공 판정된 경우)
        elif exploit_success or status == "solved":
            state["detect_decision"] = "shell_acquired"  # PoC 생성으로 라우팅
            state["detect_confidence"] = 0.8
            console.print(f"✅ EXPLOIT SUCCESS: {evidence_text or reasoning}", style="bold green")
            console.print("Routing to PoC generation...", style="bold yellow")

        # 5. Exploit 준비 완료
        elif next_action == "start_exploit":
            state["detect_decision"] = "exploit_ready"
            state["detect_confidence"] = 0.7
            console.print("⚡ Ready for exploitation", style="bold yellow")

        # 6. Exploit 재시도
        elif next_action == "retry_exploit":
            # retry_count 증가 (라우팅 함수가 아닌 여기서 처리)
            retry_count = state.get("detect_retry_count", 0) + 1
            state["detect_retry_count"] = retry_count
            state["detect_decision"] = "retry"
            state["detect_confidence"] = 0.5
            console.print(f"🔄 Retry exploit with adjustments (attempt {retry_count})", style="yellow")

        # 7. 종료 요청 (단, flag/exploit 성공이 아닌 경우만)
        elif next_action == "end":
            state["detect_decision"] = "continue"  # 일단 계속 진행 (너무 빨리 종료 방지)
            state["detect_confidence"] = 0.5
            console.print("🔄 LLM requested end, but continuing exploration", style="yellow")

        # 8. 계속 탐색
        else:  # continue_exploration
            state["detect_decision"] = "continue"
            state["detect_confidence"] = 0.5
            console.print("➡️ Continue exploration", style="cyan")

    else:
        # JSON 파싱 실패 시 기본값
        state["detect_decision"] = "continue"
        state["detect_confidence"] = 0.5
        console.print("Decision: continue (JSON parsing failed)", style="yellow")
        console.print(f"Raw response: {detect_return[:500]}...", style="dim")

    return state
