from typing import Dict, Any
from rich.console import Console

try:
    from langgraph.state import PlanningState as State
except ImportError:
    from state import PlanningState as State

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

def senario_node(state: State) -> State:
    ctx = state["ctx"]
    option = state["option"]
    core = ctx.core
    challenge_pre = state["challenge"]

    console.print("=== Scenario Agent ===", style='bold magenta')

    challenge_info = {}

    if option == "--file":
        console.print("Paste the challenge's source code. Type <<<END>>> on a new line to finish.", style="blue")
        planning_code = core.multi_line_input()
        challenge_info = {"type" : "source_code", "content" : planning_code}
        state["user_input"] = planning_code

    
    elif option == "--ghidra":
        console.print("Enter the binary path: ", style="blue", end="")
        binary_path = input()
        challenge_info = {"type" : "binary", "path" : binary_path}
        state["binary_path"] = binary_path
        
        console.print("=== Ghidra Run ===", style='bold green')
    
        try:
            binary_code = ghdira_API(binary_path)
            state["user_input"] = binary_code
            challenge_info["decompiled"] = binary_code
        except Exception as e:
            console.print(f"Error running Ghidra: {e}", style="bold red")
            console.print("Continuing without decompilation...", style="yellow")

    elif option == "--discuss":
        console.print("Ask questions or describe your intended approach.", style="blue")
        planning_discuss = core.multi_line_input()
        challenge_info = {"type" : "discussion", "content" : planning_discuss}
        state["user_input"] = planning_discuss

    scenario = ctx.scenario.create_scenario(challenge_info, state, option)
    state["scenario"] = scenario

    return state

def CoT_node(state: State) -> State:
    ctx = state["ctx"]
    option = state["option"]
    core = ctx.core

    console.print("=== Planning Agent ===", style='bold magenta')

    console.print("=== CoT Run ===", style='bold green')
    
    if option == "--file" or option == "--ghidra":
        user_input = state.get("user_input", "") or state.get("binary_path", "")
        CoT_query = build_query(option = option, code = user_input, state = state)

    elif option == "--discuss" or option == "--continue":
        user_input = state.get("user_input", "")
        CoT_query = build_query(option = option, code = user_input, state = state, plan = state.get("plan", {}))
    
    CoT_return = ctx.planning.run_CoT(prompt_query = CoT_query, ctx = ctx)

    state["cot_result"] = CoT_return
    state["cot_json"] = core.safe_json_loads(CoT_return)

    return state

def Cal_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    Cal_query = build_query(option = "--Cal", state = state, CoT = state["cot_result"])

    console.print("=== Cal Run ===", style='bold green')

    Cal_return = ctx.planning.run_Cal(prompt_query = Cal_query)

    console.print(f"{Cal_return}", style='bold yellow')
    
    state["cal_result"] = Cal_return
    state["cal_json"] = core.safe_json_loads(Cal_return)

    return state

def instruction_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Instruction Agent ===", style='bold magenta')

    instruction_query = build_query(option = "--instruction", CoT = state["cot_json"], Cal = state["cal_json"])

    console.print("=== Instruction Run ===", style='bold green')

    instruction_return = ctx.instruction.run_instruction(prompt_query = instruction_query, state = state)

    state["instruction_result"] = instruction_return
    state["instruction_json"] = core.safe_json_loads(instruction_return)

    return state

def human_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    human_query = build_query(option = "--human", Instruction = state["instruction_result"])

    console.print("=== Human Translation ===", style='bold green')

    human_return = ctx.parsing.Human__translation_run(prompt_query = human_query)

    console.print(f"{human_return}", style='bold yellow')

    console.print("Should we proceed like this? ", style="blue")
    console.print("ex) yes, y || no, n ", style="blue", end="")

    return state

def parsing_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Parsing Agent ===", style='bold magenta')

    console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
    instruction_result = core.multi_line_input()

    console.print("=== LLM_translation ===", style='bold green')
    LLM_translation = ctx.parsing.LLM_translation_run(prompt_query=instruction_result, state=state)

    state["parsing_result"] = LLM_translation

    return state

def feedback_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Feedback Agent ===", style='bold magenta')
    
    feedback_query = build_query(option = "--feedback", Instruction = state["parsing_result"])

    console.print("=== Feedback Run ===", style='bold green')

    feedback_return = ctx.feedback.feedback_run(prompt_query = feedback_query, state = state)

    state["feedback_result"] = feedback_return
    state["feedback_json"] = core.safe_json_loads(feedback_return)

    return state

def exploit_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Exploit Agent ===", style='bold magenta')

    import json
    state_for_json = {k: v for k, v in state.items() if k != "ctx"}
    plan = state.get("plan", {})
    
    exploit_query = build_query(
        option = "--exploit", 
        state = json.dumps(state_for_json, ensure_ascii=False, indent=2), 
        plan = json.dumps(plan, ensure_ascii=False, indent=2) if isinstance(plan, dict) else plan
    )
    console.print("=== Exploit Run ===", style='bold green')

    exploit_return = ctx.exploit.exploit_run(prompt_query = exploit_query)

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
        state["gpt_5"] = 0
    elif select in ["3", "end", "e", "quit", "q"]:
        state["approval_choice"] = "end"
        state["user_approval"] = False
    else:
        console.print("Invalid choice. Defaulting to continue.", style="yellow")
        state["approval_choice"] = "continue"
        state["user_approval"] = True

    return state

def help_node(state: State) -> State:
    has_scenario = bool(state.get("scenario"))
    
    if not has_scenario:
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
    console.print("Please choose which option you want to choose.", style="blue")
    option = input("> ").strip()
    state["option"] = option
    
    return state
