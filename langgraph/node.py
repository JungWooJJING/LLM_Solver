from typing import Dict, Any
from graph.state import PlanningState

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
        challeng_info = {"type" : "source_code", "content" : planning_code}
        state["user_input"] = planning_code

    
    elif option == "--ghidra":
        console.print("Enter the binary path: ", style="blue", end="")
        binary_path = input()
        challenge_info = {"type" : "binary", "path" : binary_path}
        state["binary_path"] = binary_path

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
    
    console.print("=== CoT Run ===", style='bold green')

    CoT_return = ctx.planning.run_CoT(prompt_query = CoT_query, ctx = ctx)

    state["cot_result"] = CoT_return
    state["cot_json"] = core.safe_json_loads(CoT_return)

    return state

def Cal_node(state: State) -> State:
    ctx = state["ctx"]
    core = ctx.core

    console.print("=== Cal Run ===", style='bold green')

    Cal_query = build_query(option = "--Cal", state = state, CoT = state["cot_result"])

    console.print("=== Cal Run ===", style='bold green')

    Cal_return = ctx.planning.run_Cal(prompt_query = Cal_query)
    
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

    console.print("Should we proceed like this? ", style="blue")
    console.print("ex) yes, y || no, n ", style="blue", end="")

    select = input()

    select.lower()

    if select == "y" or select == "yes":
        state["user_approval"] = True
    elif select == "n" or select == "no":
        state["user_approval"] = False
        state["gpt_5"] = 0

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

    exploit_query = build_query(option = "--exploit", Instruction = state["parsing_result"])
    console.print("=== Exploit Run ===", style='bold green')

    exploit_return = ctx.exploit.exploit_run(prompt_query = exploit_query, state = state)

    return state

