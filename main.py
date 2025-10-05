import os, json, re

from rich.console import Console

from agent.planning import PlanningAgent
from agent.instruction import InstructionAgent 
from agent.parsing import ParserAgent
from agent.feedback import FeedbackAgent
from agent.exploit import ExploitAgent
from agent.scenario import ScenarioAgent

from utility.core_utility import Core

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

# === Setting: Initialize Context ===
def setting():
    api_key = test_API_KEY()
    return AppContext(api_key)

# === Main Program ===
def main():    
    exploit_iteration = 0

    ctx = setting()
    
    core.init_state()
    core.init_plan()

    console.print("Enter the challenge title:", style="blue")
    title = input("> ")

    console.print("Enter the challenge description (Press <<<END>>> to finish):", style="blue")
    description = core.multi_line_input()

    console.print("Enter the challenge category:", style="blue")
    category = input("> ")
    
    category = category.lower()
    
    if(category == "pwnable"):
        console.print("Enter the binary checksec:", style="blue")
        checksec = core.multi_line_input()
                
        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")

        parsing_preInformation(category=category, flag = format, checksec=checksec)

    else: 
        console.print("Enter the challenge flag format:", style="blue")
        format = input("> ")
        
        parsing_preInformation(category=category, flag = format, checksec=None)    
        
    while True:
        
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ")
        
        if(ctx.planning.init_Option(option=option, ctx=ctx)):
            break
    
    while True:     
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ")
        
        ctx.planning.check_Option(option=option, ctx=ctx)
            
        exploit_iteration += 1
    
        # if exploit_iteration % 10 == 0:
        #     if not os.path.exists("state.json"):
        #         print("Error")
        #         continue
            
        #     st = load_state()
            
        #     exploit_prompt = ctx.planning.build_prompt(option="--exploit", state_json=st)
            
        #     console.print("=== Exploit ===", style="bold green")
        #     exploit_code = ctx.exploit.run_prompt_exploit(prompt=exploit_prompt)

        #     console.print("=== Human Translation ===", style="bold green")
        #     parsing_response = ctx.parsing.human_translation(query=exploit_code)
            
        #     console.print(parsing_response, style="yellow")
            
        #     console.print("Input result", style="blue")
        #     result_output = multi_line_input()
            
        #     result_build_prompt = ctx.planning.build_prompt(option="--result", query=result_output, state_json=st)
            
        #     console.print("=== LLM Translation ===", style="bold green")
        #     result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)

        #     console.print("=== Feedback === ", style="bold green")
        #     result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)

        #     update_state_json(result_feedback)
        #     console.print("Update State.json", style="bold green")

        #     plan_build_prompt = ctx.planning.build_prompt(option = "--plan", state_json=load_state(), feedback_json=result_feedback)

        #     console.print("=== run_prompt_CoT ===", style='bold green')
        #     response_CoT = ctx.planning.run_prompt_CoT(plan_build_prompt)
        #     ctx.planning.save_prompt("CoT.json", response_CoT)
        #     ctx.planning.update_state_from_cot(response_CoT)

        #     console.print("=== run_prompt_Cal ===", style='bold green')
        #     cal_input = ctx.planning.build_Cal_from_State()
        #     response_Cal = ctx.planning.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
        #     ctx.planning.save_prompt("Cal.json", response_Cal)

        #     Cal_result = ctx.planning.cal_CoT()
        #     ctx.planning.update_state_from_cal(Cal_result)

        #     console.print("=== Human Translation ===", style="bold green")
        #     parsing_response = ctx.parsing.human_translation(json.dumps(Cal_result, ensure_ascii=False, indent=2))
        #     console.print(parsing_response, style='yellow')            
        
        
        
if __name__ == "__main__":
    main()
    