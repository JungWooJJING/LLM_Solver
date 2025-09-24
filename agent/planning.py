import os, re, json
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/home/wjddn0623/Ghidra/ghidra/build/dist/ghidra_12.0_DEV"
pyghidra.start()

from typing import List, Dict, Any

from openai import OpenAI
# from .todo import add_todos_from_actions, run_ready, load_plan

from templates.prompting2 import CTFSolvePrompt
from templates.prompting import few_Shot

from rich.console import Console

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

from utility.build_query import build_query
from utility.core_utility import Core
from utility.ghidra import ghdira_API
from utility.compress import Compress


console = Console()
core = Core()
FEWSHOT = few_Shot()

DEFAULT_STATE = {
  "challenge" : [],
  "constraints": ["no brute-force > 1000"],
  "env": {},
  "selected": {},
  "results": []
}

DEFAULT_PLAN = {
  "todos": [],
  "runs": [],
  "seen_cmd_hashes": [],
  "artifacts": {},
  "backlog" : []
}

w = {"feasibility": 0.25, "info_gain": 0.30, "novelty": 0.20, "cost": 0.15, "risk": 0.15}

prompt_CoT = [
    {"role": "developer", "content": CTFSolvePrompt.planning_prompt_CoT},
    {"role": "user",   "content": FEWSHOT.web_SQLI},
    {"role": "user",   "content": FEWSHOT.web_SSTI},
    {"role": "user",   "content": FEWSHOT.forensics_PCAP},
    {"role": "user",   "content": FEWSHOT.stack_BOF},
    {"role": "user",   "content": FEWSHOT.rev_CheckMapping},
]

class PlanningAgent:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.compress = Compress(api_key=api_key)
        
    def run_CoT(self, prompt_query: str):
        global prompt_CoT
        if not isinstance(globals().get("prompt_CoT"), list):
            prompt_CoT = []

        state = core.load_state()
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}

        call_msgs = prompt_CoT + [state_msg, user_msg]

        try:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
        except Exception:
            prompt_CoT[:] = self.compress.compress_history(prompt_CoT)
            call_msgs = prompt_CoT + [state_msg, user_msg]
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)

        content = res.choices[0].message.content

        prompt_CoT.extend([user_msg, {"role": "assistant", "content": content}])
        return content

    def run_Cal(self, prompt_query : str):
        prompt_Cal = [
            {"role": "developer", "content": CTFSolvePrompt.planning_prompt_Cal},
        ]
        
        prompt_Cal.append({"role": "user", "content": prompt_query})
        
        res = self.client.chat.completions.create(model=self.model, messages=prompt_Cal)
        return res.choices[0].message.content
    
    def ghidra_option(self, ctx):
        console.print("Enter the binary path: ", style="blue", end="")
        binary_path = input()

        console.print("=== Ghdira Run ===", style='bold green')
        binary_code = ghdira_API(binary_path)
        
        state = core.load_state()
                    
        # Query make
        Cot_query = build_query(option = "--ghidra", code = binary_code, state = state)
        
        # CoT 
        console.print("=== CoT Run ===", style='bold green')
        CoT_return = self.run_CoT(prompt_query = Cot_query)
        core.save_json(fileName="CoT.json", json=CoT_return)

        # Cal 
        Cal_query = build_query(option = "--Cal", state = state, CoT = CoT_return)
        console.print("=== Cal Run ===", style='bold green')
        Cal_return = self.run_Cal(prompt_query = Cal_query)
        core.save_json(fileName="Cal.json", json=Cal_return)
        
        # instruction
        instruction_query = build_query(option = "--instruction", Cal=Cal_return)
        console.print("=== instruction Agent Run ===", style='bold green')
        instruction_return = ctx.instruction.run_instruction(instruction_query, state=state)
        core.save_json(fileName="instruction.json", json=instruction_return)
        
        #instruction print
        cmd_human = ctx.parsing.Human__translation_run(prompt_query=instruction_return)
        console.print(f"{cmd_human}", style='bold yellow')
        
        return instruction_return
        
    
    def ok(self):
        console.print("Should we proceed like this? ", style="blue")
        console.print("ex) yes, y || no, n", style="blue", end="")
        select = input()
        
        select.lower()
        
        if(select == "y" or select == "yes"):
            return 1
        
        elif(select == "n" or select == "no"):
            return 0
        
        
    def init_Option(self, option: str, ctx):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--ghidra : Generate a plan based on decompiled and disassembled results.", style="bold yellow"   )
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")
        
        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_Discuss = core.multi_line_input()

        
        elif option == "--file":
            console.print("Paste the challenge’s source code. Type <<<END>>> on a new line to finish.", style="blue")
            planning_Code = core.multi_line_input()
            
        elif option == "--ghidra":
            result = self.ghidra_option(ctx)
            
            if(self.ok()):
                pass
            
            else:
                return 0
                
            #state.json, plan.json parsing_save & load
            core.state_update()
            core.plan_update()
            
            plan = core.load_json(fileName="plan.json", default=DEFAULT_STATE)    
            state = core.load_json(fileName="state.json", default=DEFAULT_STATE)
            
            # result
            console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
            instruction_result = core.multi_line_input()
            LLM_translation = ctx.parsing.LLM_translation_run(prompt_query=instruction_result, state=state)
            
            # feedback
            feedback_result = ctx.feedback.feedback_run(prompt_query=LLM_translation, state=state)       
            
            # state & plan update

            
        elif option == "--quit":
            console.print("\nGoodbye!\n", style="bold yellow")
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")
            
        
    def check_Option(self, option: str, ctx):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            # console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            # console.print("--ghidra : Generate a plan based on decompiled and disassembled results.", style="bold yellow"   )
            # console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            # console.print("--instruction : Get step-by-step guidance based on a plan.", style="bold yellow")
            # console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")
            # console.print("--result : Update plan based on execution result.", style="bold yellow")
            # console.print("--showplan : Show current plan.", style="bold yellow")
            # console.print("--add-summary : Append a manual human summary into state.json.", style="bold yellow")
            # console.print("--quit : Exit the program.", style="bold yellow")
            # -> 추후 옵션 넣고 수정 예정
            
        # elif option == "--discuss":
            
        # elif option == "--continue":
            
        # elif option == "--exploit":
        
        elif option == "--quit":
            console.print("\nGoodbye!\n", style="bold yellow")
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")
            