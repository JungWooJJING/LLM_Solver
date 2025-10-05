import os, re, json
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/home/wjddn0623/Ghidra/ghidra/build/dist/ghidra_12.0_DEV"
pyghidra.start()

from typing import List, Dict, Any

from openai import OpenAI

from templates.prompting import CTFSolvePrompt
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

gpt_5 = 1

DEFAULT_STATE = {
  "challenge" : [],
  "scenario" : [],
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

plan_CoT = [
    {"role": "developer", "content": CTFSolvePrompt.plan_CoT},
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
        
    def run_CoT(self, prompt_query: str, ctx):
        global prompt_CoT
        global gpt_5

        if not isinstance(globals().get("prompt_CoT"), list):
            prompt_CoT = []

        state = core.load_json("state.json", default="")
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}

        call_msgs = prompt_CoT + [state_msg, user_msg]

        try:
            if gpt_5:
                res = self.client.chat.completions.create(model="gpt-5", messages=call_msgs)
            
            else:
                res = self.client.chat.completions.create(model="gpt-4o", messages=call_msgs, temperature=0.5)
                gpt_5 = 1

        except Exception:
            prompt_CoT[:] = self.compress.compress_history(prompt_CoT, ctx=ctx)
            call_msgs = prompt_CoT + [state_msg, user_msg]

            if gpt_5:
                res = self.client.chat.completions.create(model="gpt-5", messages=call_msgs)
            
            else:
                res = self.client.chat.completions.create(model="gpt-4o", messages=call_msgs, temperature=0.5)
                gpt_5 = 1

        content = res.choices[0].message.content

        plan_CoT.extend([user_msg, {"role": "assistant", "content": content}])
        return content
    
    def run_plan_CoT(self, prompt_query : str, ctx):
        global plan_CoT   
        global gpt_5
        
        if not isinstance(globals().get("prompt_CoT"), list):
            plan_CoT = []

        state = core.load_json("state.json", default="")
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}

        call_msgs = plan_CoT + [state_msg, user_msg]

        try:
            if gpt_5:
                res = self.client.chat.completions.create(model="gpt-5", messages=call_msgs)
            
            else:
                res = self.client.chat.completions.create(model="gpt-4o", messages=call_msgs, temperature=0.5)
                gpt_5 = 1

        except Exception:
            plan_CoT[:] = self.compress.compress_history(plan_CoT, ctx=ctx)
            call_msgs = plan_CoT + [state_msg, user_msg]

            if gpt_5:
                res = self.client.chat.completions.create(model="gpt-5", messages=call_msgs)
            
            else:
                res = self.client.chat.completions.create(model="gpt-4o", messages=call_msgs, temperature=0.5)
                gpt_5 = 1
                
        content = res.choices[0].message.content

        plan_CoT.extend([user_msg, {"role": "assistant", "content": content}])
        return content
    
    def run_Cal(self, prompt_query : str):
        prompt_Cal = [
            {"role": "developer", "content": CTFSolvePrompt.planning_prompt_Cal},
        ]
        
        prompt_Cal.append({"role": "user", "content": prompt_query})
        
        res = self.client.chat.completions.create(model=self.model, messages=prompt_Cal)
        return res.choices[0].message.content
    
    def first_workflow(self, option:str , ctx):
        state = core.load_json("state.json", default="")
        plan = core.load_json("plan.json", default="")

        # Scenario Analysis - Create scenario first
        console.print("=== Scenario Analysis ===", style='bold magenta')
        challenge_info = {}
        
        if(option == "--file"):
            console.print("Paste the challenge's source code. Type <<<END>>> on a new line to finish.", style="blue")
            planning_code = core.multi_line_input()
            challenge_info = {"type": "source_code", "content": planning_code}
            
            console.print("=== File Analysis ===", style='bold green')
            Cot_query = build_query(option = option, code = planning_code, state = state)

            
        elif(option == "--ghidra"):
            console.print("Enter the binary path: ", style="blue", end="")
            binary_path = input()
            challenge_info = {"type": "binary", "path": binary_path}

            console.print("=== Ghdira Run ===", style='bold green')
            binary_code = ghdira_API(binary_path)
            
            Cot_query = build_query(option = option, code = binary_code, state = state)
        
        elif(option == "--discuss"):
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_discuss = core.multi_line_input()
            challenge_info = {"type": "discussion", "content": planning_discuss}
            
            console.print("=== Discuss ===", style='bold green')
            Cot_query = build_query(option = option, code = planning_discuss, state = state, plan=plan)

        # Create scenario
        scenario = ctx.scenario.create_scenario(challenge_info, state, option)
        state["scenario"] = scenario
        core.save_json(fileName="state.json", obj=state)

        # CoT 
        console.print("=== CoT Run ===", style='bold green')
        CoT_return = self.run_CoT(prompt_query = Cot_query, ctx=ctx)
        CoT_json = core.safe_json_loads(CoT_return)
        core.save_json(fileName="CoT.json", obj=CoT_json)

        # Cal 
        Cal_query = build_query(option = "--Cal", state = state, CoT = CoT_return)
        console.print("=== Cal Run ===", style='bold green')
        Cal_return = self.run_Cal(prompt_query = Cal_query)
        Cal_json = core.safe_json_loads(Cal_return)
        core.save_json(fileName="Cal.json", obj=Cal_json)
        
        # instruction
        instruction_query = build_query(option = "--instruction", CoT= CoT_json,Cal=Cal_return)
        console.print("=== instruction Agent Run ===", style='bold green')
        instruction_return = ctx.instruction.run_instruction(instruction_query, state=state)
        instruction_json = core.safe_json_loads(instruction_return)
        core.save_json(fileName="instruction.json", obj=instruction_json)
        
        #instruction print
        cmd_human = ctx.parsing.Human__translation_run(prompt_query=instruction_return)
        console.print(f"{cmd_human}", style='bold yellow')
        
    def loop_workflow(self, option:str , ctx):
        state = core.load_json("state.json", default="")
        plan = core.load_json("plan.json", default="")
        scenario = state.get("scenario", {})
        
        if(option == "--discuss"):
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_discuss = core.multi_line_input()
            
            console.print("=== Discuss ===", style='bold green')
            Cot_query = build_query(option = option, code = planning_discuss, state = state, plan=plan)
            
        elif(option == "--continue"):
            Cot_query = build_query(option = "--plan", state = state, plan=plan)

        # CoT 
        console.print("=== CoT Run ===", style='bold green')
        CoT_return = self.run_plan_CoT(prompt_query = Cot_query, ctx=ctx)
        CoT_json = core.safe_json_loads(CoT_return)
        core.save_json(fileName="CoT.json", obj=CoT_json)

        # Cal 
        Cal_query = build_query(option = "--Cal", state = state, CoT = CoT_return)
        console.print("=== Cal Run ===", style='bold green')
        Cal_return = self.run_Cal(prompt_query = Cal_query)
        Cal_json = core.safe_json_loads(Cal_return)
        core.save_json(fileName="Cal.json", obj=Cal_json)
        
        # instruction
        instruction_query = build_query(option = "--instruction", CoT= CoT_json,Cal=Cal_return)
        console.print("=== instruction Agent Run ===", style='bold green')
        instruction_return = ctx.instruction.run_instruction(instruction_query, state=state)
        instruction_json = core.safe_json_loads(instruction_return)
        core.save_json(fileName="instruction.json", obj=instruction_json)
        
        #instruction print
        cmd_human = ctx.parsing.Human__translation_run(prompt_query=instruction_return)
        console.print(f"{cmd_human}", style='bold yellow')
        
        # Scenario Progress Tracking (after instruction generation)
        console.print("=== Scenario Progress Tracking ===", style='bold magenta')
        latest_results = {
            "CoT": CoT_json,
            "Cal": Cal_json,
            "instruction": instruction_json
        }
        progress = ctx.scenario.track_progress(scenario, state, latest_results)
        
        # Print scenario summary
        ctx.scenario.print_scenario_summary(scenario)
                
    def ok(self):
        console.print("Should we proceed like this? ", style="blue")
        console.print("ex) yes, y || no, n ", style="blue", end="")
        select = input()
        
        select.lower()
        
        if(select == "y" or select == "yes"):
            return 1
        
        elif(select == "n" or select == "no"):
            return 0
        
    def feedback_rutin(self, ctx):
        #state.json, plan.json parsing_save & load
        core.state_update()
        core.plan_update()
        
        state = core.load_json(fileName="state.json", default=DEFAULT_STATE)
        
        # result
        console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
        instruction_result = core.multi_line_input()
        console.print("=== LLM_translation ===", style='bold green')
        LLM_translation = ctx.parsing.LLM_translation_run(prompt_query=instruction_result, state=state)
        
        # feedback
        console.print("=== feedback Agent ===", style='bold green')
        feedback_result = ctx.feedback.feedback_run(prompt_query=LLM_translation, state=state)       
        feedback_json = core.safe_json_loads(feedback_result)
        core.save_json(fileName="feedback.json", obj=feedback_json)
        
        # state & plan update
        core.parsing_feedback()

    def exploit_flow(self, ctx, option : str):
            state = core.load_json(fileName="state.json", default="")
            plan = core.load_json(fileName="plan.json", default="")
            
            exploit_prompt = build_query(option=option, state=json.dumps(state, ensure_ascii=False, indent=2), plan=json.dumps(plan, ensure_ascii=False, indent=2))
            
            console.print("=== Exploit Agent ===", style='bold green')
            exploit_return = ctx.exploit.exploit_run(prompt_query=exploit_prompt)
            
            cmd_human = ctx.parsing.Human__translation_run(prompt_query=exploit_return)
            console.print(f"{cmd_human}", style='bold yellow')
            
            # result
            console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
            instruction_result = core.multi_line_input()

            console.print("=== LLM_translation ===", style='bold green')
            LLM_translation = ctx.parsing.Exploit_result_run(prompt_query=instruction_result, state=state, scenario=json.dumps(exploit_return, ensure_ascii=False, indent=2)) 
                            
            # feedback
            console.print("=== feedback Agent ===", style='bold green')
            feedback_result = ctx.feedback.exploit_feedback_run(prompt_query=LLM_translation, state=state, scenario=json.dumps(exploit_return, ensure_ascii=False, indent=2))       
            feedback_json = core.safe_json_loads(feedback_result)
            core.save_json(fileName="feedback.json", obj=feedback_json)

    def init_Option(self, option: str, ctx):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--ghidra : Generate a plan based on decompiled and disassembled results.", style="bold yellow"   )
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")
        
        elif option == "--discuss":
            self.first_workflow(option=option, ctx=ctx)
            
            if(self.ok()):
                pass
            
            else:
                gpt_5 = 0
                return 0
            
            self.feedback_rutin(ctx)

            return 1
        
        elif option == "--file":
            self.first_workflow(option=option, ctx=ctx)
            
            if(self.ok()):
                pass
            
            else:
                gpt_5 = 0
                return 0
            
            self.feedback_rutin(ctx)
            
            return 1
            
        elif option == "--ghidra":
            self.first_workflow(option=option, ctx=ctx)
            
            if(self.ok()):
                pass
            
            else:
                gpt_5 = 0
                return 0

            self.feedback_rutin(ctx)
            
            return 1
            
        elif option == "--quit":
            console.print("\nGoodbye!\n", style="bold yellow")
            
            core.cleanUp()
            
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")
        
    def check_Option(self, option: str, ctx):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--continue : Continue using LLM with the latest feedback and proceed to the next step.", style="bold yellow")
            console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")
            
        elif option == "--discuss":
            self.loop_workflow(option=option, ctx=ctx)
            
            if(self.ok()):
                pass
            
            else:
                gpt_5 = 0
                return 0
            
            self.feedback_rutin(ctx)
            
        elif option == "--continue":
            self.loop_workflow(option=option, ctx=ctx)
            
            if(self.ok()):
                pass
            
            else:
                gpt_5 = 0
                return 0
            
            self.feedback_rutin(ctx)
            
        elif option == "--exploit":
            
            self.exploit_flow(ctx=ctx, option=option)
        
            # state & plan Update
            core.exploit_feedback()
            
        
        elif option == "--quit":
            console.print("\nGoodbye!\n", style="bold yellow")
            
            core.cleanUp()
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")
            