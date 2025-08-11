import os
import json

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from client.parsing import ParsingClient
from rich.console import Console

console = Console()
expand_k = 3 

def multi_line_input():
    console.print("Enter multiple lines. Type <<<END>>> on a new line to finish input.", style="bold yellow")
    lines = []
    while True:
        line = input(" ")
        if line.strip() == "<<<END>>>":
            break
        lines.append(line)
    return "\n".join(lines)

def cleanUp():
    if os.path.exists("planning.json"):
        os.remove("planning.json")

    if os.path.exists("instruction.json"):
        os.remove("instruction.json")

class PlanningClient:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def run_prompt_CoT(self, prompt: str):
        try:
            response = self.client.chat.completions.create(
                model = self.model,
                messages=[
                    {"role": "system", "content": CTFSolvePrompt.planning_prompt_CoT},
                    {"role": "user", "content": prompt}                    
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"Failed to get response from LLM: {e}")        
        
    def run_prompt_ToT(self, prompt: str):
        try:
            response = self.client.chat.completions.create(
                model = self.model,
                messages=[
                    {"role": "system", "content": CTFSolvePrompt.planning_prompt_ToT},
                    {"role": "user", "content": prompt}                    
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"Failed to get response from LLM: {e}")  
    
    def safe_json_loads(self, JSON: str) -> dict:
        try:
            return json.loads(JSON)
        except Exception:
            JSON = JSON[JSON.find('{'): JSON.rfind('}')+1]
            return json.loads(JSON)
        
    def cal_ToT(self, tot: str):
        

    def save_prompt(self, filename: str, content: str):
        with open(filename, "w") as f:
            f.write(content)
        console.print(f"[Prompt saved to {filename}]", style="green")

    def check_Option(self, option: str, ctx):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--instruction : Get step-by-step guidance based on a Tree-of-Thought plan.", style="bold yellow")
            console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")  
            console.print("--result : Update plan based on execution result.", style="bold yellow")
            console.print("--showplan : Show current Tree-of-Thought plan.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")

        elif option == "--showplan":
            if not os.path.exists("planning.json"):
                console.print("planning.json not found. Run --file or --discuss first.", style="bold red")
                return
            with open("planning.json", "r") as f:
                console.print("[bold cyan]Current ToT Plan:[/bold cyan]\n")
                console.print(f.read(), style="white")

        elif option == "--file":
            console.print("Paste the challenge’s source code. Submit an empty line to finish.", style="blue")
            planning_Code = multi_line_input()
            
            console.print("wait...", style='bold green')
            
            planning_Prompt = self.build_prompt(option, planning_Code)
            
            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(planning_Prompt)
            self.save_prompt("CoT.json", response_CoT)

            console.print("=== run_prompt_ToT ===", style='bold green')
            response_ToT = self.run_prompt_ToT(response_CoT)
            self.save_prompt("ToT.json", response_ToT)
            
            parsing_response = ctx.parsing.human_translation(response_ToT)
            console.print(parsing_response)

        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_Discuss = multi_line_input()
            
            console.print("wait...", style='bold green')
            
            planning_Prompt = self.build_prompt(option, planning_Discuss)
            
            response_CoT = self.run_prompt_CoT(planning_Prompt)
            response_ToT = self.run_prompt_ToT(response_CoT)
            
            self.save_prompt("planning.json", response_ToT)
            parsing_response = ctx.parsing.human_translation(response_ToT)
            console.print(parsing_response)
            
        elif option == "--exploit":  
            console.print("Please wait. I will prepare an exploit script or a step-by-step procedure.", style="blue")

        elif option == "--instruction":
            console.print("I will provide step-by-step instructions based on a Tree-of-Thought plan.", style="blue")
            
            if not os.path.exists("planning.json"):
                console.print("planning.json not found. Run --file or --discuss first.", style="bold red")
                return
            
            with open("planning.json", "r") as f:
                plan_json = f.read()
            
            planning_instruction = self.build_prompt(option, plan_json)
            
            self.save_prompt("instruction.json", planning_instruction)
            
            console.print("wait...", style='bold green')
            # instruction client run_prompt

        elif option == "--result":
            console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
            result_output = multi_line_input()

            if not os.path.exists("planning.json"):
                console.print("planning.json not found. Run --file or --discuss first.", style="bold red")
                return

            with open("planning.json", "r") as f:
                previous_plan = f.read() 
            
            parsing_response = ctx.parsing.LLM_translation(result_output)
            # feedback client run_prompt -> result 

            # plan_Update = self.build_prompt("--plan", previous_plan, "feedback client_result")

            # Update planning.json

        elif option == "--quit":
            cleanUp()
            console.print("\nGoodbye!\n", style="bold yellow")
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")

    def build_prompt(self, option: str, query: str, plan_json: str = ""):
        if option == "--file":
            return (
                f"You are a planning assistant for CTF automation.\n\n"
                f"You will be given the content of a file related to a CTF challenge "
                f"(e.g., source code, binary disassembly, script, or captured data).\n"
                f"Your job is NOT to solve or exploit the challenge directly, "
                f"but to propose multiple distinct investigative or preparatory actions "
                f"for the very next step.\n\n"
                f"[File Content]\n{query}\n\n"
                f"Generate {expand_k} distinct candidates.\n"
                f"For each candidate:\n"
                f"- Provide a short Chain-of-Thought (3–5 sentences) explaining WHY this step is useful, "
                f"HOW to attempt it, and WHAT evidence or artifacts it may produce.\n"
                f"- Extract a one-line actionable 'thought'.\n"
                f"- List expected artifacts, required tools/permissions, a brief risk note, and estimated cost.\n"
                f"- Avoid trivial variations; each candidate must be meaningfully different.\n\n"
                f"Respond ONLY in the following STRICT JSON format:\n"
                f"{{\n"
                f"  \"candidates\": [\n"
                f"    {{\n"
                f"      \"cot\": \"3-5 sentences reasoning\",\n"
                f"      \"thought\": \"one-line concrete next step\",\n"
                f"      \"expected_artifacts\": [\"file1\", \"file2\"],\n"
                f"      \"requires\": [\"tool/permission/dependency\"],\n"
                f"      \"risk\": \"short note\",\n"
                f"      \"estimated_cost\": \"low|medium|high\"\n"
                f"    }}\n"
                f"  ]\n"
                f"}}"
            )
            
        elif option == "--discuss":
            return (
                f"You are an adjuster for CTF ToT planning (NOT a solver).\n"
                f"Your role is to make SMALL, LOCAL UPDATES to an ALREADY-EVALUATED ToT plan:\n"
                f"- fine-tune scores,\n"
                f"- tweak or append next-step tasks,\n"
                f"- optionally reorder within the same beam level.\n"
                f"Do NOT regenerate the plan from scratch. Do NOT attempt to solve or output flags.\n\n"
                f"[User Message]\n{query}\n\n"
                f"[Current ToT Plan JSON]\n{plan_json}\n\n"
                f"POLICY\n"
                f"- Keep existing node IDs stable. No wholesale rewrites.\n"
                f"- Only DELTA updates are allowed (score deltas, minor edits, appends, soft-deprecations).\n"
                f"- Stay in planning mode (investigation/preparation only).\n"
                f"- If user request is off-scope (solve/flag/exploit), refuse and suggest safe planning alternatives.\n"
                f"- If critical info is missing, ask up to 2 crisp clarifying questions.\n\n"
                f"TASK\n"
                f"1) Diagnose the user message (ok | ambiguity | off-topic | solve-request).\n"
                f"2) Propose SMALL DELTAS to the plan:\n"
                f"   - score_adjustments: +/- deltas with reasons (clipped to [0,1] when applied by the system).\n"
                f"   - task_updates: update/append/deprecate tasks, referencing existing IDs when possible.\n"
                f"   - reorder: optional local reordering list for same-depth siblings.\n"
                f"   - constraints_append/toolset_append: OPTIONAL short additions if justified.\n"
                f"3) Optionally set a new short 'next_goal' if the user intent shifted.\n"
                f"4) Keep it minimal. No long prose. No solving.\n\n"
                f"OUTPUT — STRICT JSON ONLY:\n"
                f"{{\n"
                f"  \"mode\": \"ok|clarify|redirect|refuse\",\n"
                f"  \"clarifying_questions\": [\"q1\", \"q2\"],\n"
                f"  \"score_adjustments\": [\n"
                f"    {{\"node_id\": \"A1\", \"delta\": +0.10, \"reason\": \"new evidence X\"}}\n"
                f"  ],\n"
                f"  \"task_updates\": [\n"
                f"    {{\"op\": \"update\", \"task_id\": \"T3\", \"fields\": {{\"description\": \"short fix\", \"risk\": \"lower\"}}}},\n"
                f"    {{\"op\": \"append\", \"parent_node\": \"B2\", \"new_task\": {{\"id\": \"T9\", \"action\": \"checksec\", \"description\": \"run checksec\", \"artifact\": \"checksec.json\"}}}},\n"
                f"    {{\"op\": \"deprecate\", \"task_id\": \"T1\", \"reason\": \"duplicate\"}}\n"
                f"  ],\n"
                f"  \"reorder\": [\n"
                f"    {{\"depth\": 2, \"order\": [\"B2\",\"A1\",\"C1\"]}}\n"
                f"  ],\n"
                f"  \"constraints_append\": [\"no brute-force > 1000 tries\"],\n"
                f"  \"toolset_append\": [\"gdb-peda\"],\n"
                f"  \"next_goal\": \"one-line immediate goal\",\n"
                f"  \"nudges\": [\"keep investigative\", \"save artifacts\" ]\n"
                f"}}\n"
                f"No prose outside the JSON."
            )



        elif option == "--instruction":
            return (
                f"You are an instruction generator for CTF automation.\n\n"
                f"You are given a selected planning candidate (thought + minimal context).\n"
                f"Convert it into a concrete, minimal sequence of terminal actions to execute.\n"
                f"BEFORE listing actions, reason briefly (2–3 sentences) about execution order and expected results "
                f"(Do NOT attempt to solve; focus on preparation and evidence collection).\n\n"
                f"[Selected Candidate]\n{query}\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                f"{{\n"
                f"  \"intra_cot\": \"2-3 sentences about order and expectations\",\n"
                f"  \"actions\": [\n"
                f"    {{\n"
                f"      \"name\": \"short label\",\n"
                f"      \"cmd\": \"exact terminal command\",\n"
                f"      \"success\": \"observable success signal\",\n"
                f"      \"artifact\": \"output file/log to save (or '-')\",\n"
                f"      \"fallback\": \"alternative command if primary fails (or '-')\"\n"
                f"    }}\n"
                f"  ]\n"
                f"}}"
            )


        elif option == "--result":
            return (
                f"You are updating a planning state based on the latest execution result.\n"
                f"Do NOT regenerate a new plan from scratch.\n"
                f"Summarize observations, classify issues, and provide rescoring hints for BFS/Beam selection.\n"
                f"(You are NOT solving the challenge.)\n\n"
                f"[Execution Result]\n{query}\n\n"
                f"[Current Plan JSON]\n{plan_json}\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                f"{{\n"
                f"  \"observations\": [\"concise fact 1\", \"concise fact 2\"],\n"
                f"  \"issues\": [\"env/tool/logical/permission/timeout/etc\"],\n"
                f"  \"new_evidence\": int,\n"
                f"  \"delta_score\": 0.0,\n"
                f"  \"updates\": {{\n"
                f"    \"hypotheses_confidence\": [{{\"name\": \"...\", \"delta\": +0.1}}],\n"
                f"    \"toolset_append\": [\"...\"],\n"
                f"    \"constraints_append\": [\"...\"]\n"
                f"  }},\n"
                f"  \"next_goal\": \"one-line immediate goal\",\n"
                f"  \"suggested_actions\": [\n"
                f"    {{\"thought\": \"concise next step\", \"reason\": \"why it helps\"}}\n"
                f"  ]\n"
                f"}}"
            )


        elif option == "--plan":
            return (
                f"You are a planning assistant updating an existing plan based on feedback.\n"
                f"Do NOT regenerate or reorder the original plan; only append or annotate.\n"
                f"Adjust confidence, add next steps, and record result notes as needed.\n"
                f"(You are NOT solving the challenge.)\n\n"
                f"[Feedback]\n{query}\n\n"
                f"[Previous Plan JSON]\n{plan_json}\n\n"
                f"Strictly follow:\n"
                f"1) Do NOT delete existing hypotheses.\n"
                f"2) You MAY modify confidence scores, append follow-up tasks, and update toolset/constraints if justified.\n"
                f"3) Add a 'result' note if execution produced a concrete outcome.\n"
                f"4) MUST include 'next_steps' with specific, small-grained actions.\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                f"{{\n"
                f"  \"goal\": \"...\",\n"
                f"  \"hypotheses\": [{{\"name\": \"...\", \"confidence\": int, \"reason\": \"...\"}}],\n"
                f"  \"selected\": \"...\",\n"
                f"  \"toolset\": [\"...\"],\n"
                f"  \"constraints\": [\"...\"],\n"
                f"  \"result\": \"short note or '-'\",\n"
                f"  \"next_steps\": [\n"
                f"    {{\"id\": \"S1\", \"action\": \"short label\", \"description\": \"what to do next\"}}\n"
                f"  ]\n"
                f"}}"
            )
