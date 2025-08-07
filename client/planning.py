import os
import json

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from client.parsing import ParsingClient
from rich.console import Console

console = Console()

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
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def run_prompt(self, prompt: str):
        try:
            response = self.client.chat.completions.create(
                model = self.model,
                messages=[
                    {"role": "system", "content": CTFSolvePrompt.planning_prompt},
                    {"role": "user", "content": prompt}                    
                ],
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"Failed to get response from LLM: {e}")        

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
            
            response = self.run_prompt(planning_Prompt)
            self.save_prompt("planning.json", response)
            parsing_response = ctx.parsing.human_translation(response)
            console.print(parsing_response)

        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_Discuss = multi_line_input()
            
            console.print("wait...", style='bold green')
            
            planning_Prompt = self.build_prompt(option, planning_Discuss)
            
            response = self.run_prompt(planning_Prompt)
            self.save_prompt("planning.json", response)
            parsing_response = ctx.parsing.human_translation(response)
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
            
            parsing_response = ctx.parsing.LLM_translation(response)
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
                f"You are a cybersecurity assistant specializing in Capture The Flag (CTF) challenges.\n\n"
                f"You are tasked with performing a Tree-of-Thought (ToT) analysis to classify the challenge.\n\n"
                f"Your job is NOT to solve the problem.\n"
                f"Your goal is to generate candidate hypotheses (possible vulnerabilities), evaluate them step-by-step, and select the most likely one.\n\n"
                f"Here is the challenge code:\n\n{query}\n\n"
                f"Respond in the following STRICT JSON format:\n"
                f"{{\n"
                f"  \"goal\": string,\n"
                f"  \"hypotheses\": [\n"
                f"    {{\"name\": string, \"confidence\": int, \"reason\": string}}\n"
                f"  ],\n"
                f"  \"selected\": string,\n"
                f"  \"toolset\": [string],\n"
                f"  \"constraints\": [string]\n"
                f"}}"
            )

        elif option == "--discuss":
            return (
                f"You are a cybersecurity assistant specializing in Capture The Flag (CTF) challenges.\n\n"
                f"Analyze the following challenge description and generate a Tree-of-Thought plan.\n"
                f"You must produce candidate vulnerability types, score them, and choose the most likely one.\n\n"
                f"Here is the challenge description:\n\n{query}\n\n"
                f"Respond in STRICT JSON:\n"
                f"{{\n"
                f"  \"goal\": string,\n"
                f"  \"hypotheses\": [\n"
                f"    {{\"name\": string, \"confidence\": int, \"reason\": string}}\n"
                f"  ],\n"
                f"  \"selected\": string,\n"
                f"  \"toolset\": [string],\n"
                f"  \"constraints\": [string]\n"
                f"}}"
            )

        elif option == "--instruction":
            return (
                f"You are given a Tree-of-Thought (ToT) plan from a CTF challenge.\n"
                f"Convert it into a sequence of terminal commands that should be executed to validate the selected hypothesis.\n\n"
                f"Plan JSON:\n{query}\n\n"
                f"Respond in STRICT JSON format:\n"
                f"{{\n"
                f"  \"steps\": [\n"
                f"    {{\"id\": string, \"action\": string, \"command\": string, \"expected_signal\": string}}\n"
                f"  ]\n"
                f"}}"
            )

        elif option == "--result":
            return (
                f"You are updating a Tree-of-Thought (ToT) plan based on the latest execution result.\n\n"
                f"[Execution Result]\n{query}\n\n"
                f"[Current Plan]\n{plan_json}\n\n"
                f"Update the ToT plan accordingly. If the execution reveals failure or unexpected output, consider adding new hypotheses or adjusting the next steps.\n"
                f"Respond in STRICT JSON:\n"
                f"{{\n"
                f"  \"goal\": string,\n"
                f"  \"hypotheses\": [\n"
                f"    {{\"name\": string, \"confidence\": int, \"reason\": string}}\n"
                f"  ],\n"
                f"  \"selected\": string,\n"
                f"  \"toolset\": [string],\n"
                f"  \"constraints\": [string]\n"
                f"}}"
            )

        elif option == "--plan":
            return (
                f"You are a cybersecurity assistant updating a Tree-of-Thought (ToT) plan for a CTF challenge.\n\n"
                f"[Feedback from Execution Result]\n{query}\n\n"
                f"[Previous ToT Plan JSON]\n{plan_json}\n\n"
                f"Update the ToT plan based on the feedback **without regenerating it from scratch**.\n"
                f"Strictly follow these instructions:\n\n"
                f"1. Do NOT remove or rewrite existing hypotheses.\n"
                f"2. You MAY:\n"
                f"   - Modify confidence scores of existing hypotheses based on feedback.\n"
                f"   - Append new follow-up tasks if feedback reveals additional actionable steps.\n"
                f"   - Add a new section named 'result' to reflect the execution outcome.\n"
                f"   - Update 'toolset' and 'constraints' if justified.\n"
                f"3. You MUST include a new section named 'next_steps', which contains specific instructions for what to do next (e.g., find offset, bypass canary, ROP chain construction).\n"
                f"4. Do NOT regenerate or reorder the original plan. Only append or annotate based on findings.\n\n"
                f"Respond ONLY in the following STRICT JSON format:\n"
                f"{{\n"
                f"  \"goal\": string,\n"
                f"  \"hypotheses\": [\n"
                f"    {{\"name\": string, \"confidence\": int, \"reason\": string}}\n"
                f"  ],\n"
                f"  \"selected\": string,\n"
                f"  \"toolset\": [string],\n"
                f"  \"constraints\": [string],\n"
                f"  \"result\": string,\n"
                f"  \"next_steps\": [\n"
                f"    {{\"id\": string, \"action\": string, \"description\": string}}\n"
                f"  ]\n"
                f"}}"
            )
