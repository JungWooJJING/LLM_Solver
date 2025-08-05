import os
import json

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
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

def pretty_print_tot_plan(json_str: str):
    try:
        plan = json.loads(json_str)
    except json.JSONDecodeError:
        console.print("Invalid JSON format.", style="red")
        return

    console.print("\nGoal", style="bold underline")
    console.print(plan["goal"])

    console.print("\nHypotheses", style="bold underline")
    for i, h in enumerate(plan["hypotheses"], 1):
        console.print(f"{i}. {h['name']} (Confidence: {h['confidence']}/10)")
        console.print(f"   Reason: {h['reason']}")

    console.print("\nSelected Hypothesis", style="bold underline")
    console.print(plan["selected"])

    console.print("\nToolset", style="bold underline")
    for tool in plan["toolset"]:
        console.print(f"- {tool}")

    console.print("\nConstraints", style="bold underline")
    for constraint in plan["constraints"]:
        console.print(f"- {constraint}")
    

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

    def check_Option(self, option: str):
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
            self.save_prompt("planning.json", planning_Prompt)
            response = self.run_prompt(planning_Prompt)
            console.print(pretty_print_tot_plan(response))

        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_Discuss = multi_line_input()
            console.print("wait...", style='bold green')
            planning_Prompt = self.build_prompt(option, planning_Discuss)
            self.save_prompt("planning.json", planning_Prompt)
            response = self.run_prompt(planning_Prompt)
            console.print(pretty_print_tot_plan(response))

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
            response = self.run_prompt(planning_instruction)
            console.print(pretty_print_tot_plan(response))

        elif option == "--result":
            console.print("Paste the result of your command execution. Submit an empty line to finish.", style="blue")
            result_output = multi_line_input()

            if not os.path.exists("planning.json"):
                console.print("planning.json not found. Run --file or --discuss first.", style="bold red")
                return
            with open("planning.json", "r") as f:
                previous_plan = f.read()

            planning_result = self.build_prompt(option, result_output, previous_plan)
            console.print("wait...", style='bold green')
            self.save_prompt("planning.json", planning_result)
            response = self.run_prompt(planning_result)
            console.print(pretty_print_tot_plan(response))

        elif option == "--quit":
            console.print("Goodbye!", style="bold yellow")
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
                f"{{\n  \"goal\": string,\n  \"hypotheses\": [{{\"name\": string, \"confidence\": int, \"reason\": string}}],\n  \"selected\": string,\n  \"toolset\": [string],\n  \"constraints\": [string]\n}}"
            )

        elif option == "--discuss":
            return (
                f"You are a cybersecurity assistant specializing in Capture The Flag (CTF) challenges.\n\n"
                f"Analyze the following challenge description and generate a Tree-of-Thought plan.\n"
                f"You must produce candidate vulnerability types, score them, and choose the most likely one.\n\n"
                f"Here is the challenge description:\n\n{query}\n\n"
                f"Respond in STRICT JSON:\n"
                f"{{\n  \"goal\": string,\n  \"hypotheses\": [{{\"name\": string, \"confidence\": int, \"reason\": string}}],\n  \"selected\": string,\n  \"toolset\": [string],\n  \"constraints\": [string]\n}}"
            )

        elif option == "--instruction":
            return (
                f"You are given a Tree-of-Thought (ToT) plan from a CTF challenge.\n"
                f"Convert it into a sequence of terminal commands that should be executed to validate the selected hypothesis.\n\n"
                f"Plan JSON:\n{query}\n\n"
                f"Respond in STRICT JSON format:\n"
                f"{{\n  \"steps\": [\n    {{\"id\": string, \"action\": string, \"command\": string, \"expected_signal\": string}}\n  ]\n}}"
            )

        elif option == "--result":
            return (
                f"You are updating a Tree-of-Thought (ToT) plan based on the latest execution result.\n\n"
                f"[Execution Result]\n{query}\n\n"
                f"[Current Plan]\n{plan_json}\n\n"
                f"Update the ToT plan accordingly. If the execution reveals failure or unexpected output, consider adding new hypotheses or adjusting the next steps.\n"
                f"Respond in STRICT JSON:\n"
                f"{{\n  \"goal\": string,\n  \"hypotheses\": [{{\"name\": string, \"confidence\": int, \"reason\": string}}],\n  \"selected\": string,\n  \"toolset\": [string],\n  \"constraints\": [string]\n}}"
            )
