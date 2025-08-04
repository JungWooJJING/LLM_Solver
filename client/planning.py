from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

console = Console()

def multi_line_input():
    lines = []

    first_line = input("> ")
    if first_line.strip() != "":
        lines.append(first_line)

    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)

    return "\n".join(lines)

class PlanningClient:
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def check_Option(option: str):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--instruction : Get step-by-step guidance based on a Tree-of-Thought plan.", style="bold yellow")
            console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")  
            console.print("--quit : Exit the program.", style="bold yellow")

        elif option == "--file":
            console.print("Paste the challenge’s source code. Submit an empty line to finish.", style="blue")
            planning_Code = multi_line_input()
            planning_Prompt = build_prompt(option, planning_Code)

        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_Discuss = multi_line_input()
            planning_Prompt = build_prompt(option, planning_Discuss)


        elif option == "--exploit":  
            console.print("Please wait. I will prepare an exploit script or a step-by-step procedure.", style="blue")

        elif option == "--instruction":
            console.print("I will provide step-by-step instructions based on a Tree-of-Thought plan.", style="blue")

        elif option == "--quit":
            console.print("Goodbye!")
            exit(1)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")
            
        def build_prompt(self, option : str, query):
            if (option == "--file"):
                return(
                    f"{query}\n"
                    f"Please analyze the code and give me information about the vulnerable parts."
                )
                
            elif (option == "discuss"):
                return(
                    f"{query}\n"
                    f""
                )
                
            elif (option == "--instruction"):
            

            