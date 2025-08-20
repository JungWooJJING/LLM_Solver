import os, json
from rich.console import Console
from client.pre_infomation import PreInformationClient
from client.planning import PlanningClient
from client.parsing import ParsingClient
from client.instruction import InstructionClient
from client.feedback import FeedbackClient
from client.exploit import ExploitClient

console = Console()

# === Common Input Handler ===
def multi_line_input():
    console.print("Enter multiple lines. Type <<<END>>> on a new line to finish input.", style="bold yellow")
    lines = []
    while True:
        line = input(" ")
        if line.strip() == "<<<END>>>":
            break
        lines.append(line)
    return "\n".join(lines)

# === API Key Check ===
def test_API_KEY():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        console.print("Please set the OPENAI_API_KEY environment variable.", style='bold red')
        console.print('export OPENAI_API_KEY="<API_KEY>"', style='bold red')
        exit(1)
    return api_key

# === Context Class for All Clients ===
class AppContext:
    def __init__(self, api_key):
        self.api_key = api_key
        self.preinfo = PreInformationClient(api_key)
        self.planning = PlanningClient(api_key)
        self.parsing = ParsingClient(api_key)
        self.instruction = InstructionClient(api_key)
        self.feedback = FeedbackClient(api_key)
        self.exploit = ExploitClient(api_key)

# === Setting: Initialize Context ===
def setting():
    api_key = test_API_KEY()
    return AppContext(api_key)

# === Main Program ===
def main():
    iteration = 0

    ctx = setting()

    # console.print("Enter the challenge title:", style="blue")
    # title = input("> ")

    # console.print("Enter the challenge description (Press <<<END>>> to finish):", style="blue")
    # description = multi_line_input()

    # console.print("Enter the challenge category:", style="blue")
    # category = input("> ")

    # console.print("wait...", style='bold green')
    # result = ctx.preinfo.ask_PreInformation(title, description, category)

    # console.print("\n=== LLM Analysis ===\n", style='bold yellow')
    # console.print(result, style='bold yellow')
    # console.print("====================\n", style='bold yellow')

    while True:
        iteration += 1
        
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ")
        ctx.planning.check_Option(option, ctx)
        
        
        # if iteration % 3 == 0:
        #     if not os.path.exists("state.json"):
        #         print("Error")
        #         continue

        #     console.print("Compress state.json", style="bold green")
        #     with open("state.json", "r", encoding="utf-8") as f:
        #         state = json.load(f)

        #     result_pompress = ctx.parsing.run_prompt_state_compress(json.dumps(state))

        #     if isinstance(result_pompress, str):
        #         obj = json.loads(result_pompress)
        #     else:
        #         obj = result_pompress
                
        #     if not isinstance(obj, dict):
        #         print("Error: compressor returned non-JSON-object")
        #         continue

        #     with open("state.json", "w", encoding="utf-8") as f:
        #         json.dump(obj, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()