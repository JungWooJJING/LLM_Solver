import os
from rich.console import Console
from client.pre_infomation import PreInformationClient
from client.planning import PlanningClient
from client.parsing import ParsingClient

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

# === Setting: Initialize Context ===
def setting():
    api_key = test_API_KEY()
    return AppContext(api_key)

# === Main Program ===
def main():
    ctx = setting()

    # === Pre-Information Phase ===
    console.print("Enter the challenge title:", style="blue")
    title = input("> ")

    console.print("Enter the challenge description (Press <<<END>>> to finish):", style="blue")
    description = multi_line_input()

    console.print("Enter the challenge category:", style="blue")
    category = input("> ")

    console.print("wait...", style='bold green')
    result = ctx.preinfo.ask_PreInformation(title, description, category)

    console.print("\n=== LLM Analysis ===\n", style='bold yellow')
    console.print(result, style='bold yellow')
    console.print("====================\n", style='bold yellow')

    # === Planning Phase ===
    while True:
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ")
        ctx.planning.check_Option(option, ctx)

if __name__ == "__main__":
    main()
