# main.py

import os
from rich.console import Console
from client.pre_infomation import PreInformationClient
from client.planning import PlanningClient

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

# API_KEY Test
def test_API_KEY():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key: # If not found, print an error message and exit
        console.print("Please set the OPENAI_API_KEY environment variable.", style='bold red')
        console.print('export OPENAI_API_KEY="<API_KEY>"', style='bold red') 
        exit(1)
    return api_key

def pre_Information(api_key):
    # Input title 
    console.print("Enter the challenge title:", style="blue")
    title = input("> ")

    # Input description
    console.print("Enter the challenge description (Press Enter twice to finish):", style="blue")
    description = multi_line_input()

    # Input category
    console.print("Enter the challenge category:", style="blue")
    category = input("> ")

    # Create an instance of PreInformationClient and request analysis from the LLM
    client = PreInformationClient(api_key=api_key)
    result = client.ask_PreInformation(title, description, category)

    # Output LLM analysis result
    console.print("\n=== LLM Analysis ===\n", style='bold yellow')
    console.print(result, style='bold yellow')
    console.print("====================\n", style='bold yellow')

def planning(api_key):

    while(1):
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ")
        PlanningClient.check_Option(option)
    
    
def main():
    api_key = test_API_KEY() # Verify and retrieve API key
    
    pre_Information(api_key) # Run the Pre-Information client


if __name__ == "__main__":
    api_key = "dd"
    # main()
    planning(api_key)