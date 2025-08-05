import os

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

console = Console()

class ParsingClient:
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def human_translation(self, query : str):
        console.print("\nWait... LLM is currently being translated.\n", style="green")
        parsing_human_propmt = self.build_prompt_parsing("human", query)
        response = self.run_prompt_parsing(parsing_human_propmt)
        console.print(response)
    
    def LLM_translation(self, query : str):
        console.print("\nWait... LLM is currently being translated.\n", style="green")
        parsing_LLM_propmt = self.build_prompt_parsing("LLM", query)
        response = self.run_prompt_parsing(parsing_LLM_propmt)
        console.print(response)


    def run_prompt_parsing(self, prompt : str):
        try:
            response = self.client.chat.completions.create(
                model = self.model,
                messages=[
                    {"role": "system", "content": CTFSolvePrompt.parsing_prompt},
                    {"role": "user", "content": prompt}                    
                ],
                temperature=0.3
            )
            
            return response.choices[0].message.content
        
        except Exception as e:
            raise RuntimeError(f"Failed to get response from LLM: {e}")    
        
    def build_prompt_parsing(self, option : str, query : str):
        if option == "human":
            return (
                "Please rewrite the following JSON-like content so that a human can quickly and easily understand it.\n"
                "Summarize or explain the key structure and meaning clearly.\n"
                "Use simple and intuitive language, and visually organize the information (e.g., with indentation, bullet points, or headers) so that the structure can be grasped at a glance.\n\n"
                f"Original content:\n{query}"
            )

        elif option == "LLM":
             return (
                "You will be given JSON-formatted content. Please rewrite or restructure it in a way that makes it more explicit, structured, and easy for a language model to process.\n"
                "Clarify any ambiguous or implicit information and make sure the logic and structure are clearly represented.\n"
                "Use consistent formatting, expand any shorthand notations, and keep the key-value relationships intact.\n\n"
                f"Original JSON:\n{query}"
            )
