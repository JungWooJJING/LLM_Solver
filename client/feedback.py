import json

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

console = Console()

class FeedbackClient:
    
    def __init__(self, api_key : str, model : str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def run_prompt_feedback(self, prompt):
        try:
            response = self.client.chat.completions.create(
                model = self.model,
                messages=[
                    {"role": "developer", "content": CTFSolvePrompt.feedback_prompt},
                    {"role": "user", "content": prompt}                    
                ],
            )
            
            return response.choices[0].message.content
        
        except Exception as e:
            raise RuntimeError(f"Failed to get response from LLM: {e}")   