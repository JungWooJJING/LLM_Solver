import os
import json

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

class InstructionClient:
    
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    