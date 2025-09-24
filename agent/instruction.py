import json

from templates.prompting2 import CTFSolvePrompt
from utility.core_utility import Core

from openai import OpenAI

core = Core()

class InstructionAgent:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def run_instruction(self, prompt_query: str, state: str):
        prompt_instruction = [
            {"role": "developer", "content": CTFSolvePrompt.instruction_prompt},
        ]
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg = {"role" : "user", "content" : prompt_query} 
        
        call_msgs = prompt_instruction + [state_msg, user_msg]
                
        res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
        return res.choices[0].message.content