import json

from templates.prompting2 import CTFSolvePrompt
from openai import OpenAI

class FeedbackAgent:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.api_key = OpenAI(api_key=api_key)
        self.model = model
        
    def feedback_run(self, prompt_query:str = "", state: str = ""):
        feedback_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.feedback_prompt}
        ]
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}
        
        call_msgs = feedback_prompt + [state_msg, user_msg]

        res = self.client.chat.completions.create(model=self.model, messages=call_msgs, temperature=0.5)

        return res.choices[0].message.content