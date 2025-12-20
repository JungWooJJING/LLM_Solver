import json

from templates.prompting import CTFSolvePrompt
from openai import OpenAI

class FeedbackAgent:
    def __init__(self, api_key: str, model: str = "gpt-5.2"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def feedback_run(self, prompt_query:str = "", state: str = ""):
        feedback_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.feedback_prompt}
        ]
        
        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}
        
        call_msgs = feedback_prompt + [state_msg, user_msg]

        res = self.client.chat.completions.create(model=self.model, messages=call_msgs)

        return res.choices[0].message.content

    def exploit_feedback_run(self, prompt_query:str = "", state: str = "", scenario: str = ""):
        feedback_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.exploit_feedback}
        ]
        
        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        exploit_msg = {"role": "developer", "content": "[Exploit Scenario]\n" + json.dumps(scenario, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}
        
        call_msgs = feedback_prompt + [state_msg, exploit_msg,user_msg]

        res = self.client.chat.completions.create(model=self.model, messages=call_msgs)

        return res.choices[0].message.content