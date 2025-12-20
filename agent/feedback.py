import json

from templates.prompting import CTFSolvePrompt
from openai import OpenAI
try:
    import google.generativeai as genai
except ImportError:
    genai = None

class FeedbackAgent:
    def __init__(self, api_key: str, model: str = "gpt-5.2"):
        self.api_key = api_key
        self.model = model
        
        if model == "gpt-5.2":
            self.client = OpenAI(api_key=api_key)
            self.is_gemini = False
        elif model == "gemini-3-flash-preview":
            if genai is None:
                raise ImportError("google-generativeai package is required for Gemini. Install with: pip install google-generativeai")
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(model)
            self.is_gemini = True
        else:
            raise ValueError(f"Invalid model: {model}. Supported: gpt-5.2, gemini-3-flash-preview")
    
    def _convert_messages_to_prompt(self, messages):
        """OpenAI messages 형식을 Gemini prompt 텍스트로 변환"""
        prompt_parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            if role == "developer" or role == "system":
                prompt_parts.append(f"[System/Developer]\n{content}\n")
            elif role == "user":
                prompt_parts.append(f"[User]\n{content}\n")
            elif role == "assistant":
                prompt_parts.append(f"[Assistant]\n{content}\n")
        
        return "\n".join(prompt_parts)
        
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

        if self.is_gemini:
            prompt_text = self._convert_messages_to_prompt(call_msgs)
            res = self.client.generate_content(prompt_text)
            return res.text
        else:
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

        if self.is_gemini:
            prompt_text = self._convert_messages_to_prompt(call_msgs)
            res = self.client.generate_content(prompt_text)
            return res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content