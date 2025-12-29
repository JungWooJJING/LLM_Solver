import json
import time

from templates.prompting import CTFSolvePrompt
from openai import OpenAI
import warnings
# google.generativeai FutureWarning 억제
warnings.filterwarnings("ignore", category=FutureWarning, message=".*google.generativeai.*")

try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
except ImportError:
    genai = None
    google_exceptions = None

class ParserAgent:
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model
        
        if model == "gpt-4o":
            self.client = OpenAI(api_key=api_key)
            self.is_gemini = False
        elif model == "gemini-1.5-flash" or model == "gemini-1.5-flash-latest" or model == "gemini-3-flash-preview":
            if genai is None:
                raise ImportError("google-generativeai package is required for Gemini. Install with: pip install google-generativeai")
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(model)
            self.is_gemini = True
        else:
            raise ValueError(f"Invalid model: {model}. Supported: gpt-4o, gemini-1.5-flash, gemini-1.5-flash-latest, gemini-3-flash-preview")
    
    def _generate_with_retry(self, generate_func, max_retries=3):
        """Rate limit 오류 발생 시 재시도하는 헬퍼 함수"""
        for attempt in range(max_retries):
            try:
                return generate_func()
            except Exception as e:
                if google_exceptions and isinstance(e, google_exceptions.ResourceExhausted):
                    # Rate limit 오류인 경우
                    error_str = str(e)
                    # retry_delay 추출 시도
                    retry_delay = 40  # 기본값 40초
                    if "retry in" in error_str.lower() or "retry_delay" in error_str.lower():
                        import re
                        delay_match = re.search(r'retry.*?(\d+\.?\d*)\s*s', error_str, re.IGNORECASE)
                        if delay_match:
                            retry_delay = float(delay_match.group(1)) + 5  # 여유 5초 추가
                    
                    if attempt < max_retries - 1:
                        print(f"Rate limit exceeded. Waiting {retry_delay}s before retry (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        raise
                else:
                    # 다른 오류는 즉시 전파
                    raise
        raise Exception("Max retries exceeded")
    
    def LLM_translation_run(self, prompt_query:str = "", state: str= ""):
        LLM_translation_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.parsing_LLM_translation},
        ]
        
        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}
        
        call_msgs = LLM_translation_prompt + [state_msg, user_msg]

        if self.is_gemini:
            # Gemini API 호출 - 시스템 프롬프트와 대화 분리
            system_parts = []
            user_parts = []
            
            for msg in call_msgs:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "developer" or role == "system":
                    system_parts.append(content)
                elif role == "user":
                    user_parts.append(content)
            
            system_instruction = "\n\n".join(system_parts) if system_parts else None
            user_content = "\n\n".join(user_parts) if user_parts else ""
            
            if system_instruction:
                try:
                    res = self._generate_with_retry(
                        lambda: self.client.generate_content(
                            user_content,
                            system_instruction=system_instruction
                        )
                    )
                except TypeError:
                    full_prompt = f"{system_instruction}\n\n---\n\n{user_content}"
                    res = self._generate_with_retry(
                        lambda: self.client.generate_content(full_prompt)
                    )
            else:
                res = self._generate_with_retry(
                    lambda: self.client.generate_content(user_content)
                )
            return res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content

    def Exploit_result_run(self, prompt_query:str = "", state: str="", scenario: str=""):
        exploit_translation_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.exploit_result_translation},
        ]
        
        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        exploit_msg = {"role": "developer", "content": "[Exploit Scenario]\n" + json.dumps(scenario, ensure_ascii=False)}
        user_msg  = {"role": "user", "content": prompt_query}
        
        call_msgs = exploit_translation_prompt + [state_msg, exploit_msg,user_msg]

        if self.is_gemini:
            # Gemini API 호출 - 시스템 프롬프트와 대화 분리
            system_parts = []
            user_parts = []
            
            for msg in call_msgs:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "developer" or role == "system":
                    system_parts.append(content)
                elif role == "user":
                    user_parts.append(content)
            
            system_instruction = "\n\n".join(system_parts) if system_parts else None
            user_content = "\n\n".join(user_parts) if user_parts else ""
            
            if system_instruction:
                try:
                    res = self._generate_with_retry(
                        lambda: self.client.generate_content(
                            user_content,
                            system_instruction=system_instruction
                        )
                    )
                except TypeError:
                    full_prompt = f"{system_instruction}\n\n---\n\n{user_content}"
                    res = self._generate_with_retry(
                        lambda: self.client.generate_content(full_prompt)
                    )
            else:
                res = self._generate_with_retry(
                    lambda: self.client.generate_content(user_content)
                )
            return res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content