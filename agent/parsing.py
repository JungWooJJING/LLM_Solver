import json
import time

from templates.prompting import CTFSolvePrompt
from openai import OpenAI
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

# 새로운 google-genai SDK 사용
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

class ParserAgent:
    def __init__(self, api_key: str, model: str = "gpt-5.2"):
        self.api_key = api_key
        self.model = model

        if model == "gpt-5.2":
            self.client = OpenAI(api_key=api_key)
            self.is_gemini = False
        elif model in ["gemini-1.5-flash", "gemini-1.5-flash-latest", "gemini-3-flash-preview"]:
            if genai is None:
                raise ImportError("google-genai package is required for Gemini. Install with: pip install google-genai")
            self.client = genai.Client(api_key=api_key)
            self.gemini_model = model
            self.is_gemini = True
        else:
            raise ValueError(f"Invalid model: {model}. Supported: gpt-5.2, gemini-1.5-flash, gemini-1.5-flash-latest, gemini-3-flash-preview")
    
    def _generate_with_retry(self, generate_func, max_retries=5):
        """Rate limit 오류 시 지수 백오프로 재시도"""
        import re
        base_delay = 60  # 기본 대기 시간 60초

        for attempt in range(max_retries):
            try:
                return generate_func()
            except Exception as e:
                error_str = str(e).lower()
                # Rate limit 또는 리소스 소진 오류 감지
                if "resource" in error_str or "rate" in error_str or "quota" in error_str or "429" in error_str:
                    # API 응답에서 권장 대기 시간 추출
                    retry_delay = base_delay
                    delay_match = re.search(r'retry.*?(\d+\.?\d*)\s*s', str(e), re.IGNORECASE)
                    if delay_match:
                        retry_delay = float(delay_match.group(1)) + 10  # 여유분 10초 추가

                    # 지수 백오프: 실패할수록 대기 시간 증가
                    retry_delay = max(retry_delay, base_delay * (1.5 ** attempt))
                    retry_delay = min(retry_delay, 300)  # 최대 5분

                    if attempt < max_retries - 1:
                        print(f"Rate limit exceeded. Waiting {retry_delay:.1f}s before retry (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        raise
                else:
                    raise
        raise Exception("Max retries exceeded")

    def _call_gemini(self, system_instruction: str, user_content: str):
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_instruction if system_instruction else None,
        )

        response = self.client.models.generate_content(
            model=self.gemini_model,
            contents=user_content,
            config=config
        )
        return response.text

    def LLM_translation_run(self, prompt_query: str = "", state: str = ""):
        LLM_translation_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.parsing_LLM_translation},
        ]

        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state

        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = LLM_translation_prompt + [state_msg, user_msg]

        if self.is_gemini:
            # 새로운 google-genai SDK 사용
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

            return self._generate_with_retry(
                lambda: self._call_gemini(system_instruction, user_content)
            )
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content

    def Exploit_result_run(self, prompt_query: str = "", state: str = "", scenario: str = ""):
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
        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = exploit_translation_prompt + [state_msg, exploit_msg, user_msg]

        if self.is_gemini:
            # 새로운 google-genai SDK 사용
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

            return self._generate_with_retry(
                lambda: self._call_gemini(system_instruction, user_content)
            )
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content