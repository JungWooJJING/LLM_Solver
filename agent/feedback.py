import json

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

class FeedbackAgent:
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

    def _call_gemini(self, system_instruction: str, user_content: str):
        from google.genai import types
        from rich.console import Console
        console = Console()

        config = types.GenerateContentConfig(
            system_instruction=system_instruction if system_instruction else None,
        )

        response = self.client.models.generate_content(
            model=self.gemini_model,
            contents=user_content,
            config=config
        )

        # 디버깅: 응답 상태 출력
        if response is None:
            console.print("  [API] Gemini returned None", style="bold red")
            return '{"error": "Gemini returned None"}'

        if hasattr(response, 'candidates') and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, 'finish_reason'):
                finish_reason = str(candidate.finish_reason)
                if 'SAFETY' in finish_reason.upper() or 'BLOCK' in finish_reason.upper():
                    console.print(f"  [API] Response blocked: {finish_reason}", style="bold red")
                    return '{"error": "blocked"}'

        text = response.text
        if not text or text.strip() == "":
            console.print("  [API] Empty response from Gemini", style="bold yellow")
            return '{"error": "empty response"}'

        console.print(f"  [API] Response OK ({len(text)} chars)", style="dim green")
        return text

    def feedback_run(self, prompt_query: str = "", state: str = ""):
        feedback_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.feedback_prompt}
        ]

        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state

        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = feedback_prompt + [state_msg, user_msg]

        if self.is_gemini:
            # 새로운 google-genai SDK 사용
            system_parts = []
            user_parts = []

            for msg in call_msgs:
                role = msg.get("role", "user")
                content_text = msg.get("content", "")
                if role == "developer" or role == "system":
                    system_parts.append(content_text)
                elif role == "user":
                    user_parts.append(content_text)

            system_instruction = "\n\n".join(system_parts) if system_parts else None
            user_content = "\n\n".join(user_parts) if user_parts else ""

            return self._call_gemini(system_instruction, user_content)
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content

    def exploit_feedback_run(self, prompt_query: str = "", state: str = "", scenario: str = ""):
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
        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = feedback_prompt + [state_msg, exploit_msg, user_msg]

        if self.is_gemini:
            # 새로운 google-genai SDK 사용
            system_parts = []
            user_parts = []

            for msg in call_msgs:
                role = msg.get("role", "user")
                content_text = msg.get("content", "")
                if role == "developer" or role == "system":
                    system_parts.append(content_text)
                elif role == "user":
                    user_parts.append(content_text)

            system_instruction = "\n\n".join(system_parts) if system_parts else None
            user_content = "\n\n".join(user_parts) if user_parts else ""

            return self._call_gemini(system_instruction, user_content)
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content
