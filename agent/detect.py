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

class DetectAgent:
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
        """새로운 google-genai SDK를 사용한 Gemini API 호출"""
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

    def detect_run(self, prompt_query: str):
        detect_prompt = [
            {"role": "developer", "content": CTFSolvePrompt.detect_prompt},
        ]

        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = detect_prompt + [user_msg]

        if self.is_gemini:
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
