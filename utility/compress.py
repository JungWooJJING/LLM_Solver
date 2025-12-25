import os, json, re

from openai import OpenAI
import warnings
# google.generativeai FutureWarning 억제
warnings.filterwarnings("ignore", category=FutureWarning, message=".*google.generativeai.*")

try:
    from google import genai
except ImportError:
    try:
        import google.generativeai as genai
    except ImportError:
        genai = None
from templates.prompting import CTFSolvePrompt
from rich.console import Console
from utility.core_utility import Core
core = Core()

console = Console()

class Compress:
    def __init__(self, api_key: str, model: str = "gpt-5.2"):
        self.api_key = api_key
        self.model = model
        
        if model == "gpt-5.2":
            self.client = OpenAI(api_key=api_key)
            self.is_gemini = False
        elif model == "gemini-3-flash-preview":
            if genai is None:
                raise ImportError("google-genai package is required for Gemini. Install with: pip install google-genai")
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

    def compress_state(self) -> dict:
        if not os.path.exists("state.json"):
            raise FileNotFoundError("state.json not found")

        state = core.load_json(fileName="state.json", default={})

        prompt = [
            {"role":"developer","content": CTFSolvePrompt.compress_state},
            {"role":"user","content": json.dumps(state, ensure_ascii=False)},
        ]

        try:
            if self.is_gemini:
                # Gemini API 호출 - 시스템 프롬프트와 대화 분리
                system_parts = []
                user_parts = []
                
                for msg in prompt:
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
                        res = self.client.generate_content(
                            user_content,
                            system_instruction=system_instruction
                        )
                    except TypeError:
                        full_prompt = f"{system_instruction}\n\n---\n\n{user_content}"
                        res = self.client.generate_content(full_prompt)
                else:
                    res = self.client.generate_content(user_content)
                raw = res.text
            else:
                res = self.client.chat.completions.create(model=self.model, messages=prompt)
                raw = res.choices[0].message.content
            compressed_state = json.loads(raw)
            
            # JSON 파일 저장 제거됨
            console.print(f"State compressed: {len(json.dumps(state))} → {len(json.dumps(compressed_state))} chars", style="green")
            
            return compressed_state
        except Exception as e:
            console.print(f"Error compressing state: {e}", style="red")
            return state

        
    def compress_plan(self) -> dict:
        if not os.path.exists("plan.json"):
            raise FileNotFoundError("plan.json not found")

        plan = core.load_json(fileName="plan.json", default={})

        prompt = [
            {"role":"developer","content": CTFSolvePrompt.compress_plan},
            {"role":"user","content": json.dumps(plan, ensure_ascii=False)},
        ]

        try:
            if self.is_gemini:
                # Gemini API 호출 - 시스템 프롬프트와 대화 분리
                system_parts = []
                user_parts = []
                
                for msg in prompt:
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
                        res = self.client.generate_content(
                            user_content,
                            system_instruction=system_instruction
                        )
                    except TypeError:
                        full_prompt = f"{system_instruction}\n\n---\n\n{user_content}"
                        res = self.client.generate_content(full_prompt)
                else:
                    res = self.client.generate_content(user_content)
                raw = res.text
            else:
                res = self.client.chat.completions.create(model=self.model, messages=prompt)
                raw = res.choices[0].message.content
            compressed_plan = json.loads(raw)
            
            # JSON 파일 저장 제거됨
            console.print(f"Plan compressed: {len(json.dumps(plan))} → {len(json.dumps(compressed_plan))} chars", style="green")
            
            return compressed_plan
        except Exception as e:
            console.print(f"Error compressing plan: {e}", style="red")
            return plan


    def compress_messages(self, history: list) -> list:
        prompt = [
            {"role":"developer","content": CTFSolvePrompt.compress_history},
            {"role":"user","content": json.dumps(history, ensure_ascii=False)},
        ]
        if self.is_gemini:
            prompt_text = self._convert_messages_to_prompt(prompt)
            res = self.client.generate_content(prompt_text)
            raw = res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=prompt)
            raw = res.choices[0].message.content
        payload = json.loads(raw)
        msgs = payload.get("messages")
        if not (isinstance(msgs, list) and all(isinstance(m, dict) and
                                            m.get("role") in {"system","developer","user","assistant"} and
                                            isinstance(m.get("content",""), str)
                                            for m in msgs)):
            raise ValueError("invalid messages[] from compressor")
        return msgs

    def compress_history(self, history: list, ctx):
        console.print("=== Compress state.json ===", style="bold green")
        self.compress_state()

        console.print("=== Compress plan.json ===", style="bold green")
        self.compress_plan()

        console.print("=== Compress history query ===", style="bold green")
        try:
            return self.compress_messages(history)
        except Exception:
            return history