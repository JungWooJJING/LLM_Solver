import os, json, re

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console
from utility.core_utility import Core
core = Core()

console = Console()

class Compress:
    def __init__(self, api_key: str, model: str = "gpt-5.2"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def compress_state(self) -> dict:
        if not os.path.exists("state.json"):
            raise FileNotFoundError("state.json not found")

        state = core.load_json(fileName="state.json", default={})

        prompt = [
            {"role":"developer","content": CTFSolvePrompt.compress_state},
            {"role":"user","content": json.dumps(state, ensure_ascii=False)},
        ]

        try:
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