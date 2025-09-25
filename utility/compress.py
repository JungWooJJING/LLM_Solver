import os, json, re

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

console = Console()

class Compress:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def compress_state(self) -> dict:
        if not os.path.exists("state.json"):
            raise FileNotFoundError("state.json not found")
        
        with open("state.json","r",encoding="utf-8") as f:
            state = json.load(f)
            
        # out = ctx.parsing.run_prompt_state_compress(json.dumps(state, ensure_ascii=False))
        # try:
        #     obj = json.loads(out) if isinstance(out, str) else out
        # except Exception as e:
        #     raise ValueError(f"state compressor returned invalid JSON: {e}")
        
        # if not isinstance(obj, dict):
        #     raise TypeError("state compressor returned non-dict")
        # with open("state.json","w",encoding="utf-8") as f:
        #     json.dump(obj, f, ensure_ascii=False, indent=2)
        # return obj

    def compress_messages(self, history: list, client, model) -> list:
        prompt = [
            {"role":"developer","content": CTFSolvePrompt.compress_history},
            {"role":"user","content": json.dumps(history, ensure_ascii=False)},
        ]
        res = client.chat.completions.create(model=model, messages=prompt)
        raw = res.choices[0].message.content
        payload = json.loads(raw)
        msgs = payload.get("messages")
        if not (isinstance(msgs, list) and all(isinstance(m, dict) and
                                            m.get("role") in {"system","developer","user","assistant"} and
                                            isinstance(m.get("content",""), str)
                                            for m in msgs)):
            raise ValueError("invalid messages[] from compressor")
        return msgs

    def compress_history(self, history: list):
        console.print("Compress state.json", style="bold green")
        self.compress_state()
        console.print("Compress history query", style="bold green")
        try:
            return self.compress_messages(history, self.client, self.model)
        except Exception:
            return history