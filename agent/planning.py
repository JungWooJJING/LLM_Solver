import os
import json

# Ghidra는 선택적 의존성 - 경로가 있으면 시작, 없으면 건너뛰기
try:
    import pyghidra
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    
    if os.path.exists(ghidra_dir):
        os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
        pyghidra.start()
    else:
        print(f"Warning: Ghidra not found at {ghidra_dir}. --ghidra option will not be available.")
        print("Set GHIDRA_INSTALL_DIR environment variable if you want to use Ghidra features.")
except ImportError:
    print("Warning: pyghidra not installed. --ghidra option will not be available.")
except Exception as e:
    print(f"Warning: Failed to start Ghidra: {e}. --ghidra option will not be available.")

from openai import OpenAI
try:
    import google.generativeai as genai
except ImportError:
    try:
        from google import genai
    except ImportError:
        genai = None

from templates.prompting import CTFSolvePrompt, few_Shot
from rich.console import Console
from utility.build_query import build_query
from utility.core_utility import Core
from utility.compress import Compress

# Ghidra API (선택적)
try:
    from utility.ghidra import ghdira_API
except (ImportError, ModuleNotFoundError):
    def ghdira_API(*args, **kwargs):
        raise RuntimeError("Ghidra is not available. Please install Ghidra and set GHIDRA_INSTALL_DIR.")

console = Console()
core = Core()
FEWSHOT = few_Shot()

DEFAULT_STATE = {
    "challenge": [],
    "scenario": [],
    "constraints": ["no brute-force > 1000"],
    "env": {},
    "selected": {},
    "results": []
}

DEFAULT_PLAN = {
    "todos": [],
    "runs": [],
    "seen_cmd_hashes": [],
    "artifacts": {},
    "backlog": []
}

prompt_CoT = [
    {"role": "developer", "content": CTFSolvePrompt.planning_prompt_CoT},
    {"role": "user", "content": FEWSHOT.web_SQLI},
    {"role": "user", "content": FEWSHOT.web_SSTI},
    {"role": "user", "content": FEWSHOT.forensics_PCAP},
    {"role": "user", "content": FEWSHOT.stack_BOF},
    {"role": "user", "content": FEWSHOT.rev_CheckMapping},
]

plan_CoT = [
    {"role": "developer", "content": CTFSolvePrompt.plan_CoT},
    {"role": "user", "content": FEWSHOT.web_SQLI},
    {"role": "user", "content": FEWSHOT.web_SSTI},
    {"role": "user", "content": FEWSHOT.forensics_PCAP},
    {"role": "user", "content": FEWSHOT.stack_BOF},
    {"role": "user", "content": FEWSHOT.rev_CheckMapping},
]

class PlanningAgent:
    def __init__(self, api_key: str, model: str):
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
        
        self.compress = Compress(api_key=api_key, model=model)
        
    def run_CoT(self, prompt_query: str, ctx, state: dict = None):
        global prompt_CoT

        if not isinstance(globals().get("prompt_CoT"), list):
            prompt_CoT = []

        # state가 제공되면 사용, 없으면 state.json에서 로드
        if state is None:
            state = core.load_json("state.json", default="")
        else:
            # 필터링된 state가 전달된 경우 그대로 사용
            pass
        
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = prompt_CoT + [state_msg, user_msg]

        try:
            if self.is_gemini:
                # Gemini API 호출
                prompt_text = self._convert_messages_to_prompt(call_msgs)
                res = self.client.generate_content(prompt_text)
                content = res.text
            else:
                # OpenAI API 호출
                res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
                content = res.choices[0].message.content
        except Exception:
            prompt_CoT[:] = self.compress.compress_history(prompt_CoT, ctx=ctx)
            call_msgs = prompt_CoT + [state_msg, user_msg]
            if self.is_gemini:
                prompt_text = self._convert_messages_to_prompt(call_msgs)
                res = self.client.generate_content(prompt_text)
                content = res.text
            else:
                res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
                content = res.choices[0].message.content

        plan_CoT.extend([user_msg, {"role": "assistant", "content": content}])
        return content
    
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
    
    def run_Cal(self, prompt_query: str, state: dict = None):
        prompt_Cal = [
            {"role": "developer", "content": CTFSolvePrompt.planning_prompt_Cal},
        ]
        
        # state가 제공되면 STATE 메시지에 추가
        if state is not None:
            state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
            prompt_Cal.append(state_msg)
        
        prompt_Cal.append({"role": "user", "content": prompt_query})
        
        if self.is_gemini:
            prompt_text = self._convert_messages_to_prompt(prompt_Cal)
            res = self.client.generate_content(prompt_text)
            return res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=prompt_Cal)
            return res.choices[0].message.content
