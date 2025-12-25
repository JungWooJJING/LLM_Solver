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
                raise ImportError("google-genai package is required for Gemini. Install with: pip install google-genai")
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
                # Gemini API 호출 - 시스템 프롬프트와 대화 분리
                system_parts = []
                user_parts = []
                assistant_parts = []
                
                for msg in call_msgs:
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                    if role == "developer" or role == "system":
                        system_parts.append(content)
                    elif role == "user":
                        user_parts.append(content)
                    elif role == "assistant":
                        assistant_parts.append(content)
                
                system_instruction = "\n\n".join(system_parts) if system_parts else None
                # 대화 형식으로 변환 (few-shot 예제 포함)
                conversation_text = ""
                for i, user_content in enumerate(user_parts):
                    conversation_text += f"User: {user_content}\n"
                    if i < len(assistant_parts):
                        conversation_text += f"Model: {assistant_parts[i]}\n"
                
                if system_instruction:
                    try:
                        # system_instruction 파라미터 사용 (새로운 Gemini API)
                        res = self.client.generate_content(
                            conversation_text if conversation_text else user_parts[-1] if user_parts else "",
                            system_instruction=system_instruction
                        )
                    except TypeError:
                        # system_instruction을 지원하지 않으면 텍스트로 합침
                        full_prompt = f"{system_instruction}\n\n---\n\n{conversation_text if conversation_text else user_parts[-1] if user_parts else ''}"
                        res = self.client.generate_content(full_prompt)
                else:
                    res = self.client.generate_content(conversation_text if conversation_text else user_parts[-1] if user_parts else "")
                content = res.text
            else:
                # OpenAI API 호출
                res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
                content = res.choices[0].message.content
        except Exception:
            prompt_CoT[:] = self.compress.compress_history(prompt_CoT, ctx=ctx)
            call_msgs = prompt_CoT + [state_msg, user_msg]
            if self.is_gemini:
                # Gemini API 호출 - 시스템 프롬프트와 대화 분리
                system_parts = []
                user_parts = []
                assistant_parts = []
                
                for msg in call_msgs:
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                    if role == "developer" or role == "system":
                        system_parts.append(content)
                    elif role == "user":
                        user_parts.append(content)
                    elif role == "assistant":
                        assistant_parts.append(content)
                
                system_instruction = "\n\n".join(system_parts) if system_parts else None
                conversation_text = ""
                for i, user_content in enumerate(user_parts):
                    conversation_text += f"User: {user_content}\n"
                    if i < len(assistant_parts):
                        conversation_text += f"Model: {assistant_parts[i]}\n"
                
                if system_instruction:
                    try:
                        res = self.client.generate_content(
                            conversation_text if conversation_text else user_parts[-1] if user_parts else "",
                            system_instruction=system_instruction
                        )
                    except TypeError:
                        full_prompt = f"{system_instruction}\n\n---\n\n{conversation_text if conversation_text else user_parts[-1] if user_parts else ''}"
                        res = self.client.generate_content(full_prompt)
                else:
                    res = self.client.generate_content(conversation_text if conversation_text else user_parts[-1] if user_parts else "")
                content = res.text
            else:
                res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
                content = res.choices[0].message.content

        plan_CoT.extend([user_msg, {"role": "assistant", "content": content}])
        return content
    
    def _convert_messages_to_prompt(self, messages):
        """OpenAI messages 형식을 Gemini용으로 변환
        - system/developer 역할은 system_instruction으로 분리
        - user/assistant는 대화 형식으로 변환
        """
        system_instructions = []
        conversation_parts = []
        
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            if role == "developer" or role == "system":
                # 시스템 프롬프트는 별도로 수집
                system_instructions.append(content)
            elif role == "user":
                conversation_parts.append(("user", content))
            elif role == "assistant":
                conversation_parts.append(("model", content))
        
        # 시스템 프롬프트를 하나로 합침
        system_text = "\n\n".join(system_instructions) if system_instructions else None
        
        # 대화 형식으로 변환
        if conversation_parts:
            # Gemini는 첫 번째 메시지가 user여야 함
            if conversation_parts[0][0] == "user":
                # 시스템 프롬프트가 있으면 첫 user 메시지 앞에 추가
                if system_text:
                    full_prompt = f"{system_text}\n\n---\n\nUser: {conversation_parts[0][1]}"
                else:
                    full_prompt = f"User: {conversation_parts[0][1]}"
                
                # 나머지 대화 추가
                for i in range(1, len(conversation_parts)):
                    role, content = conversation_parts[i]
                    if role == "user":
                        full_prompt += f"\n\nUser: {content}"
                    elif role == "model":
                        full_prompt += f"\n\nModel: {content}"
                
                return full_prompt
            else:
                # 첫 메시지가 model이면 시스템 프롬프트만 반환
                return system_text if system_text else ""
        else:
            # 대화가 없으면 시스템 프롬프트만 반환
            return system_text if system_text else ""
    
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
            # Gemini API 호출 - 시스템 프롬프트와 대화 분리
            system_parts = []
            user_parts = []
            
            for msg in prompt_Cal:
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
                    # system_instruction을 지원하지 않으면 텍스트로 합침
                    full_prompt = f"{system_instruction}\n\n---\n\n{user_content}"
                    res = self.client.generate_content(full_prompt)
            else:
                res = self.client.generate_content(user_content)
            return res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=prompt_Cal)
            return res.choices[0].message.content
