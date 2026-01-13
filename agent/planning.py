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
warnings.filterwarnings("ignore", category=FutureWarning)

# 새로운 google-genai SDK 사용
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

from templates.prompting import CTFSolvePrompt
from rich.console import Console
from utility.build_query import build_query
from utility.core_utility import Core
from utility.fewshot_selector import select_fewshots, build_fewshot_messages, get_category_hints

# Ghidra API (선택적)
try:
    from utility.ghidra import ghdira_API
except (ImportError, ModuleNotFoundError):
    def ghdira_API(*args, **kwargs):
        raise RuntimeError("Ghidra is not available. Please install Ghidra and set GHIDRA_INSTALL_DIR.")

console = Console()
core = Core()

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


def build_dynamic_prompt_CoT(category: str, description: str = "", signals: list = None):
    # 기본 시스템 프롬프트
    base_prompt = CTFSolvePrompt.planning_prompt_CoT

    # 카테고리별 힌트 추가
    category_hints = get_category_hints(category)
    if category_hints:
        base_prompt = base_prompt + "\n" + category_hints

    messages = [{"role": "developer", "content": base_prompt}]

    # 동적으로 선택된 few-shot 추가
    fewshot_messages = build_fewshot_messages(category, description, signals, max_examples=3)
    messages.extend(fewshot_messages)

    return messages


def build_dynamic_plan_CoT(category: str, description: str = "", signals: list = None):
    base_prompt = CTFSolvePrompt.plan_CoT

    category_hints = get_category_hints(category)
    if category_hints:
        base_prompt = base_prompt + "\n" + category_hints

    messages = [{"role": "developer", "content": base_prompt}]

    fewshot_messages = build_fewshot_messages(category, description, signals, max_examples=3)
    messages.extend(fewshot_messages)

    return messages

class PlanningAgent:
    def __init__(self, api_key: str, model: str):
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
        """Rate limit 및 서버 오류 시 지수 백오프로 재시도"""
        import time
        import re
        base_delay = 10  # 기본 대기 시간 10초

        for attempt in range(max_retries):
            try:
                return generate_func()
            except Exception as e:
                error_str = str(e).lower()
                error_code = ""
                # 에러 코드 추출 (503, 429 등)
                code_match = re.search(r'(\d{3})', str(e))
                if code_match:
                    error_code = code_match.group(1)
                
                # 일시적 오류 감지 (503, 429, 500, 502, 504 등)
                is_temporary_error = (
                    "503" in error_code or "429" in error_code or 
                    "500" in error_code or "502" in error_code or "504" in error_code or
                    "resource" in error_str or "rate" in error_str or 
                    "quota" in error_str or "overloaded" in error_str or
                    "unavailable" in error_str or "timeout" in error_str
                )
                
                if is_temporary_error:
                    # API 응답에서 권장 대기 시간 추출
                    retry_delay = base_delay
                    delay_match = re.search(r'retry.*?(\d+\.?\d*)\s*s', str(e), re.IGNORECASE)
                    if delay_match:
                        retry_delay = float(delay_match.group(1)) + 5  # 여유분 5초 추가

                    # 지수 백오프: 실패할수록 대기 시간 증가
                    retry_delay = max(retry_delay, base_delay * (1.5 ** attempt))
                    retry_delay = min(retry_delay, 120)  # 최대 2분

                    if attempt < max_retries - 1:
                        console.print(f"API 서버 오류 ({error_code if error_code else 'temporary'}). {retry_delay:.1f}초 후 재시도 중... (시도 {attempt + 1}/{max_retries})", style="yellow")
                        time.sleep(retry_delay)
                        continue
                    else:
                        console.print(f"최대 재시도 횟수({max_retries}) 초과. API 서버가 과부하 상태입니다.", style="bold red")
                        raise
                else:
                    # 일시적 오류가 아니면 즉시 재시도하지 않음
                    raise
        raise Exception("Max retries exceeded")

    def _call_gemini(self, system_instruction: str, user_content: str):
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_instruction if system_instruction else None,
        )

        def _generate():
            response = self.client.models.generate_content(
                model=self.gemini_model,
                contents=user_content,
                config=config
            )

            # 디버깅: 응답 상태 출력
            if response is None:
                console.print("  [API] Gemini returned None", style="bold red")
                return '{"error": "Gemini returned None"}'

            # safety filter 확인
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'finish_reason'):
                    finish_reason = str(candidate.finish_reason)
                    if 'SAFETY' in finish_reason.upper() or 'BLOCK' in finish_reason.upper():
                        console.print(f"  [API] Response blocked: {finish_reason}", style="bold red")
                        return '{"error": "blocked", "reason": "' + finish_reason + '"}'

            text = response.text
            if not text or text.strip() == "":
                console.print("  [API] Empty response from Gemini", style="bold yellow")
                return '{"error": "empty response"}'

            console.print(f"  [API] Response OK ({len(text)} chars)", style="dim green")
            return text

        # 재시도 로직으로 감싸기
        return self._generate_with_retry(_generate)
        
        
    def run_CoT(self, prompt_query: str, ctx, state: dict = None):
        # state가 제공되면 사용, 없으면 state.json에서 로드
        if state is None:
            state = core.load_json("state.json", default="")

        # 카테고리와 설명 추출
        category = "misc"
        description = ""
        signals = state.get("signals", [])

        if state.get("challenge") and len(state["challenge"]) > 0:
            challenge = state["challenge"][0]
            category = challenge.get("category", "misc").lower()
            description = challenge.get("description", "")

        # 동적으로 프롬프트 생성 (카테고리별 few-shot 선택)
        prompt_CoT = build_dynamic_prompt_CoT(category, description, signals)

        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg = {"role": "user", "content": prompt_query}

        call_msgs = prompt_CoT + [state_msg, user_msg]

        try:
            if self.is_gemini:
                # 새로운 google-genai SDK 사용
                system_parts = []
                user_parts = []
                assistant_parts = []

                for msg in call_msgs:
                    role = msg.get("role", "user")
                    content_text = msg.get("content", "")
                    if role == "developer" or role == "system":
                        system_parts.append(content_text)
                    elif role == "user":
                        user_parts.append(content_text)
                    elif role == "assistant":
                        assistant_parts.append(content_text)

                system_instruction = "\n\n".join(system_parts) if system_parts else None
                # 대화 형식으로 변환 (few-shot 예제 포함)
                conversation_text = ""
                for i, user_content in enumerate(user_parts):
                    conversation_text += f"User: {user_content}\n"
                    if i < len(assistant_parts):
                        conversation_text += f"Model: {assistant_parts[i]}\n"

                user_content = conversation_text if conversation_text else (user_parts[-1] if user_parts else "")
                content = self._call_gemini(system_instruction, user_content)
            else:
                # OpenAI API 호출
                res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
                content = res.choices[0].message.content
        except Exception as e:
            # API 호출 실패 시 에러 로깅 후 재시도 없이 에러 전파
            console.print(f"Error in CoT API call: {e}", style="bold red")
            raise

        # 대화 히스토리는 state.results에 저장되므로 별도 관리 불필요
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
            # 새로운 google-genai SDK 사용
            system_parts = []
            user_parts = []

            for msg in prompt_Cal:
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
            res = self.client.chat.completions.create(model=self.model, messages=prompt_Cal)
            return res.choices[0].message.content
