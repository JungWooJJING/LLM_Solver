import json

from templates.prompting import CTFSolvePrompt
from utility.core_utility import Core

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

core = Core()

class InstructionAgent:
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
    
    def _collect_failed_commands(self, state_dict):
        failed_commands = []

        # results에서 실패한 명령어 수집
        results = state_dict.get("results", [])
        for result in results:
            if result.get("status") == "fail":
                execution_output = result.get("execution_output", "")
                # 명령어와 에러 추출
                if execution_output:
                    failed_commands.append({
                        "track_id": result.get("track_id", "unknown"),
                        "timestamp": result.get("timestamp", ""),
                        "output": execution_output[:500]  # 최대 500자만
                    })

        # vulnerability_tracks에서 실패한 명령어 수집
        tracks = state_dict.get("vulnerability_tracks", {})
        for track_id, track in tracks.items():
            consecutive_failures = track.get("consecutive_failures", 0)
            if consecutive_failures > 0:
                # 이 트랙의 최근 실패 정보
                failed_commands.append({
                    "track_id": track_id,
                    "vuln": track.get("vuln", "Unknown"),
                    "consecutive_failures": consecutive_failures,
                    "last_signals": track.get("signals", [])[-3:] if track.get("signals") else []
                })

        return failed_commands

    def _check_binary_constraints(self, state_dict):
        import subprocess
        import re

        binary_path = state_dict.get("binary_path", "")
        if not binary_path:
            return ""

        try:
            # file 명령어로 바이너리 정보 확인
            result = subprocess.run(
                ["file", binary_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return ""

            file_output = result.stdout.lower()

            constraints = []

            # FreeBSD 바이너리 감지
            if "freebsd" in file_output:
                constraints.append("CRITICAL: This is a FreeBSD binary - CANNOT be executed on Linux!")
                constraints.append("CRITICAL: Memory inspection (x/..., examine, etc.) requires EXECUTION - NOT POSSIBLE!")
                constraints.append("")
                constraints.append("MANDATORY: Use STATIC ANALYSIS ONLY:")
                constraints.append("   1. ghidra_decompile(function_address='0x...') - Get decompiled C code")
                constraints.append("   2. objdump_disassemble(start_address='0x...') - Get assembly code")
                constraints.append("   3. strings(binary_path) - Extract hardcoded strings")
                constraints.append("   4. readelf -a - Analyze ELF sections and symbols")
                constraints.append("")
                constraints.append("ABSOLUTELY FORBIDDEN (WILL ALWAYS FAIL):")
                constraints.append("   - gdb_debug with ANY memory commands (x/..., p, examine)")
                constraints.append("   - gdb_debug with 'run', 'start', 'break + run'")
                constraints.append("   - Dynamic analysis (requires execution)")
                constraints.append("   - pwntools execution")
                constraints.append("")
                constraints.append("WHY: FreeBSD uses /libexec/ld-elf.so.1 (not Linux's ld-linux.so)")
                constraints.append("         Memory is UNINITIALIZED without execution!")
                constraints.append("         Analysis MUST be purely static (code reading only)")

            # 32비트 바이너리 감지 (64비트 시스템에서 실행 시)
            elif "32-bit" in file_output and "x86-64" not in file_output:
                # 32비트 라이브러리 체크
                lib_check = subprocess.run(
                    ["dpkg", "--print-foreign-architectures"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if "i386" not in lib_check.stdout:
                    constraints.append("WARNING: 32-bit binary detected, but 32-bit libraries may not be available")
                    constraints.append("Consider using static analysis if execution fails")

            if constraints:
                header = "=" * 70
                return f"{header}\n" + "\n".join(constraints) + f"\n{header}"

        except Exception:
            pass

        return ""

    def _build_failure_context(self, failed_commands):
        if not failed_commands:
            return ""

        context_parts = [
            "IMPORTANT: Previous attempts have FAILED. Learn from these mistakes:",
            "=" * 60
        ]

        for i, failure in enumerate(failed_commands[-5:], 1):  # 최근 5개만
            context_parts.append(f"\nFailure #{i}:")
            context_parts.append(f"  Track: {failure.get('track_id', 'unknown')}")

            if "vuln" in failure:
                context_parts.append(f"  Vulnerability: {failure['vuln']}")
                context_parts.append(f"  Consecutive Failures: {failure.get('consecutive_failures', 0)}")

            if "output" in failure:
                context_parts.append(f"  Error Output: {failure['output'][:200]}...")

        context_parts.append("\n" + "=" * 60)
        context_parts.append("DO NOT repeat these failed approaches!")
        context_parts.append("Try a DIFFERENT method or tool!")
        context_parts.append("=" * 60)

        return "\n".join(context_parts)
        
    def run_instruction(self, prompt_query: str, state: str):
        prompt_instruction = [
            {"role": "developer", "content": CTFSolvePrompt.instruction_prompt},
        ]

        # ctx는 JSON 직렬화 불가능하므로 제외
        if isinstance(state, dict):
            state_for_json = {k: v for k, v in state.items() if k != "ctx"}
        else:
            state_for_json = state

        # 실패한 명령어들을 수집
        failed_commands = self._collect_failed_commands(state_for_json)

        # 바이너리 호환성 체크 및 제약사항 추가
        binary_constraints = self._check_binary_constraints(state_for_json)

        # 실패 이력을 프롬프트에 추가
        context_parts = []
        if binary_constraints:
            context_parts.append(binary_constraints)
        if failed_commands:
            context_parts.append(self._build_failure_context(failed_commands))

        if context_parts:
            prompt_query = "\n\n".join(context_parts) + "\n\n" + prompt_query

        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state_for_json, ensure_ascii=False)}
        user_msg = {"role" : "user", "content" : prompt_query}

        call_msgs = prompt_instruction + [state_msg, user_msg]
        
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