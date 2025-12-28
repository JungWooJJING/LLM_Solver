import json

from templates.prompting import CTFSolvePrompt
from utility.core_utility import Core

from openai import OpenAI
import warnings
# google.generativeai FutureWarning 억제
warnings.filterwarnings("ignore", category=FutureWarning, message=".*google.generativeai.*")

try:
    import google.generativeai as genai
except ImportError:
    genai = None

core = Core()

class InstructionAgent:
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model
        
        if model == "gpt-4o":
            self.client = OpenAI(api_key=api_key)
            self.is_gemini = False
        elif model == "gemini-1.5-flash" or model == "gemini-1.5-flash-latest" or model == "gemini-3-flash-preview":
            if genai is None:
                raise ImportError("google-generativeai package is required for Gemini. Install with: pip install google-generativeai")
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(model)
            self.is_gemini = True
        else:
            raise ValueError(f"Invalid model: {model}. Supported: gpt-4o, gemini-1.5-flash, gemini-1.5-flash-latest, gemini-3-flash-preview")
    
    def _collect_failed_commands(self, state_dict):
        """실패한 명령어들을 state에서 수집"""
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
        """바이너리 실행 제약사항 체크 (OS, 아키텍처 등)"""
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
                constraints.append("🚫 CRITICAL: This is a FreeBSD binary - CANNOT be executed on Linux!")
                constraints.append("🚫 CRITICAL: Memory inspection (x/..., examine, etc.) requires EXECUTION - NOT POSSIBLE!")
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
        """실패 이력을 기반으로 컨텍스트 문자열 생성"""
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
            # Gemini API 호출 - 시스템 프롬프트와 대화 분리
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
            return res.text
        else:
            res = self.client.chat.completions.create(model=self.model, messages=call_msgs)
            return res.choices[0].message.content