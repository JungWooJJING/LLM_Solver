import os
import subprocess
import re
from typing import Dict, List, Any, Optional
from rich.console import Console

console = Console()


def run_command(cmd: str, timeout: int = 30) -> tuple:
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def analyze_pwnable(binary_path: str) -> Dict[str, Any]:
    analysis = {
        "checksec": {},
        "file_info": "",
        "symbols": [],
        "interesting_functions": [],
        "strings_hints": [],
        "suggested_vuln": []
    }

    if not binary_path or not os.path.exists(binary_path):
        return analysis

    # 1. file 명령어
    stdout, _, _ = run_command(f"file '{binary_path}'")
    analysis["file_info"] = stdout.strip()

    # 2. checksec
    stdout, _, _ = run_command(f"checksec --file='{binary_path}' 2>/dev/null")
    if stdout:
        analysis["checksec"]["raw"] = stdout.strip()
        # 파싱
        if "NX enabled" in stdout or "NX            : enabled" in stdout.lower():
            analysis["checksec"]["nx"] = True
        else:
            analysis["checksec"]["nx"] = False
        if "Canary found" in stdout or "canary" in stdout.lower() and "enabled" in stdout.lower():
            analysis["checksec"]["canary"] = True
        else:
            analysis["checksec"]["canary"] = False
        if "PIE enabled" in stdout or "PIE           : enabled" in stdout.lower():
            analysis["checksec"]["pie"] = True
        else:
            analysis["checksec"]["pie"] = False

    # 3. 심볼 테이블에서 흥미로운 함수 찾기
    stdout, _, _ = run_command(f"nm '{binary_path}' 2>/dev/null | grep -E 'win|shell|flag|system|exec|gets|strcpy|sprintf|scanf'")
    if stdout:
        for line in stdout.strip().split('\n'):
            if line:
                analysis["symbols"].append(line.strip())
                # win 함수 감지
                if 'win' in line.lower() or 'shell' in line.lower() or 'flag' in line.lower():
                    analysis["interesting_functions"].append(line.strip())

    # 4. 위험한 함수 사용 감지
    stdout, _, _ = run_command(f"objdump -d '{binary_path}' 2>/dev/null | grep -E '<gets@|<strcpy@|<sprintf@|<scanf@|<strcat@'")
    if stdout:
        dangerous_funcs = set()
        for line in stdout.strip().split('\n'):
            if '<gets@' in line:
                dangerous_funcs.add("gets")
            if '<strcpy@' in line:
                dangerous_funcs.add("strcpy")
            if '<sprintf@' in line:
                dangerous_funcs.add("sprintf")
            if '<scanf@' in line:
                dangerous_funcs.add("scanf")
            if '<strcat@' in line:
                dangerous_funcs.add("strcat")

        if dangerous_funcs:
            analysis["suggested_vuln"].append({
                "type": "Buffer Overflow",
                "evidence": f"Dangerous functions detected: {', '.join(dangerous_funcs)}",
                "confidence": "high"
            })

    # 5. format string 감지
    stdout, _, _ = run_command(f"objdump -d '{binary_path}' 2>/dev/null | grep -B5 '<printf@' | grep -v 'format'")
    if stdout and 'printf' in stdout:
        # printf 직접 호출 패턴 감지
        analysis["suggested_vuln"].append({
            "type": "Format String",
            "evidence": "printf() usage detected - verify if user input is passed directly",
            "confidence": "medium"
        })

    # 6. Heap 관련 함수 감지 (malloc, free, calloc, realloc)
    stdout, _, _ = run_command(f"objdump -d '{binary_path}' 2>/dev/null | grep -E '<malloc@|<free@|<calloc@|<realloc@'")
    if stdout:
        heap_funcs = set()
        malloc_count = stdout.count('<malloc@')
        free_count = stdout.count('<free@')

        if '<malloc@' in stdout:
            heap_funcs.add("malloc")
        if '<free@' in stdout:
            heap_funcs.add("free")
        if '<calloc@' in stdout:
            heap_funcs.add("calloc")
        if '<realloc@' in stdout:
            heap_funcs.add("realloc")

        if heap_funcs:
            analysis["heap_info"] = {
                "functions": list(heap_funcs),
                "malloc_count": malloc_count,
                "free_count": free_count
            }

            # UAF 가능성 감지: malloc과 free 둘 다 있으면
            if "malloc" in heap_funcs and "free" in heap_funcs:
                analysis["suggested_vuln"].append({
                    "type": "Heap Vulnerability (UAF/Double-Free)",
                    "evidence": f"Heap functions detected: {', '.join(heap_funcs)} (malloc:{malloc_count}, free:{free_count})",
                    "confidence": "medium",
                    "hints": [
                        "Check if freed pointers are NULLed",
                        "Look for chunk size constraints in alloc functions",
                        "Identify if same-sized chunks from different types can overlap"
                    ]
                })

    # 7. strings에서 힌트 찾기
    stdout, _, _ = run_command(f"strings '{binary_path}' 2>/dev/null | grep -iE 'flag|password|secret|admin|root|shell|bin/sh' | head -10")
    if stdout:
        for line in stdout.strip().split('\n'):
            if line:
                analysis["strings_hints"].append(line.strip())

    return analysis


def analyze_web(url: str, source_path: str = "") -> Dict[str, Any]:
    analysis = {
        "url_info": {},
        "source_files": [],
        "potential_vulns": [],
        "endpoints": [],
        "technologies": []
    }

    # URL 파싱
    if url:
        analysis["url_info"]["url"] = url
        # 기본 연결 테스트 (curl)
        stdout, stderr, rc = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' '{url}' 2>/dev/null", timeout=10)
        if rc == 0:
            analysis["url_info"]["status"] = stdout.strip()

    # 소스 파일 분석
    if source_path and os.path.exists(source_path):
        if os.path.isdir(source_path):
            # 디렉토리인 경우 파일 목록
            stdout, _, _ = run_command(f"find '{source_path}' -type f -name '*.py' -o -name '*.php' -o -name '*.js' -o -name '*.html' 2>/dev/null | head -20")
            if stdout:
                analysis["source_files"] = stdout.strip().split('\n')

            # 기술 스택 감지
            if any('.py' in f for f in analysis["source_files"]):
                analysis["technologies"].append("Python")
                # Flask/Django 감지
                stdout, _, _ = run_command(f"grep -r 'from flask' '{source_path}' 2>/dev/null | head -1")
                if stdout:
                    analysis["technologies"].append("Flask")
                stdout, _, _ = run_command(f"grep -r 'from django' '{source_path}' 2>/dev/null | head -1")
                if stdout:
                    analysis["technologies"].append("Django")

            if any('.php' in f for f in analysis["source_files"]):
                analysis["technologies"].append("PHP")

            # SQL 쿼리 감지
            stdout, _, _ = run_command(f"grep -r -E 'SELECT|INSERT|UPDATE|DELETE|query\\(' '{source_path}' 2>/dev/null | head -5")
            if stdout:
                analysis["potential_vulns"].append({
                    "type": "SQL Injection",
                    "evidence": "SQL queries detected in source code",
                    "confidence": "medium"
                })

            # Template 사용 감지
            stdout, _, _ = run_command(f"grep -r -E 'render_template|render_template_string|Jinja|Twig' '{source_path}' 2>/dev/null | head -3")
            if stdout:
                if 'render_template_string' in stdout:
                    analysis["potential_vulns"].append({
                        "type": "SSTI",
                        "evidence": "render_template_string() detected - potential SSTI",
                        "confidence": "high"
                    })

            # 파일 포함 감지
            stdout, _, _ = run_command(f"grep -r -E 'include\\(|require\\(|file_get_contents|open\\(' '{source_path}' 2>/dev/null | head -3")
            if stdout:
                analysis["potential_vulns"].append({
                    "type": "LFI/Path Traversal",
                    "evidence": "File operations detected - check for path validation",
                    "confidence": "medium"
                })

        elif os.path.isfile(source_path):
            analysis["source_files"] = [source_path]

    return analysis


def analyze_reversing(binary_path: str) -> Dict[str, Any]:
    analysis = {
        "file_info": "",
        "entry_point": "",
        "imports": [],
        "strings_hints": [],
        "anti_debug": [],
        "crypto_hints": []
    }

    if not binary_path or not os.path.exists(binary_path):
        return analysis

    # 1. file 명령어
    stdout, _, _ = run_command(f"file '{binary_path}'")
    analysis["file_info"] = stdout.strip()

    # 2. entry point
    stdout, _, _ = run_command(f"readelf -h '{binary_path}' 2>/dev/null | grep 'Entry point'")
    if stdout:
        analysis["entry_point"] = stdout.strip()

    # 3. imports
    stdout, _, _ = run_command(f"objdump -T '{binary_path}' 2>/dev/null | grep -E 'strcmp|memcmp|strlen|strncmp' | head -10")
    if stdout:
        for line in stdout.strip().split('\n'):
            if line:
                analysis["imports"].append(line.strip())

    # 4. anti-debug 감지
    stdout, _, _ = run_command(f"objdump -d '{binary_path}' 2>/dev/null | grep -E 'ptrace|IsDebuggerPresent|CheckRemoteDebugger'")
    if stdout:
        analysis["anti_debug"].append("ptrace/debugger detection found")

    # 5. crypto 관련 힌트
    stdout, _, _ = run_command(f"strings '{binary_path}' 2>/dev/null | grep -iE 'aes|rsa|sha|md5|base64|encrypt|decrypt' | head -10")
    if stdout:
        for line in stdout.strip().split('\n'):
            if line:
                analysis["crypto_hints"].append(line.strip())

    # 6. 흥미로운 strings
    stdout, _, _ = run_command(f"strings '{binary_path}' 2>/dev/null | grep -iE 'correct|wrong|flag|password|license|serial|key' | head -15")
    if stdout:
        for line in stdout.strip().split('\n'):
            if line:
                analysis["strings_hints"].append(line.strip())

    return analysis


def analyze_forensics(file_path: str) -> Dict[str, Any]:
    analysis = {
        "file_type": "",
        "details": {}
    }

    if not file_path or not os.path.exists(file_path):
        return analysis

    # file 명령어
    stdout, _, _ = run_command(f"file '{file_path}'")
    analysis["file_type"] = stdout.strip()

    # PCAP 파일
    if 'pcap' in stdout.lower() or file_path.endswith(('.pcap', '.pcapng')):
        analysis["details"]["type"] = "pcap"
        stdout, _, _ = run_command(f"capinfos '{file_path}' 2>/dev/null | head -10")
        if stdout:
            analysis["details"]["info"] = stdout.strip()

    # 이미지 파일
    elif any(ext in file_path.lower() for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']):
        analysis["details"]["type"] = "image"
        stdout, _, _ = run_command(f"exiftool '{file_path}' 2>/dev/null | head -20")
        if stdout:
            analysis["details"]["exif"] = stdout.strip()

    # ZIP/Archive
    elif 'zip' in stdout.lower() or file_path.endswith('.zip'):
        analysis["details"]["type"] = "archive"
        stdout, _, _ = run_command(f"unzip -l '{file_path}' 2>/dev/null | head -20")
        if stdout:
            analysis["details"]["contents"] = stdout.strip()

    return analysis


def auto_analyze(category: str, state: Dict) -> Dict[str, Any]:
    """
    카테고리에 따라 자동 분석을 수행합니다.

    Args:
        category: 문제 카테고리
        state: 현재 상태 (binary_path, url 등 포함)

    Returns:
        분석 결과 딕셔너리
    """
    category = category.lower()
    binary_path = state.get("binary_path", "")
    url = state.get("url", "")

    # challenge에서도 경로 추출 시도
    if not binary_path and state.get("challenge"):
        challenge = state["challenge"][0] if state["challenge"] else {}
        binary_path = challenge.get("binary_path", "") or challenge.get("source_path", "")

    if not url and state.get("challenge"):
        challenge = state["challenge"][0] if state["challenge"] else {}
        url = challenge.get("url", "")

    if category == "pwnable":
        return analyze_pwnable(binary_path)
    elif category == "web":
        source_path = ""
        if state.get("challenge"):
            source_path = state["challenge"][0].get("source_path", "")
        return analyze_web(url, source_path)
    elif category == "reversing":
        return analyze_reversing(binary_path)
    elif category == "forensics":
        return analyze_forensics(binary_path)
    else:
        return {}


def format_analysis_summary(analysis: Dict[str, Any], category: str) -> str:
    lines = []

    if category == "pwnable":
        if analysis.get("checksec"):
            lines.append("=== Checksec ===")
            cs = analysis["checksec"]
            lines.append(f"  NX: {'Enabled' if cs.get('nx') else 'Disabled'}")
            lines.append(f"  Canary: {'Enabled' if cs.get('canary') else 'Disabled'}")
            lines.append(f"  PIE: {'Enabled' if cs.get('pie') else 'Disabled'}")

        if analysis.get("interesting_functions"):
            lines.append("\n=== Interesting Functions ===")
            for func in analysis["interesting_functions"][:5]:
                lines.append(f"  {func}")

        if analysis.get("suggested_vuln"):
            lines.append("\n=== Suggested Vulnerabilities ===")
            for vuln in analysis["suggested_vuln"]:
                lines.append(f"  [{vuln['confidence'].upper()}] {vuln['type']}: {vuln['evidence']}")
                # Heap 취약점의 경우 힌트 추가
                if vuln.get("hints"):
                    for hint in vuln["hints"]:
                        lines.append(f"    → {hint}")

        if analysis.get("heap_info"):
            lines.append("\n=== Heap Analysis ===")
            hi = analysis["heap_info"]
            lines.append(f"  Functions: {', '.join(hi.get('functions', []))}")
            lines.append(f"  malloc calls: {hi.get('malloc_count', 0)}, free calls: {hi.get('free_count', 0)}")
            lines.append("  Strategy hints:")
            lines.append("    - If size > 0x408 possible: Use unsorted bin for libc leak")
            lines.append("    - If size <= 0x408: Tcache/fastbin attacks, need heap leak first")
            lines.append("    - Check for size constraints (if size >= 0x100, etc.)")

    elif category == "web":
        if analysis.get("technologies"):
            lines.append("=== Technologies ===")
            lines.append(f"  {', '.join(analysis['technologies'])}")

        if analysis.get("potential_vulns"):
            lines.append("\n=== Potential Vulnerabilities ===")
            for vuln in analysis["potential_vulns"]:
                lines.append(f"  [{vuln['confidence'].upper()}] {vuln['type']}: {vuln['evidence']}")

    elif category == "reversing":
        if analysis.get("anti_debug"):
            lines.append("=== Anti-Debug Detected ===")
            for ad in analysis["anti_debug"]:
                lines.append(f"  {ad}")

        if analysis.get("strings_hints"):
            lines.append("\n=== Interesting Strings ===")
            for s in analysis["strings_hints"][:10]:
                lines.append(f"  {s}")

    return "\n".join(lines) if lines else "No significant findings from auto-analysis."
