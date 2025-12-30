"""
진전도 추적 및 전략 변경 모듈

연속 실패나 동일 패턴 반복을 감지하여 전략 변경을 제안합니다.
"""

import hashlib
from typing import Dict, List, Any, Tuple
from rich.console import Console

console = Console()


def hash_signals(signals: List[Dict]) -> str:
    if not signals:
        return "empty"
    signal_str = str(sorted([str(s) for s in signals]))
    return hashlib.md5(signal_str.encode()).hexdigest()[:8]


def analyze_progress(state: Dict) -> Dict[str, Any]:
    """
    현재 state를 분석하여 진전도를 평가합니다.

    Returns:
        {
            "is_stuck": bool,
            "reason": str,
            "suggestion": str,
            "stats": dict
        }
    """
    results = state.get("results", [])
    signals = state.get("signals", [])
    seen_cmd_hashes = state.get("seen_cmd_hashes", [])
    iteration_count = state.get("iteration_count", 0)

    analysis = {
        "is_stuck": False,
        "reason": "",
        "suggestion": "",
        "stats": {
            "total_iterations": iteration_count,
            "total_results": len(results),
            "unique_commands": len(set(seen_cmd_hashes)),
            "total_signals": len(signals)
        }
    }

    # 1. 연속 실패 감지
    if len(results) >= 3:
        recent_results = results[-3:]
        fail_count = sum(1 for r in recent_results if not r.get("ok", False))
        if fail_count == 3:
            analysis["is_stuck"] = True
            analysis["reason"] = "3 consecutive failures detected"
            analysis["suggestion"] = "Try a different vulnerability type or analysis approach"
            return analysis

    # 2. 동일 signals 반복 감지
    if len(results) >= 3:
        recent_signal_hashes = []
        for r in results[-3:]:
            r_signals = r.get("signals", [])
            recent_signal_hashes.append(hash_signals(r_signals))

        if len(set(recent_signal_hashes)) == 1 and recent_signal_hashes[0] != "empty":
            analysis["is_stuck"] = True
            analysis["reason"] = "Same signals detected in last 3 iterations"
            analysis["suggestion"] = "The current approach is not yielding new information. Consider changing the attack vector."
            return analysis

    # 3. 명령어 중복 실행 감지
    if seen_cmd_hashes:
        from collections import Counter
        cmd_counts = Counter(seen_cmd_hashes)
        repeated = [(cmd, count) for cmd, count in cmd_counts.items() if count >= 3]
        if repeated:
            analysis["is_stuck"] = True
            analysis["reason"] = f"Command repeated {repeated[0][1]} times"
            analysis["suggestion"] = "Breaking out of command loop. Try manual intervention with --discuss"
            return analysis

    # 4. 너무 많은 iteration 없이 진전 없음
    if iteration_count >= 10 and len(signals) == 0:
        analysis["is_stuck"] = True
        analysis["reason"] = f"{iteration_count} iterations without discovering signals"
        analysis["suggestion"] = "No progress detected. Review the challenge description or try a completely different approach."
        return analysis

    # 5. 진전 있음 - 새로운 signals 발견
    if len(signals) > 0:
        # 최근에 새로운 signal 발견했는지
        if results:
            last_result = results[-1]
            if last_result.get("signals"):
                analysis["stats"]["recent_discovery"] = True

    return analysis


def should_change_strategy(state: Dict) -> Tuple[bool, str]:
    """
    전략 변경이 필요한지 판단합니다.

    Returns:
        (should_change: bool, reason: str)
    """
    progress = analyze_progress(state)

    if progress["is_stuck"]:
        return True, f"{progress['reason']}. {progress['suggestion']}"

    return False, ""


def get_alternative_strategies(category: str, current_vuln: str = "") -> List[str]:
    """
    현재 시도 중인 취약점 외에 시도해볼 수 있는 대안을 제안합니다.
    """
    alternatives = {
        "pwnable": [
            "Stack Buffer Overflow → Try format string vulnerability",
            "Format String → Try heap exploitation",
            "Direct exploitation → Try information leak first",
            "Local exploit → Check if remote differs",
            "ROP chain → Try ret2libc or ret2win"
        ],
        "web": [
            "SQL Injection → Try SSTI or XSS",
            "SSTI → Try LFI/Path Traversal",
            "Authentication bypass → Try IDOR or broken access control",
            "Direct exploitation → Try information disclosure first",
            "Client-side → Check server-side vulnerabilities"
        ],
        "reversing": [
            "Static analysis → Try dynamic debugging",
            "Direct solving → Try patching binary",
            "Complex algorithm → Look for shortcuts or backdoors",
            "Anti-debug bypass → Try different debugger or emulation"
        ],
        "crypto": [
            "Mathematical attack → Try implementation weakness",
            "Known attack → Check for custom modifications",
            "Brute force → Look for oracle or timing attack"
        ]
    }

    return alternatives.get(category.lower(), [
        "Try a different analysis approach",
        "Review the challenge description for hints",
        "Look for hidden files or information"
    ])


def format_stuck_message(state: Dict) -> str:
    progress = analyze_progress(state)

    if not progress["is_stuck"]:
        return ""

    category = "misc"
    if state.get("challenge") and len(state["challenge"]) > 0:
        category = state["challenge"][0].get("category", "misc").lower()

    lines = [
        "=" * 50,
        " STRATEGY CHANGE RECOMMENDED",
        "=" * 50,
        f"Reason: {progress['reason']}",
        "",
        "Suggested alternatives:"
    ]

    for alt in get_alternative_strategies(category)[:3]:
        lines.append(f"  - {alt}")

    lines.extend([
        "",
        "Options:",
        "  --discuss : Discuss new approach with LLM",
        "  --exploit : Try direct exploitation if you have enough info",
        "=" * 50
    ])

    return "\n".join(lines)
