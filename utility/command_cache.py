import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from rich.console import Console

console = Console()


def hash_command(cmd: str) -> str:
    # 공백 정규화
    normalized = " ".join(cmd.split())
    return hashlib.md5(normalized.encode()).hexdigest()[:12]


def is_duplicate_command(cmd: str, seen_hashes: List[str]) -> bool:
    cmd_hash = hash_command(cmd)
    return cmd_hash in seen_hashes


def add_command_to_cache(cmd: str, seen_hashes: List[str]) -> List[str]:
    cmd_hash = hash_command(cmd)
    if cmd_hash not in seen_hashes:
        seen_hashes.append(cmd_hash)
    return seen_hashes


def get_similar_commands(cmd: str, results: List[Dict]) -> List[Dict]:
    similar = []
    cmd_lower = cmd.lower()
    cmd_parts = set(cmd.split())

    for result in results:
        prev_cmd = result.get("cmd", "")
        if not prev_cmd:
            continue

        prev_parts = set(prev_cmd.split())

        # Jaccard 유사도 계산
        intersection = len(cmd_parts & prev_parts)
        union = len(cmd_parts | prev_parts)

        if union > 0:
            similarity = intersection / union
            if similarity > 0.7:  # 70% 이상 유사
                similar.append({
                    "cmd": prev_cmd,
                    "similarity": similarity,
                    "result": result
                })

    return sorted(similar, key=lambda x: x["similarity"], reverse=True)


def check_command_before_execution(
    cmd: str,
    state: Dict
) -> Tuple[bool, Optional[str], Optional[Dict]]:
    seen_hashes = state.get("seen_cmd_hashes", [])
    results = state.get("results", [])

    # 1. 완전 동일 명령어 체크
    if is_duplicate_command(cmd, seen_hashes):
        # 이전 결과 찾기
        cmd_hash = hash_command(cmd)
        for result in reversed(results):
            if hash_command(result.get("cmd", "")) == cmd_hash:
                return False, "Exact duplicate command", result

        return False, "Command already executed (no cached result)", None

    # 2. 유사 명령어 체크
    similar = get_similar_commands(cmd, results)
    if similar:
        top_similar = similar[0]
        if top_similar["similarity"] > 0.9:  # 90% 이상 유사하면 경고
            console.print(
                f"[!] Similar command already executed ({top_similar['similarity']:.0%} match)",
                style="yellow"
            )
            console.print(f"    Previous: {top_similar['cmd'][:60]}...", style="dim")

            # 하지만 실행은 허용 (사용자가 의도적으로 변형했을 수 있음)
            return True, "Similar command found but allowing execution", None

    # 3. 무한 루프 패턴 감지
    if len(results) >= 3:
        recent_cmds = [r.get("cmd", "") for r in results[-3:]]
        recent_hashes = [hash_command(c) for c in recent_cmds if c]

        if len(set(recent_hashes)) == 1:
            # 최근 3개 명령어가 모두 동일
            return False, "Infinite loop detected - same command 3 times", results[-1]

    return True, None, None


def suggest_alternative_command(
    blocked_cmd: str,
    state: Dict
) -> Optional[str]:
    results = state.get("results", [])
    signals = state.get("signals", [])

    # 간단한 휴리스틱 기반 제안
    suggestions = []

    if "checksec" in blocked_cmd.lower():
        suggestions.append("Try analyzing the binary with: file <binary> && readelf -h <binary>")

    if "gdb" in blocked_cmd.lower():
        suggestions.append("Try using ltrace or strace for dynamic analysis")

    if "curl" in blocked_cmd.lower():
        suggestions.append("Try with different headers or parameters")

    if suggestions:
        return suggestions[0]

    return "Consider a different approach based on the signals discovered so far"


class CommandCache:
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.cache: Dict[str, Dict] = {}
        self.execution_count: Dict[str, int] = {}

    def get(self, cmd: str) -> Optional[Dict]:
        cmd_hash = hash_command(cmd)
        return self.cache.get(cmd_hash)

    def set(self, cmd: str, result: Dict):
        cmd_hash = hash_command(cmd)

        # 캐시 크기 제한
        if len(self.cache) >= self.max_size:
            # 가장 오래된 항목 제거 (FIFO)
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]

        self.cache[cmd_hash] = {
            "cmd": cmd,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }

        # 실행 횟수 추적
        self.execution_count[cmd_hash] = self.execution_count.get(cmd_hash, 0) + 1

    def get_execution_count(self, cmd: str) -> int:
        cmd_hash = hash_command(cmd)
        return self.execution_count.get(cmd_hash, 0)

    def is_frequently_executed(self, cmd: str, threshold: int = 3) -> bool:
        return self.get_execution_count(cmd) >= threshold
