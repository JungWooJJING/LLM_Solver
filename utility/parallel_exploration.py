"""
병렬 취약점 탐색 모듈

여러 취약점 후보를 동시에 검증하여 가장 유망한 것을 선택합니다.
"""

import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from rich.console import Console

console = Console()


class ParallelExplorer:
    """병렬 취약점 탐색기"""

    def __init__(self, max_workers: int = 3, timeout: int = 60):
        """
        Args:
            max_workers: 동시 실행할 최대 탐색 수
            timeout: 각 탐색의 타임아웃 (초)
        """
        self.max_workers = max_workers
        self.timeout = timeout

    def explore_candidates(
        self,
        candidates: List[Dict],
        validate_func: Callable[[Dict], Dict],
        max_candidates: int = 3
    ) -> List[Dict]:
        """
        여러 후보를 병렬로 검증합니다.

        Args:
            candidates: 검증할 후보 리스트 (Cal 결과에서 정렬된)
            validate_func: 각 후보를 검증하는 함수
            max_candidates: 검증할 최대 후보 수

        Returns:
            검증 결과 리스트 (성공한 것 우선)
        """
        # 상위 N개 후보만 선택
        top_candidates = candidates[:max_candidates]

        if len(top_candidates) <= 1:
            # 후보가 1개 이하면 병렬 처리 불필요
            if top_candidates:
                result = validate_func(top_candidates[0])
                return [result]
            return []

        console.print(f"\n[Parallel] Exploring {len(top_candidates)} candidates simultaneously...", style="cyan")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 각 후보에 대해 검증 태스크 제출
            future_to_candidate = {
                executor.submit(validate_func, candidate): candidate
                for candidate in top_candidates
            }

            # 결과 수집 (완료되는 순서대로)
            for future in concurrent.futures.as_completed(future_to_candidate, timeout=self.timeout):
                candidate = future_to_candidate[future]
                try:
                    result = future.result()
                    result["candidate"] = candidate
                    result["completed_at"] = datetime.now().isoformat()
                    results.append(result)

                    # 성공하면 나머지 취소 가능
                    if result.get("success", False):
                        console.print(f"[Parallel] Found promising result: {candidate.get('vuln', 'unknown')}", style="green")
                        # 다른 future들 취소
                        for f in future_to_candidate:
                            if f != future and not f.done():
                                f.cancel()
                        break

                except concurrent.futures.TimeoutError:
                    console.print(f"[Parallel] Timeout for: {candidate.get('vuln', 'unknown')}", style="yellow")
                    results.append({
                        "candidate": candidate,
                        "success": False,
                        "error": "timeout",
                        "completed_at": datetime.now().isoformat()
                    })
                except Exception as e:
                    console.print(f"[Parallel] Error for {candidate.get('vuln', 'unknown')}: {e}", style="red")
                    results.append({
                        "candidate": candidate,
                        "success": False,
                        "error": str(e),
                        "completed_at": datetime.now().isoformat()
                    })

        # 성공한 결과를 우선으로 정렬
        results.sort(key=lambda x: (not x.get("success", False), x.get("completed_at", "")))

        console.print(f"[Parallel] Completed: {len(results)} results", style="cyan")
        return results


def select_best_candidate(
    cal_results: List[Dict],
    state: Dict,
    max_to_explore: int = 2
) -> Dict:
    """
    Cal 결과에서 최적의 후보를 선택합니다.
    점수가 비슷한 상위 후보들은 병렬로 빠른 검증을 수행합니다.

    Args:
        cal_results: Cal 에이전트의 평가 결과
        state: 현재 상태
        max_to_explore: 탐색할 최대 후보 수

    Returns:
        선택된 최적 후보
    """
    if not cal_results:
        return {}

    # 점수순 정렬
    sorted_results = sorted(cal_results, key=lambda x: x.get("final", 0), reverse=True)

    if len(sorted_results) == 1:
        return sorted_results[0]

    # 상위 후보들의 점수 차이 확인
    top_score = sorted_results[0].get("final", 0)
    close_candidates = []

    for result in sorted_results[:max_to_explore]:
        score = result.get("final", 0)
        # 상위 점수와 10% 이내 차이면 비슷하다고 판단
        if top_score > 0 and (top_score - score) / top_score < 0.1:
            close_candidates.append(result)
        elif score == top_score:
            close_candidates.append(result)

    if len(close_candidates) <= 1:
        # 명확한 1등이 있음
        return sorted_results[0]

    # 점수가 비슷한 후보들이 있으면 추가 기준으로 선택
    console.print(f"[Selection] {len(close_candidates)} candidates with similar scores", style="yellow")

    # 추가 선택 기준:
    # 1. cost가 낮은 것
    # 2. risk가 낮은 것
    # 3. exploitability가 높은 것

    def score_candidate(c):
        scores = c.get("scores", {})
        return (
            scores.get("exploitability", 0) * 2 +
            (1 - scores.get("cost", 0.5)) +
            (1 - scores.get("risk", 0.5))
        )

    close_candidates.sort(key=score_candidate, reverse=True)

    console.print(f"[Selection] Best candidate: {close_candidates[0].get('vuln', 'unknown')}", style="green")
    return close_candidates[0]


def should_explore_parallel(cal_results: List[Dict]) -> bool:
    """병렬 탐색이 유용한지 판단합니다."""
    if len(cal_results) < 2:
        return False

    # 상위 2개의 점수 차이 확인
    sorted_results = sorted(cal_results, key=lambda x: x.get("final", 0), reverse=True)
    score1 = sorted_results[0].get("final", 0)
    score2 = sorted_results[1].get("final", 0)

    # 점수가 비슷하면 병렬 탐색 권장
    if score1 > 0:
        diff_ratio = (score1 - score2) / score1
        return diff_ratio < 0.15  # 15% 이내 차이

    return False
