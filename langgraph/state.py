# graph/state.py
from typing import TypedDict, List, Dict, Any, Literal
from typing_extensions import Annotated
import threading


# Thread-safe 캐시 래퍼
class ThreadSafeDict:
    def __init__(self, data: dict = None):
        self._data = data if data is not None else {}
        self._lock = threading.RLock()

    def get(self, key, default=None):
        with self._lock:
            return self._data.get(key, default)

    def __getitem__(self, key):
        with self._lock:
            return self._data[key]

    def __setitem__(self, key, value):
        with self._lock:
            self._data[key] = value

    def __contains__(self, key):
        with self._lock:
            return key in self._data

    def __iter__(self):
        with self._lock:
            return iter(self._data.copy())

    def items(self):
        with self._lock:
            return list(self._data.items())

    def keys(self):
        with self._lock:
            return list(self._data.keys())

    def values(self):
        with self._lock:
            return list(self._data.values())

    def update(self, other):
        with self._lock:
            self._data.update(other)

    def to_dict(self):
        with self._lock:
            return self._data.copy()

class Plan(TypedDict):
    # 현재 계획
    cot_result: str
    cot_json: Dict[str, Any]  # {"candidates": [...]}
    cal_result: str
    cal_json: Dict[str, Any]  # {"results": [{"idx": 0, "final": 0.9, ...}]}
    instruction_result: str
    instruction_json: Dict[str, Any]
    multi_instructions: List[Dict[str, Any]]  # Multi-Track용
    
    # 계획 저장
    plan: Dict[str, Any]  # plan.json 내용
    todos: List[Any]  # 할 일 목록
    runs: List[Any]  # 실행 이력
    backlog: List[Any]  # 백로그
    seen_cmd_hashes: List[str]  # 중복 방지
    
    # 이전 계획
    previous_plans: List[Dict[str, Any]]  # 이전 계획 이력
    previous_cot_results: List[str]  # 이전 CoT 결과들
    previous_cal_results: List[str]  # 이전 Cal 결과들
    
    # 계획 성공 여부 및 진행도
    plan_success_status: Dict[str, str]  # track_id -> "success"|"fail"|"partial"|"in_progress"
    plan_progress: Dict[str, float]  # track_id -> 진행도 (0.0 ~ 1.0)
    plan_attempts: Dict[str, int]  # track_id -> 시도 횟수
    
    # Multi-Track Planning
    vulnerability_tracks: Dict[str, Any]  # Track management
    track_tools: Dict[str, Any]  # 각 트랙에 할당된 도구 정보
    current_track: str  # 현재 활성 트랙 ID
    selected: Dict[str, Any]  # 현재 선택된 candidate


class State(TypedDict):
    # 타겟 정보
    challenge: List[Dict[str, Any]]  # Challenge 정보 (category, flag format 등)
    binary_path: str  # 바이너리 경로
    url: str  # 웹 타겟 URL
    target_info: Dict[str, Any]  # 타겟 상세 정보 (추가)

    # libc 및 one_gadget 정보 (자동 탐지)
    libc_path: str  # 탐지된 libc 파일 경로
    one_gadget_offsets: List[Dict[str, str]]  # [{"address": "0x...", "constraints": "..."}]
    one_gadget_raw: str  # one_gadget 원본 출력

    # 보호 기법
    protections: Dict[str, Any]  # checksec 결과, 보호 기법 정보
    mitigations: List[str]  # 활성화된 보호 기법 목록 (NX, PIE, RELRO, Canary 등)
    
    # 실행해서 얻은 정보
    facts: Dict[str, Any]  # 검증된 사실들 (offsets, addresses, mitigations 등)
    artifacts: Dict[str, Any]  # 생성된 파일/경로
    signals: List[Dict[str, Any]]  # 최근 발견된 신호들 (facts로 승격되기 전)
    errors: List[str]  # 실행 중 발생한 에러들
    
    # 실행 결과
    results: List[Any]  # 실행 이력
    execution_results: Dict[str, str]  # 각 트랙의 실행 결과 (track_id -> output)
    execution_output: str  # 기본 실행 결과
    execution_status: str  # "success", "fail", "partial", "flag_detected", "privilege_escalated"
    parsing_result: str
    multi_parsing_results: Dict[str, str]  # track_id -> parsing_result
    
    # Flag 감지 관련
    flag_detected: bool  # Flag가 감지되었는지 여부
    detected_flag: str  # 감지된 flag 값 (첫 번째)
    all_detected_flags: List[str]  # 감지된 모든 flag 값들
    
    # 관리자 권한 획득 관련
    privilege_escalated: bool  # 관리자 권한이 획득되었는지 여부
    privilege_evidence: str  # 관리자 권한 획득 증거 (예: "uid=0", "root prompt", etc.)
    
    # PoC 코드 생성 관련
    poc_result: str  # PoC 생성 결과 (원본 텍스트)
    poc_json: Dict[str, Any]  # PoC 생성 결과 (파싱된 JSON)
    poc_script_path: str  # 생성된 PoC 스크립트 파일 경로
    
    # Feedback 결과
    feedback_result: str
    feedback_json: Dict[str, Any]
    
    # 재시도 제한 관련
    instruction_retry_count: int  # Instruction 재시도 횟수
    iteration_count: int  # 워크플로우 반복 횟수 (--continue 시 리셋)
    workflow_step_count: int  # Workflow step count (recursion_limit 체크용)

    # 명령어 캐싱 (중복 실행 방지)
    command_cache: Dict[str, Dict[str, Any]]  # {cmd_hash: {cmd, result, success, timestamp}}
    failed_commands: Dict[str, Dict[str, Any]]  # {cmd_hash: {cmd, error, timestamp, attempt_count}}
    all_track_outputs: Dict[str, List[Dict[str, Any]]]  # {track_id: [{cmd, success, stdout, ...}]}

    # 자동 분석 결과
    auto_analysis: Dict[str, Any]  # 카테고리별 자동 분석 결과

    # Exploit Readiness (Feedback에서 계산)
    exploit_readiness: Dict[str, Any]  # {score: 0.0-1.0, components: {...}, recommend_exploit: bool, ...}


class Context(TypedDict):
    # 사용자 입력
    user_input: str
    option: str  # "--file", "--ghidra", "--discuss", "--continue" 등
    current_step: str
    
    # 환경 및 제약
    constraints: List[str]  # 제약 조건
    env: Dict[str, Any]  # 환경 변수 및 설정
    
    # 제어 플래그
    user_approval: bool
    approval_choice: str  # "continue", "restart", "end"
    init_flow: int
    
    # 시스템 컨텍스트
    ctx: Any  # 컨텍스트 객체 (직렬화 불가)
    API_KEY: str
    
    # 시나리오 (선택적, 하위 호환성)
    scenario: Dict[str, Any]


class PlanningState(Plan, State, Context):
    # Plan의 모든 필드 + State의 모든 필드 + Context의 모든 필드
    # = 모든 필드가 자동으로 상속됨
    pass


# === State 접근 헬퍼 함수 ===
def get_plan(state: PlanningState) -> Dict[str, Any]:
    return {
        "cot_result": state.get("cot_result", ""),
        "cot_json": state.get("cot_json", {}),
        "cal_result": state.get("cal_result", ""),
        "cal_json": state.get("cal_json", {}),
        "instruction_result": state.get("instruction_result", ""),
        "instruction_json": state.get("instruction_json", {}),
        "multi_instructions": state.get("multi_instructions", []),
        "plan": state.get("plan", {}),
        "todos": state.get("todos", []),
        "runs": state.get("runs", []),
        "backlog": state.get("backlog", []),
        "seen_cmd_hashes": state.get("seen_cmd_hashes", []),
        "previous_plans": state.get("previous_plans", []),
        "previous_cot_results": state.get("previous_cot_results", []),
        "previous_cal_results": state.get("previous_cal_results", []),
        "plan_success_status": state.get("plan_success_status", {}),
        "plan_progress": state.get("plan_progress", {}),
        "plan_attempts": state.get("plan_attempts", {}),
        "vulnerability_tracks": state.get("vulnerability_tracks", {}),
        "track_tools": state.get("track_tools", {}),
        "current_track": state.get("current_track", ""),
        "selected": state.get("selected", {}),
    }


def get_state(state: PlanningState) -> Dict[str, Any]:
    return {
        "challenge": state.get("challenge", []),
        "binary_path": state.get("binary_path", ""),
        "url": state.get("url", ""),
        "target_info": state.get("target_info", {}),
        "protections": state.get("protections", {}),
        "mitigations": state.get("mitigations", []),
        "facts": state.get("facts", {}),
        "artifacts": state.get("artifacts", {}),
        "signals": state.get("signals", []),
        "errors": state.get("errors", []),
        "results": state.get("results", []),
        "execution_results": state.get("execution_results", {}),
        "execution_output": state.get("execution_output", ""),
        "execution_status": state.get("execution_status", ""),
        "parsing_result": state.get("parsing_result", ""),
        "multi_parsing_results": state.get("multi_parsing_results", {}),
        "flag_detected": state.get("flag_detected", False),
        "privilege_escalated": state.get("privilege_escalated", False),
        "privilege_evidence": state.get("privilege_evidence", ""),
        "detected_flag": state.get("detected_flag", ""),
        "all_detected_flags": state.get("all_detected_flags", []),
        "poc_result": state.get("poc_result", ""),
        "poc_json": state.get("poc_json", {}),
        "poc_script_path": state.get("poc_script_path", ""),
        "feedback_result": state.get("feedback_result", ""),
        "feedback_json": state.get("feedback_json", {}),
        "instruction_retry_count": state.get("instruction_retry_count", 0),
    }


def get_context(state: PlanningState) -> Dict[str, Any]:
    return {
        "user_input": state.get("user_input", ""),
        "option": state.get("option", ""),
        "current_step": state.get("current_step", ""),
        "constraints": state.get("constraints", []),
        "env": state.get("env", {}),
        "user_approval": state.get("user_approval", False),
        "approval_choice": state.get("approval_choice", ""),
        "init_flow": state.get("init_flow", 0),
        "ctx": state.get("ctx"),
        "API_KEY": state.get("API_KEY", ""),
        "scenario": state.get("scenario", {}),
    }


# === Agent별 필요한 정보만 추출하는 함수 ===
def get_state_for_cot(state: PlanningState) -> Dict[str, Any]:
    tracks = state.get("vulnerability_tracks", {})
    results = state.get("results", [])
    
    # 트랙 요약 (전체가 아닌 핵심 정보만)
    tracks_summary = {
        track_id: {
            "vuln": track.get("vuln"),
            "status": track.get("status"),
            "progress": track.get("progress", 0.0),
            "attempts": track.get("attempts", 0)
        }
        for track_id, track in tracks.items()
    }
    
    return {
        # 타겟 정보
        "challenge": state.get("challenge", []),
        "binary_path": state.get("binary_path", ""),
        "url": state.get("url", ""),
        "target_info": state.get("target_info", {}),
        
        # 보호 기법
        "protections": state.get("protections", {}),
        "mitigations": state.get("mitigations", []),
        
        # 기존 탐색 결과 (요약)
        "vulnerability_tracks": tracks_summary,
        "facts": state.get("facts", {}),
        "artifacts": state.get("artifacts", {}),
        "results": results[-10:] if results else [],  # 최근 10개만

        # 실패한 접근법 (반복 방지용)
        "failed_approaches": state.get("failed_approaches", []),

        # 제약 조건
        "constraints": state.get("constraints", []),
    }


def get_state_for_cal(state: PlanningState) -> Dict[str, Any]:
    return {
        "cot_result": state.get("cot_result", ""),
        "cot_json": state.get("cot_json", {}),
        "challenge": state.get("challenge", []),
        "constraints": state.get("constraints", []),
    }


def get_state_for_instruction(state: PlanningState) -> Dict[str, Any]:
    return {
        # 계획 결과
        "cot_json": state.get("cot_json", {}),
        "cal_json": state.get("cal_json", {}),
        "current_track": state.get("current_track", ""),
        "selected": state.get("selected", {}),

        # 타겟 정보
        "challenge": state.get("challenge", []),
        "binary_path": state.get("binary_path", ""),
        "url": state.get("url", ""),
        "target_info": state.get("target_info", {}),

        # 보호 기법
        "protections": state.get("protections", {}),
        "mitigations": state.get("mitigations", []),

        # 발견된 정보
        "facts": state.get("facts", {}),
        "artifacts": state.get("artifacts", {}),

        # 제약 조건
        "constraints": state.get("constraints", []),

        # 이미 실행한 명령어 (중복 방지)
        "seen_cmd_hashes": state.get("seen_cmd_hashes", []),
        "command_cache": state.get("command_cache", {}),
        "failed_commands": state.get("failed_commands", {}),
        "all_track_outputs": state.get("all_track_outputs", {}),  # 실행된 명령어 리스트

        # 이전 실행 결과 (중복 방지용 - 전체 결과 전달)
        "execution_results": state.get("execution_results", {}),
        "results": state.get("results", []),  # 전체 결과 전달 (중복 명령어 추출용)
    }


def get_state_for_parsing(state: PlanningState) -> Dict[str, Any]:
    return {
        "execution_results": state.get("execution_results", {}),
        "execution_output": state.get("execution_output", ""),
        "execution_status": state.get("execution_status", ""),
        "challenge": state.get("challenge", []),
        "binary_path": state.get("binary_path", ""),
        "protections": state.get("protections", {}),
        "facts": state.get("facts", {}),
    }


def get_state_for_feedback(state: PlanningState) -> Dict[str, Any]:
    return {
        "execution_results": state.get("execution_results", {}),
        "execution_status": state.get("execution_status", ""),
        "parsing_result": state.get("parsing_result", ""),
        "cot_json": state.get("cot_json", {}),
        "cal_json": state.get("cal_json", {}),
        "instruction_json": state.get("instruction_json", {}),
        "facts": state.get("facts", {}),
        "artifacts": state.get("artifacts", {}),
        "signals": state.get("signals", []),
        "errors": state.get("errors", []),
        "challenge": state.get("challenge", []),
    }


def get_state_for_detect(state: PlanningState) -> Dict[str, Any]:
    return {
        "feedback_result": state.get("feedback_result", ""),
        "feedback_json": state.get("feedback_json", {}),
        "exploit_result": state.get("exploit_result", ""),
        "execution_results": state.get("execution_results", {}),
        "execution_status": state.get("execution_status", ""),
        "parsing_result": state.get("parsing_result", ""),
        "signals": state.get("signals", []),
        "facts": state.get("facts", {}),
        "artifacts": state.get("artifacts", {}),
        "vulnerability_tracks": state.get("vulnerability_tracks", {}),
        "flag_detected": state.get("flag_detected", False),
        "detected_flag": state.get("detected_flag", ""),
        "privilege_escalated": state.get("privilege_escalated", False),
        "challenge": state.get("challenge", []),
        "exploit_readiness": state.get("exploit_readiness", {}),
    }


# === 공통 유틸리티 함수 ===
def is_shell_acquired(text: str) -> bool:
    import re

    if not text:
        return False

    text_lower = text.lower()

    # 1. 쉘 프롬프트 확인 (가장 확실한 신호)
    shell_prompts = ["$ ", "# ", "> ", "bash:", "sh:", "zsh:", "csh:"]
    has_prompt = any(prompt in text for prompt in shell_prompts)

    # 2. 실제 명령어 실행 결과 패턴 확인
    # "id" 명령어의 전체 출력 패턴: "uid=0(root) gid=0(root) groups=0(root)"
    id_pattern = r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)"
    has_id_output = bool(re.search(id_pattern, text))

    # 3. "whoami" 명령어 결과 확인
    whoami_pattern = r"^(root|admin|user|www-data|nobody|daemon)\s*$"
    has_whoami = bool(re.search(whoami_pattern, text, re.MULTILINE))

    # 4. 쉘 환경 변수 확인
    env_vars = ["PATH=", "HOME=", "USER=", "SHELL="]
    has_env_vars = sum(1 for var in env_vars if var in text) >= 2  # 최소 2개 이상

    # 5. 실제 쉘 명령어 실행 결과 (ls -la 출력 패턴)
    ls_pattern = r"[d-][rwx-]{9}\s+\d+\s+\w+\s+\w+\s+\d+\s+[A-Za-z]{3}\s+\d+\s+[\d:]+\s+[^\s]+"
    has_ls_output = bool(re.search(ls_pattern, text))

    # 최소 2개 이상의 강한 신호가 있어야 쉘 획득으로 판단
    strong_signals = [
        has_prompt,  # 쉘 프롬프트
        has_id_output,  # id 명령어 출력
        (has_whoami and has_env_vars),  # whoami + 환경 변수
        (has_ls_output and has_env_vars),  # ls 출력 + 환경 변수
    ]

    # 쉘 프롬프트가 있고 추가 신호가 하나라도 있으면
    if has_prompt and (has_id_output or has_whoami or has_ls_output or has_env_vars):
        return True

    # 또는 강한 신호가 2개 이상
    if sum(strong_signals) >= 2:
        return True

    return False


def is_privilege_escalated(text: str) -> bool:
    import re

    if not text:
        return False

    # 1. uid=0 패턴 (root 권한)
    if re.search(r"uid=0\(root\)", text):
        return True

    # 2. root 사용자 whoami 출력
    if re.search(r"^root\s*$", text, re.MULTILINE):
        return True

    # 3. root 프롬프트
    if "root@" in text and "#" in text:
        return True

    # 4. sudo 성공 메시지
    if "is not in the sudoers file" not in text and "sorry" not in text.lower():
        if re.search(r"root@|uid=0|euid=0", text):
            return True

    # 5. 권한 변경 성공 메시지
    priv_patterns = [
        r"privilege.*escalat",
        r"got\s+root",
        r"became\s+root",
        r"now\s+root",
    ]
    for pattern in priv_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False
