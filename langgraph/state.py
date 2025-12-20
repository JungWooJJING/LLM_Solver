# graph/state.py
from typing import TypedDict, List, Dict, Any, Literal
from typing_extensions import Annotated

class Plan(TypedDict):
    """
    계획 저장 및 관리
    - 계획 수립 결과 (CoT, Cal, Instruction)
    - 이전 계획 이력
    - 계획 성공 여부 및 진행도
    - 트랙 관리
    """
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
    """
    타겟에 대한 정보 및 실행 결과
    - 타겟 정보 (challenge, binary, URL 등)
    - 보호 기법 (checksec, mitigations 등)
    - 실행해서 얻은 정보 (facts, artifacts, signals, results)
    """
    # 타겟 정보
    challenge: List[Dict[str, Any]]  # Challenge 정보 (category, flag format 등)
    binary_path: str  # 바이너리 경로
    url: str  # 웹 타겟 URL
    target_info: Dict[str, Any]  # 타겟 상세 정보 (추가)
    
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
    execution_status: str  # "success", "fail", "partial", "flag_detected"
    parsing_result: str
    multi_parsing_results: Dict[str, str]  # track_id -> parsing_result
    
    # Flag 감지 관련
    flag_detected: bool  # Flag가 감지되었는지 여부
    detected_flag: str  # 감지된 flag 값 (첫 번째)
    all_detected_flags: List[str]  # 감지된 모든 flag 값들
    
    # PoC 코드 생성 관련
    poc_result: str  # PoC 생성 결과 (원본 텍스트)
    poc_json: Dict[str, Any]  # PoC 생성 결과 (파싱된 JSON)
    poc_script_path: str  # 생성된 PoC 스크립트 파일 경로
    
    # Feedback 결과
    feedback_result: str
    feedback_json: Dict[str, Any]


class Context(TypedDict):
    """
    컨텍스트 및 제어 정보
    - 사용자 입력 및 옵션
    - 환경 설정 및 제약
    - 제어 플래그
    - 시스템 컨텍스트
    """
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
    """
    통합 State: Plan + State + Context
    
    LangGraph의 StateGraph는 단일 TypedDict를 요구하므로,
    Plan, State, Context를 다중 상속하여 통합 State를 구성합니다.
    
    TypedDict의 다중 상속은 모든 부모 클래스의 필드를 자동으로 합칩니다.
    따라서 필드를 명시적으로 나열할 필요가 없습니다.
    """
    # Plan의 모든 필드 + State의 모든 필드 + Context의 모든 필드
    # = 모든 필드가 자동으로 상속됨


# === State 접근 헬퍼 함수 ===
def get_plan(state: PlanningState) -> Dict[str, Any]:
    """
    Plan 부분만 추출
    """
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
    """
    State 부분만 추출
    """
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
        "detected_flag": state.get("detected_flag", ""),
        "all_detected_flags": state.get("all_detected_flags", []),
        "poc_result": state.get("poc_result", ""),
        "poc_json": state.get("poc_json", {}),
        "poc_script_path": state.get("poc_script_path", ""),
        "feedback_result": state.get("feedback_result", ""),
        "feedback_json": state.get("feedback_json", {}),
    }


def get_context(state: PlanningState) -> Dict[str, Any]:
    """
    Context 부분만 추출
    """
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
    """
    CoT Agent에 필요한 정보만 추출
    - 타겟 정보 (challenge, binary_path, url)
    - 보호 기법 (protections, mitigations)
    - 기존 트랙 요약 (vulnerability_tracks의 핵심 정보만)
    - 발견된 사실 (facts)
    - 생성된 아티팩트 (artifacts)
    - 최근 실행 결과 (results의 최근 항목만)
    - 제약 조건 (constraints)
    """
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
        
        # 제약 조건
        "constraints": state.get("constraints", []),
    }


def get_state_for_cal(state: PlanningState) -> Dict[str, Any]:
    """
    Cal Agent에 필요한 정보만 추출
    - CoT 결과 (cot_result, cot_json)
    - 타겟 정보 (challenge)
    - 제약 조건 (constraints)
    """
    return {
        "cot_result": state.get("cot_result", ""),
        "cot_json": state.get("cot_json", {}),
        "challenge": state.get("challenge", []),
        "constraints": state.get("constraints", []),
    }


def get_state_for_instruction(state: PlanningState) -> Dict[str, Any]:
    """
    Instruction Agent에 필요한 정보만 추출
    - CoT/Cal 결과 (cot_json, cal_json)
    - 타겟 정보 (challenge, binary_path, url)
    - 보호 기법 (protections, mitigations)
    - 발견된 사실 (facts)
    - 생성된 아티팩트 (artifacts)
    - 제약 조건 (constraints)
    - 현재 트랙 정보 (current_track, selected)
    """
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
    }


def get_state_for_parsing(state: PlanningState) -> Dict[str, Any]:
    """
    Parsing Agent에 필요한 정보만 추출
    - 실행 결과 (execution_results, execution_output, execution_status)
    - 타겟 정보 (challenge, binary_path)
    - 보호 기법 (protections)
    - 기존 사실 (facts)
    """
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
    """
    Feedback Agent에 필요한 정보만 추출
    - 실행 결과 (execution_results, execution_status, parsing_result)
    - 계획 정보 (cot_json, cal_json, instruction_json)
    - 발견된 정보 (facts, artifacts, signals)
    - 타겟 정보 (challenge)
    """
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
