from typing import Tuple
from enum import Enum


class TaskComplexity(Enum):
    SIMPLE = "simple"      # 파싱, 성공/실패 판단, 간단한 변환
    MEDIUM = "medium"      # 피드백 생성, 명령어 생성
    COMPLEX = "complex"    # 취약점 분석, exploit 코드 생성, 전략 수립


# OpenAI 모델 계층
OPENAI_MODELS = {
    TaskComplexity.SIMPLE: "gpt-4o-mini",      # 저렴, 빠름
    TaskComplexity.MEDIUM: "gpt-5.2",           # 균형
    TaskComplexity.COMPLEX: "gpt-5.2",          # 고성능 (필요시 gpt-4-turbo)
}

# Gemini 모델 계층
GEMINI_MODELS = {
    TaskComplexity.SIMPLE: "gemini-1.5-flash",       # 저렴, 빠름
    TaskComplexity.MEDIUM: "gemini-1.5-flash",       # 균형
    TaskComplexity.COMPLEX: "gemini-1.5-pro",        # 고성능
}


def get_model_for_task(base_model: str, task_type: str) -> str:
    # 작업별 복잡도 매핑
    task_complexity_map = {
        # 단순 작업
        "parsing": TaskComplexity.SIMPLE,
        "parse": TaskComplexity.SIMPLE,
        "translate": TaskComplexity.SIMPLE,
        "format": TaskComplexity.SIMPLE,

        # 중간 복잡도
        "feedback": TaskComplexity.MEDIUM,
        "instruction": TaskComplexity.MEDIUM,
        "command": TaskComplexity.MEDIUM,

        # 복잡한 작업
        "planning": TaskComplexity.COMPLEX,
        "cot": TaskComplexity.COMPLEX,
        "cal": TaskComplexity.COMPLEX,
        "exploit": TaskComplexity.COMPLEX,
        "poc": TaskComplexity.COMPLEX,
        "analysis": TaskComplexity.COMPLEX,
    }

    # 작업 복잡도 결정
    task_lower = task_type.lower()
    complexity = TaskComplexity.MEDIUM  # 기본값

    for key, comp in task_complexity_map.items():
        if key in task_lower:
            complexity = comp
            break

    # 모델 계열 확인 및 적절한 모델 선택
    is_gemini = "gemini" in base_model.lower()

    if is_gemini:
        return GEMINI_MODELS.get(complexity, base_model)
    else:
        return OPENAI_MODELS.get(complexity, base_model)


def should_use_fast_model(task_type: str) -> bool:
    fast_tasks = ["parsing", "parse", "translate", "format", "validate"]
    return any(t in task_type.lower() for t in fast_tasks)


def get_model_info(model: str) -> dict:
    model_info = {
        # OpenAI
        "gpt-5.2": {"tier": "high", "cost": "$$", "speed": "medium"},
        "gpt-4o-mini": {"tier": "low", "cost": "$", "speed": "fast"},
        "gpt-4-turbo": {"tier": "high", "cost": "$$$", "speed": "slow"},

        # Gemini
        "gemini-1.5-flash": {"tier": "low", "cost": "$", "speed": "fast"},
        "gemini-1.5-pro": {"tier": "high", "cost": "$$", "speed": "medium"},
        "gemini-3-flash-preview": {"tier": "medium", "cost": "$", "speed": "fast"},
    }
    return model_info.get(model, {"tier": "unknown", "cost": "?", "speed": "?"})
