# graph/state.py
from typing import TypedDict, List, Dict, Any, Literal
from typing_extensions import Annotated

class PlanningState(TypedDict):

    challenge: List[Dict[str, Any]]
    scenario: Dict[str, Any]
    constraints: List[str]
    env: Dict[str, Any]
    selected: Dict[str, Any]
    results: List[Any]
    
    todos: List[Any]
    runs: List[Any]
    seen_cmd_hashes: List[str]
    artifacts: Dict[str, Any]
    backlog: List[Any]
    
    option: str  
    current_step: str  
    user_input: str
    user_approval: bool  
    binary_path: str  
    
    cot_result: str  
    cot_json: Dict[str, Any]
    cal_result: str
    cal_json: Dict[str, Any]
    instruction_result: str
    instruction_json: Dict[str, Any]
    parsing_result: str
    feedback_result: str
    feedback_json: Dict[str, Any]
    
    ctx: Any  
    
    gpt_5: int  
    init_flow : int
    user_approval : bool