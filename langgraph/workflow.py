from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

# 상대 import로 변경 (langgraph 패키지 내에서 사용)
try:
    from langgraph.state import PlanningState
    from langgraph.node import senario_node, CoT_node, Cal_node, instruction_node, human_node, parsing_node, feedback_node, exploit_node, approval_node, help_node, option_input_node
except ImportError:
    # 같은 디렉토리에서 실행하는 경우
    from state import PlanningState
    from node import senario_node, CoT_node, Cal_node, instruction_node, human_node, parsing_node, feedback_node, exploit_node, approval_node, help_node, option_input_node

def route_by_option(state: PlanningState) -> str:

    option = state.get("option", "")
    has_scenario = bool(state.get("scenario"))
    
    if not has_scenario:
        if option == "--help":
            return "help"
        elif option == "--file" or option == "--ghidra" or option == "--discuss":
            return "first_workflow"
        elif option == "--quit":
            return "end"
        elif option in ["--continue", "--exploit"]:
            return "invalid_init"
        else:
            return "invalid"
    
    else:
        if option == "--help":
            return "help"
        elif option in ["--discuss", "--continue"]:
            return "loop_workflow"
        elif option == "--exploit":
            return "exploit_flow"
        elif option == "--quit":
            return "end"
        elif option in ["--file", "--ghidra"]:
            return "invalid_loop"
        else:
            return "invalid"

def route_loop_option(state: PlanningState) -> str:
    option = state.get("option", "")
    
    if option == "--help":
        return "help"
    elif option in ["--discuss", "--continue"]:
        return "loop_workflow"
    elif option == "--exploit":
        return "exploit_flow"
    elif option == "--quit":
        return "end"
    else:
        return "invalid"

def route_after_approval(state: PlanningState) -> str:
    approval_choice = state.get("approval_choice", "continue")
    
    if approval_choice == "continue":
        return "continue"
    elif approval_choice == "restart":
        return "restart"
    elif approval_choice == "end":
        return "end"
    else:
        return "continue"

def create_init_workflow():
    graph = StateGraph(PlanningState)

    graph.add_node("scenario", senario_node)
    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("instruction", instruction_node)
    graph.add_node("human", human_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("approval", approval_node)

    graph.set_entry_point("scenario")
    graph.add_edge("scenario", "CoT")
    graph.add_edge("CoT", "Cal")
    graph.add_edge("Cal", "instruction")
    graph.add_edge("instruction", "human")
    graph.add_edge("human", "approval")

    graph.add_conditional_edges(
        "approval",
        route_after_approval,
        {
            "continue": "parsing",  
            "restart": "scenario",  
            "end": END  
        }
    )

    graph.add_edge("parsing", "feedback")
    graph.add_edge("feedback", END)  
    
    return graph.compile()

def create_loop_workflow():
    graph = StateGraph(PlanningState)

    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("instruction", instruction_node)
    graph.add_node("human", human_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("approval", approval_node)
    graph.add_node("exploit", exploit_node)

    graph.set_entry_point("CoT")
    graph.add_edge("CoT", "Cal")
    graph.add_edge("Cal", "instruction")
    graph.add_edge("instruction", "human")
    graph.add_edge("human", "approval")

    graph.add_conditional_edges(
        "approval",
        route_after_approval,
        {
            "continue": "parsing",  
            "restart": "CoT",  
            "end": END  
        }
    )

    graph.add_edge("parsing", "feedback")
    graph.add_edge("feedback", END)
    

    return graph.compile()

def create_main_workflow():
    workflow = StateGraph(PlanningState)

    init_graph = create_init_workflow()
    loop_graph = create_loop_workflow()

    workflow.add_node("init_workflow", init_graph)
    workflow.add_node("loop_workflow", loop_graph)
    workflow.add_node("help", help_node)
    workflow.add_node("option_input", option_input_node)
    workflow.add_node("exploit", exploit_node)

    workflow.set_entry_point("option_input")
    
    workflow.add_edge("help", "option_input")
    
    workflow.add_edge("init_workflow", "option_input")
    
    workflow.add_edge("loop_workflow", "option_input")
    
    workflow.add_edge("exploit", "option_input")
    
    workflow.add_conditional_edges(
        "option_input",
        route_by_option,
        {
            "help": "help",
            "first_workflow": "init_workflow",
            "loop_workflow": "loop_workflow",
            "exploit_flow": "exploit",
            "end": END,
            "invalid": "help",
            "invalid_init": "help",
            "invalid_loop": "help"
        }
    )
    
    return workflow.compile()
