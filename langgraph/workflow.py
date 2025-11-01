from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from graph.state import State
from graph.node import senario_node, CoT_node, Cal_node, instruction_node, human_node, parsing_node, feedback_node, exploit_node

def create_init_workflow():
    graph = StateGraph(State)

    graph.add_node("senario", senario_node)
    graph.add_node("CoT", CoT_node)
    graph.add_node("Cal", Cal_node)
    graph.add_node("instruction", instruction_node)
    graph.add_node("human", human_node)
    graph.add_node("parsing", parsing_node)
    graph.add_node("feedback", feedback_node)
    graph.add_node("exploit", exploit_node)

    workflow.set_entry_point("scenario")
    workflow.add_edge("scenario", "cot")
    workflow.add_edge("cot", "cal")
    workflow.add_edge("cal", "instruction")

