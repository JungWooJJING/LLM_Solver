"""
LangGraph 워크플로우 시각화 스크립트

사용법:
    python -m langgraph.visualize
    또는
    python langgraph/visualize.py
"""

import sys
import os

# 프로젝트 루트를 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langgraph.workflow import create_main_workflow, create_init_workflow, create_loop_workflow
from rich.console import Console

console = Console()

def visualize_workflow(workflow, name="Workflow", output_format="mermaid"):
    """
    워크플로우를 시각화
    
    Args:
        workflow: 컴파일된 LangGraph 워크플로우
        name: 워크플로우 이름
        output_format: 출력 형식 ("mermaid", "ascii", "png", "svg")
    """
    try:
        # LangGraph의 get_graph() 메서드로 그래프 객체 가져오기
        graph = workflow.get_graph()
        
        console.print(f"\n=== {name} Visualization ===", style="bold green")
        
        if output_format == "mermaid":
            # Mermaid 다이어그램 출력 (LangGraph 공식 방법)
            try:
                mermaid_diagram = graph.draw_mermaid()
                console.print("\n[Mermaid Diagram]", style="bold cyan")
                console.print(mermaid_diagram)
                
                # 파일로 저장
                output_file = f"./artifacts/{name.lower().replace(' ', '_')}_mermaid.md"
                os.makedirs("./artifacts", exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(f"# {name} - Mermaid Diagram\n\n")
                    f.write("```mermaid\n")
                    f.write(mermaid_diagram)
                    f.write("\n```\n")
                console.print(f"\nSaved to: {output_file}", style="green")
            except AttributeError:
                console.print("draw_mermaid() 메서드를 사용할 수 없습니다.", style="yellow")
                console.print("LangGraph 버전을 확인하세요.", style="cyan")
            
        elif output_format == "ascii":
            # ASCII 아트 출력
            try:
                # LangGraph는 print_ascii() 메서드를 제공할 수도 있음
                if hasattr(graph, 'print_ascii'):
                    ascii_diagram = graph.print_ascii()
                elif hasattr(graph, 'draw_ascii'):
                    ascii_diagram = graph.draw_ascii()
                else:
                    # Mermaid를 ASCII로 변환하거나 간단한 텍스트 출력
                    mermaid = graph.draw_mermaid()
                    ascii_diagram = f"Mermaid diagram available. Use 'mermaid' format instead.\n\n{mermaid[:500]}..."
                
                console.print("\n[ASCII Diagram]", style="bold cyan")
                console.print(ascii_diagram)
                
                # 파일로 저장
                output_file = f"./artifacts/{name.lower().replace(' ', '_')}_ascii.txt"
                os.makedirs("./artifacts", exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(f"{name} - ASCII Diagram\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(ascii_diagram)
                console.print(f"\nSaved to: {output_file}", style="green")
            except Exception as e:
                console.print(f"ASCII 출력 중 오류: {e}", style="yellow")
                console.print("Mermaid 형식으로 시도해보세요.", style="cyan")
            
        elif output_format in ["png", "svg"]:
            # 이미지로 저장 (Mermaid를 이미지로 변환하려면 추가 도구 필요)
            console.print("\nPNG/SVG 출력은 Mermaid 다이어그램을 이미지로 변환해야 합니다.", style="yellow")
            console.print("다음 방법을 사용할 수 있습니다:", style="cyan")
            console.print("  1) Mermaid Live Editor (https://mermaid.live/)에 코드 붙여넣기", style="cyan")
            console.print("  2) mermaid-cli 설치: npm install -g @mermaid-js/mermaid-cli", style="cyan")
            console.print("     그 후: mmdc -i input.mmd -o output.png", style="cyan")
            console.print("\n대신 Mermaid 형식으로 출력합니다...", style="yellow")
            visualize_workflow(workflow, name, "mermaid")
                
        else:
            console.print(f"지원하지 않는 형식: {output_format}", style="yellow")
            console.print("지원 형식: mermaid, ascii, png, svg", style="cyan")
            
    except Exception as e:
        console.print(f"시각화 중 오류 발생: {e}", style="bold red")
        import traceback
        console.print(traceback.format_exc(), style="dim")

def main():
    console.print("\n=== LangGraph Workflow Visualizer ===", style="bold magenta")
    
    # 출력 형식 선택
    console.print("\n출력 형식을 선택하세요:", style="cyan")
    console.print("  1) mermaid (기본, 마크다운 호환)", style="yellow")
    console.print("  2) ascii (텍스트 다이어그램)", style="yellow")
    console.print("  3) png (이미지, pygraphviz 필요)", style="yellow")
    console.print("  4) svg (벡터 이미지, pygraphviz 필요)", style="yellow")
    console.print("  5) all (모든 형식)", style="yellow")
    
    choice = input("\n선택 (1-5, 기본값: 1): ").strip() or "1"
    
    format_map = {
        "1": "mermaid",
        "2": "ascii",
        "3": "png",
        "4": "svg",
        "5": "all"
    }
    
    output_format = format_map.get(choice, "mermaid")
    
    # 워크플로우 선택
    console.print("\n시각화할 워크플로우를 선택하세요:", style="cyan")
    console.print("  1) Main Workflow (전체)", style="yellow")
    console.print("  2) Init Workflow (초기)", style="yellow")
    console.print("  3) Loop Workflow (루프)", style="yellow")
    console.print("  4) All (모든 워크플로우)", style="yellow")
    
    workflow_choice = input("\n선택 (1-4, 기본값: 1): ").strip() or "1"
    
    workflows_to_visualize = []
    
    if workflow_choice == "1":
        workflows_to_visualize = [("Main Workflow", create_main_workflow())]
    elif workflow_choice == "2":
        workflows_to_visualize = [("Init Workflow", create_init_workflow())]
    elif workflow_choice == "3":
        workflows_to_visualize = [("Loop Workflow", create_loop_workflow())]
    elif workflow_choice == "4":
        workflows_to_visualize = [
            ("Main Workflow", create_main_workflow()),
            ("Init Workflow", create_init_workflow()),
            ("Loop Workflow", create_loop_workflow())
        ]
    else:
        workflows_to_visualize = [("Main Workflow", create_main_workflow())]
    
    # 시각화 실행
    for name, workflow in workflows_to_visualize:
        if output_format == "all":
            # 모든 형식으로 출력
            for fmt in ["mermaid", "ascii"]:
                visualize_workflow(workflow, name, fmt)
        else:
            visualize_workflow(workflow, name, output_format)
    
    console.print("\n=== 시각화 완료 ===", style="bold green")

if __name__ == "__main__":
    main()

# 간단한 사용 예제:
# 
# from langgraph.workflow import create_main_workflow
# from langgraph.visualize import visualize_workflow
# 
# workflow = create_main_workflow()
# visualize_workflow(workflow, "Main Workflow", "mermaid")
#
# 또는 직접:
# workflow = create_main_workflow()
# print(workflow.get_graph().draw_mermaid())

