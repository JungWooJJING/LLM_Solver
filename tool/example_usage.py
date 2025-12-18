"""
PwnableTool 사용 예제
"""

from pwnable_tool import PwnableTool, create_pwnable_tools
from langchain_openai import ChatOpenAI
import os
import angr

# ========== 방법 1: 직접 사용 ==========
def example_direct_usage():
    """PwnableTool을 직접 사용하는 예제"""
    print("=== 직접 사용 예제 ===\n")
    
    # 도구 인스턴스 생성
    tool = PwnableTool(binary_path="/home/wjddn0623/lab/LLM_CTF/database/pwn/puffin/puffin")
    
    # checksec 실행
    # result = tool.checksec()
    # print("Checksec 결과:")
    # print(result)
    # print("\n")
    
    # tool = PwnableTool(binary_path="/lib/x86_64-linux-gnu/libc.so.6")

    # # ROPgadget 검색
    # result = tool.ropgadget_search(search_pattern="pop rdi")
    # print("ROPgadget 결과:")
    # print(result)
    # print("\n")
    
    # tool = PwnableTool(binary_path="/home/wjddn0623/lab/LLM_CTF/database/pwn/puffin/puffin")

    # # strings 추출
    # result = tool.strings_extract(min_length=8, filter_pattern="flag")
    # print("Strings 결과:")
    # print(result)
    
    result = tool.pwndbg_debug(binary_path="/home/wjddn0623/lab/LLM_CTF/database/pwn/puffin/puffin", command="disass main")
    print("GDB 디버깅 결과:")
    print(result)


# ========== 방법 2: LangChain 도구로 사용 ==========
def example_langchain_usage():
    """LangChain 도구로 변환하여 사용하는 예제"""
    print("\n=== LangChain 도구 사용 예제 ===\n")
    
    # 도구 생성
    tools = create_pwnable_tools(binary_path="./challenge")
    
    print(f"생성된 도구 개수: {len(tools)}")
    for tool in tools:
        print(f"- {tool.name}: {tool.description[:50]}...")
    
    # LLM에 도구 바인딩
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        llm = ChatOpenAI(api_key=api_key, model="gpt-4o-mini")
        llm_with_tools = llm.bind_tools(tools)
        
        # LLM이 도구를 호출할 수 있도록 설정
        print("\nLLM에 도구가 바인딩되었습니다.")
        print("이제 LLM이 자동으로 적절한 도구를 선택하여 사용할 수 있습니다.")


# ========== 방법 3: 동적 바이너리 경로 설정 ==========
def example_dynamic_binary():
    """바이너리 경로를 동적으로 설정하는 예제"""
    print("\n=== 동적 바이너리 경로 예제 ===\n")
    
    # 초기에는 바이너리 경로 없이 생성
    tool = PwnableTool()
    
    # 나중에 바이너리 경로 설정
    tool.set_binary_path("./challenge")
    
    # 이제 도구 사용 가능
    result = tool.checksec()
    print("Checksec 결과:")
    print(result)


# ========== 방법 4: 특정 함수만 디스어셈블 ==========
def example_specific_function():
    """특정 함수만 디스어셈블하는 예제"""
    print("\n=== 특정 함수 디스어셈블 예제 ===\n")
    
    tool = PwnableTool(binary_path="./challenge")
    
    # main 함수만 디스어셈블
    result = tool.objdump_disassemble(function_name="main")
    print("main 함수 디스어셈블:")
    print(result)


# ========== 방법 5: 에러 처리 ==========
def example_error_handling():
    """에러 처리 예제"""
    print("\n=== 에러 처리 예제 ===\n")
    
    tool = PwnableTool()
    
    # 바이너리 경로 없이 실행하면 에러
    result = tool.checksec()
    result_json = json.loads(result)
    if "error" in result_json:
        print(f"에러 발생: {result_json['error']}")
    
    # 존재하지 않는 바이너리
    try:
        tool.set_binary_path("./nonexistent")
    except FileNotFoundError as e:
        print(f"파일 없음: {e}")


if __name__ == "__main__":
    import json
    # tool = PwnableTool(binary_path="/home/wjddn0623/lab/LLM_CTF/database/pwn/puffin/puffin")
    
    # tool = PwnableTool(binary_path="/home/wjddn0623/lab/LLM_CTF/database/pwn/puffin/stripped_binary")

    example_direct_usage()

# # 1. 특정 함수 디컴파일
#     result = tool.ghidra_decompile(function_name="main")
#     # result = tool.ghidra_decompile(function_address="0x0010082a")
#     print(result)
#     # # 각 예제 실행
#     # example_direct_usage()
#     # example_langchain_usage()
#     # example_dynamic_binary()
#     # example_specific_function()
# #     # example_error_handling()
#     p = project = angr.Project("./test")
#     sm = p.factory.simulation_manager()
#     sm.explore(find=0x4012e2)
#     print(sm.found[0].posix.dumps(0))