import os

# Ghidra는 선택적 의존성 - 경로가 있으면 시작, 없으면 건너뛰기
GHIDRA_AVAILABLE = False
GHIDRA_DIR = None

try:
    import pyghidra
    # 환경 변수에서만 가져오기 (기본값 없음)
    GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR")
    
    if GHIDRA_DIR and os.path.isdir(GHIDRA_DIR):
        os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_DIR
        pyghidra.start(install_dir=GHIDRA_DIR)
        from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
        GHIDRA_AVAILABLE = True
    else:
        print("Warning: GHIDRA_INSTALL_DIR environment variable is not set or path does not exist.")
        print("Ghidra features will not be available.")
        print("To enable Ghidra, set the environment variable using:")
        print("  export GHIDRA_INSTALL_DIR=/path/to/ghidra")
except ImportError:
    print("Warning: pyghidra not installed. Ghidra features will not be available.")
except Exception as e:
    print(f"Warning: Failed to start Ghidra: {e}. Ghidra features will not be available.")


def find_entry_function(fm):
    entry_funcs = find_entry_functions(fm)
    return entry_funcs[0] if entry_funcs else None


def find_entry_functions(fm):
    preferred = ["main", "entry", "entry_point", "_start"]
    funcs = list(fm.getFunctions(True))
    entry_funcs = []

    # 이름 우선순위대로 검색
    for name in preferred:
        for f in funcs:
            if f.getName() == name:
                entry_funcs.append(f)

    # 진입점 함수가 없으면 첫 번째 함수를 반환 (하위 호환성)
    if not entry_funcs and funcs:
        entry_funcs = [funcs[0]]

    return entry_funcs


def ghdira_API(target: str, main_only: bool = True) -> str:
    """
    Ghidra API를 사용하여 바이너리 분석
    Ghidra가 사용 불가능한 경우 에러 메시지 반환
    """
    if not GHIDRA_AVAILABLE:
        return f"Error: Ghidra is not available. Please set GHIDRA_INSTALL_DIR environment variable."

    result = ""

    with pyghidra.open_program(target) as flat:
        program = flat.getCurrentProgram()
        fm = program.getFunctionManager()
        listing = program.getListing()
        decomp = FlatDecompilerAPI(flat)

        try:
            # 진입점 함수들만 찾기 (main_only 파라미터와 관계없이 항상 진입점만 출력)
            entry_funcs = find_entry_functions(fm)

            if not entry_funcs:
                raise RuntimeError("[!] No entry function found")

            # main_only가 True면 첫 번째 진입점만, False면 모든 진입점 출력
            funcs_to_process = [entry_funcs[0]] if main_only else entry_funcs

            # 진입점 함수들만 출력
            for func in funcs_to_process:
                name = func.getName()
                try:
                    c_code = decomp.decompile(func, 30)

                    asm_lines = []
                    instr_iter = listing.getInstructions(func.getBody(), True)
                    while instr_iter.hasNext():
                        instr = instr_iter.next()
                        asm_lines.append(f"{instr.getAddress()}:\t{instr}")

                    asm_code = "\n".join(asm_lines)
                    entry = func.getEntryPoint()

                    result += f"=== MATCH: {name} {entry} ===\n"
                    result += "--- Decompiled Code ---\n"
                    result += f"{c_code}\n"
                    result += "--- Assembly ---\n"
                    result += f"{asm_code}\n"
                except Exception as e:
                    print(f"[!] Failed {name}: {e}")
        finally:
            decomp.dispose()

    return result
