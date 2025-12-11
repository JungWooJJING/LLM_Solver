import os
import pyghidra

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR")

if not GHIDRA_DIR:
    raise RuntimeError(
        "GHIDRA_INSTALL_DIR environment variable is not set.\n"
        "Please set the environment variable using:\n"
        "  export GHIDRA_INSTALL_DIR=/path/to/ghidra\n\n"
        "Or add it to ~/.zshrc or ~/.bashrc for permanent configuration."
    )

if not os.path.isdir(GHIDRA_DIR):
    raise RuntimeError(
        f"GHIDRA_INSTALL_DIR path does not exist: {GHIDRA_DIR}\n"
        "Please set the correct Ghidra installation path in the environment variable."
    )

os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_DIR

pyghidra.start(install_dir=GHIDRA_DIR)

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI


def find_entry_function(fm):

    preferred = ["main", "entry", "entry_point", "_start"]
    funcs = list(fm.getFunctions(True))

    # 이름 우선순위대로 검색
    for name in preferred:
        for f in funcs:
            if f.getName() == name:
                return f

    return funcs[0] if funcs else None


def ghdira_API(target: str, main_only: bool = True) -> str:

    result = ""

    with pyghidra.open_program(target) as flat:
        program = flat.getCurrentProgram()
        fm = program.getFunctionManager()
        listing = program.getListing()
        decomp = FlatDecompilerAPI(flat)

        try:
            if main_only:
                main_func = find_entry_function(fm)

                if main_func is None:
                    raise RuntimeError("[!] No entry function found")

                name = main_func.getName()
                c_code = decomp.decompile(main_func, 30)

                asm_lines = []
                instr_iter = listing.getInstructions(main_func.getBody(), True)
                while instr_iter.hasNext():
                    instr = instr_iter.next()
                    asm_lines.append(f"{instr.getAddress()}:\t{instr}")

                asm_code = "\n".join(asm_lines)
                entry = main_func.getEntryPoint()

                result += f"=== MATCH: {name} {entry} ===\n"
                result += "--- Decompiled Code ---\n"
                result += f"{c_code}\n"
                result += "--- Assembly ---\n"
                result += f"{asm_code}\n"

            else:
                for f in fm.getFunctions(True):
                    name = f.getName()
                    try:
                        c_code = decomp.decompile(f, 30)

                        asm_lines = []
                        instr_iter = listing.getInstructions(f.getBody(), True)
                        while instr_iter.hasNext():
                            instr = instr_iter.next()
                            asm_lines.append(f"{instr.getAddress()}:\t{instr}")

                        asm_code = "\n".join(asm_lines)
                        entry = f.getEntryPoint()

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