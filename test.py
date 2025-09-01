import os
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/home/wjddn0623/Ghidra/ghidra/build/dist/ghidra_12.0_DEV"
TARGET = "/home/wjddn0623/wargame/REVERSING/rev-basic-3/chall3.exe"

pyghidra.start()

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

with pyghidra.open_program(TARGET, analyze=False) as flat:
    program = flat.getCurrentProgram()
    fm = program.getFunctionManager()
    listing = program.getListing()
    decomp = FlatDecompilerAPI(flat)

    print(f"[+] Opened: {program.getName()}")

    keywords = ["main", "flag"]  # 부분 일치 키워드
    result = ""

    for f in fm.getFunctions(True):
        name = f.getName()

        try:
            # C 디컴파일
            c_code = decomp.decompile(f, 30)

            # 어셈블리 추출
            asm_lines = []
            instr_iter = listing.getInstructions(f.getBody(), True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                asm_lines.append(f"{instr.getAddress()}:\t{instr}")

            asm_code = "\n".join(asm_lines)

            # result에 누적
            result += f"===== MATCH: {name} @ {f.getEntryPoint()} =====\n"
            result += "----- Decompiled C Code -----\n"
            result += c_code + "\n"
            result += "----- Assembly -----\n"
            result += asm_code + "\n\n"

        except Exception as e:
            print(f"[!] Decompile failed for {name}: {e}")

    if result:
        print(result)
    else:
        print("[-] 'main' 또는 'flag'를 포함한 함수 없음.")

    decomp.dispose()
