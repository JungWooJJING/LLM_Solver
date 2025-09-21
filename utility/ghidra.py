import pyghidra, os

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

os.environ["GHIDRA_INSTALL_DIR"] = "/home/wjddn0623/Ghidra/ghidra/build/dist/ghidra_12.0_DEV"
pyghidra.start()

def ghdira_API(target : str):
    result = ""

    with pyghidra.open_program(target) as flat:
        program = flat.getCurrentProgram()
        fm = program.getFunctionManager()
        listing = program.getListing()
        decomp = FlatDecompilerAPI(flat)

        for f in fm.getFunctions(True):
            name = f.getName()

            try :
                c_code = decomp.decompile(f, 30)

                asm_line = []
                instr_iter = listing.getInstructions(f.getBody(), True)
                while instr_iter.hasNext():
                    instr = instr_iter.next()
                    asm_line.append(f"{instr.getAddress()}:\t{instr}")

                asm_code = "\n".join(asm_line)

                result += f"=== MATCH: {name} 0x{f.getEntryPoint()} ===\n"
                result += f"--- Decompiled Code ---\n"
                result += f"{c_code} \n"
                result += f"--- Assembly ---\n"
                result += f"{asm_code} + \n"
            except Exception as e:
                print(f"[!] Failed {name} : {e}")

    decomp.dispose()

    return result