import subprocess
import json
import re
import os
import shlex
from typing import Optional, List, Dict, Any
from pathlib import Path
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field

# Angr는 선택적 의존성 - Protobuf 버전 충돌 방지를 위해 선택적 import
try:
    import angr
    ANGR_AVAILABLE = True
except (ImportError, Exception) as e:
    ANGR_AVAILABLE = False
    angr = None

# PyGhidra는 선택적 의존성 - 있으면 사용, 없으면 에러 메시지
try:
    import pyghidra
    # pyghidra.start() 후에만 ghidra 모듈을 import할 수 있음
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False
    pyghidra = None


class ReversingTool:
    def __init__(self, binary_path: Optional[str] = None):
        """
        Args:
            binary_path: 분석할 바이너리 경로 (선택사항, 나중에 설정 가능)
        """
        self.binary_path = binary_path
        self._check_binary_exists()
    
    def _run_command(self, cmd: List[str], timeout: int = 30) -> Dict[str, any]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "cmd": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "cmd": " ".join(cmd)
            }
    
    def set_binary_path(self, binary_path: str):
        self.binary_path = binary_path
        self._check_binary_exists()
    
    def _check_binary_exists(self):
        if self.binary_path and not Path(self.binary_path).exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
        
    """
    기드라 디컴파일 혹은 어셈
    """
    def ghidra_decompile(
        self,
        function_name: Optional[str] = None,
        binary_path: Optional[str] = None,
        project_path: Optional[str] = None,
        analyze_binary: bool = True,
        function_address: Optional[str] = None
    ) -> str:
        """
        Ghidra로 바이너리의 특정 함수를 디컴파일합니다.
        함수명 또는 주소로 함수를 찾아 디컴파일된 코드와 어셈블리 코드를 반환합니다.
        
        Args:
            function_name: 디컴파일할 함수명 또는 주소 (예: "main", "0x401200")
            binary_path: 바이너리 경로 (선택사항)
            project_path: Ghidra 프로젝트 경로 (선택사항)
            analyze_binary: 바이너리 분석 여부
            function_address: 함수 주소 (16진수, 예: "0x401200" 또는 "401200")
        """
        if not GHIDRA_AVAILABLE:
            return json.dumps({
                "error": "PyGhidra is not available. Please install: pip install pyghidra"
            }, indent=2)
        
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        if not Path(target).exists():
            return json.dumps({"error": f"Binary not found: {target}"}, indent=2)
        
        ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if not ghidra_dir:
            return json.dumps({
                "error": "GHIDRA_INSTALL_DIR environment variable is not set."
            }, indent=2)
        
        import tempfile
        
        try:
            if not pyghidra.started():
                pyghidra.start(install_dir=ghidra_dir)
            
            from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
            from ghidra.program.flatapi import FlatProgramAPI  
            
            results = []
            
            if not project_path:
                project_path = tempfile.mkdtemp(prefix="ghidra_project_")
            
            project_name = Path(target).stem + "_project"
            
            with pyghidra.open_project(project_path, project_name, create=True) as project:
                binary_name = Path(target).name
                loader = pyghidra.program_loader().project(project)
                loader = loader.source(target).projectFolderPath("/")
                
                program_path = None
                with loader.load() as load_results:
                    load_results.save(pyghidra.task_monitor())
                    try:
                        if hasattr(load_results, 'programs') and load_results.programs:
                            program_path = load_results.programs[0].getDomainFile().getPathname()
                        elif hasattr(load_results, 'getPrograms'):
                            programs = load_results.getPrograms()
                            if programs and len(programs) > 0:
                                program_path = programs[0].getDomainFile().getPathname()
                    except Exception:
                        pass
                    
                    if not program_path:
                        program_path = "/" + binary_name
                
                with pyghidra.program_context(project, program_path) as program:
                    if analyze_binary:
                        try:
                            pyghidra.analyze(program, pyghidra.task_monitor(timeout=30))
                        except Exception:
                            pass
                    
                    flat_api = FlatProgramAPI(program)
                    decomp = FlatDecompilerAPI(flat_api)
                    
                    try:
                        fm = program.getFunctionManager()
                        listing = program.getListing()
                        
                        func = None
                        
                        # 1. 주소 기반 검색 (우선순위 1)
                        if function_address:
                            func = self._find_function_by_address(fm, function_address)
                        
                        # 2. 함수명 기반 검색 (우선순위 2)
                        if not func and function_name:
                            # 주소 형식인지 확인 (0x401200 또는 401200)
                            if function_name.startswith("0x") or (len(function_name) > 2 and all(c in "0123456789abcdefABCDEF" for c in function_name.replace("0x", ""))):
                                func = self._find_function_by_address(fm, function_name)
                            else:
                                # 이름으로 검색
                                for f in fm.getFunctions(True):
                                    if f.getName() == function_name:
                                        func = f
                                        break
                                
                                # 대소문자 무시 검색
                                if not func:
                                    for f in fm.getFunctions(True):
                                        if f.getName().lower() == function_name.lower():
                                            func = f
                                            break
                        
                        if not func:
                            # 사용 가능한 함수 목록 반환 (주소 포함)
                            available_funcs = []
                            for f in list(fm.getFunctions(True))[:50]:
                                func_name = f.getName()
                                func_addr = str(f.getEntryPoint())
                                available_funcs.append(f"{func_name} ({func_addr})")
                            
                            return json.dumps({
                                "error": f"Function not found" + (f" (name: {function_name})" if function_name else "") + (f" (address: {function_address})" if function_address else ""),
                                "available_functions": available_funcs,
                                "hint": "Please provide function_name or function_address"
                            }, indent=2, ensure_ascii=False)
                        
                        func_result = self._decompile_function(func, decomp, listing)
                        if func_result:
                            results.append(func_result)
                    
                    finally:
                        decomp.dispose()
            
            return json.dumps({
                "binary_path": target,
                "functions": results
            }, indent=2, ensure_ascii=False)
            
        except Exception as e:
            import traceback
            return json.dumps({
                "error": f"Ghidra decompilation failed: {str(e)}",
                "traceback": traceback.format_exc(),
                "binary_path": target
            }, indent=2)
        
    def _find_function_by_address(self, fm, address_str: str):
        try:
            # 주소 문자열 정규화
            addr_str = address_str.replace("0x", "").replace("0X", "")
            if not addr_str:
                return None
            
            # 16진수로 변환
            try:
                addr_int = int(addr_str, 16)
            except ValueError:
                return None
            
            # Address 객체 생성
            from ghidra.program.model.address import Address
            addr_space = fm.getProgram().getAddressFactory().getDefaultAddressSpace()
            address = addr_space.getAddress(addr_int)
            
            # 주소의 함수 찾기
            func = fm.getFunctionAt(address)
            if func:
                return func
            
            # 주소를 포함하는 함수 찾기
            func = fm.getFunctionContaining(address)
            return func
            
        except Exception as e:
            return None
    
    
    def _decompile_function(self, func, decomp, listing):
        try:
            func_name = func.getName()
            entry_point = func.getEntryPoint()
            
            # 디컴파일 (timeout 30초)
            c_code = decomp.decompile(func, 30)
            
            # 어셈블리 코드 추출
            asm_lines = []
            instr_iter = listing.getInstructions(func.getBody(), True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                asm_lines.append(f"{instr.getAddress()}:\t{instr}")
            
            asm_code = "\n".join(asm_lines)
            
            return {
                "function_name": func_name,
                "entry_point": "0x" + str(entry_point),
                "decompiled_code": str(c_code),
                "assembly_code": asm_code,
            }
        except Exception as e:
            return {
                "function_name": func.getName(),
                "error": f"Decompilation failed: {str(e)}"
            }
    
    def _remove_ansi_colors(self, text: str) -> str:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def pwndbg_debug(self, binary_path: Optional[str] = None, command: str = None) -> str:
        """
        GDB(Pwndbg)로 바이너리 디버깅
        Args:
            command: 디버깅 명령 (예: 'vmmap', 'telescope', 'info functions')
            binary_path: 바이너리 경로
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        gdb_cmd = ['gdb', '--batch', '-ex', command, target]
        
        # Pwndbg는 출력이 매우 길고 컬러 코드가 섞여 있어서 타임아웃을 넉넉히 잡아야 함
        run_result = self._run_command(gdb_cmd, timeout=15)
        
        if not run_result["success"]:
            return json.dumps({
                "error": run_result.get("error", "GDB failed"),
                "stderr": run_result.get("stderr", "")
            }, indent=2)
        
        # ANSI 컬러 코드 제거
        cleaned_output = self._remove_ansi_colors(run_result["stdout"])

        return json.dumps({
            "binary_path": target,
            "command": command,
            "result": cleaned_output
        }, indent=2, ensure_ascii=False)
    
    def angr_symbolic_execution(self, binary_path: Optional[str] = None, find_address: str = None, avoid_address: Optional[str] = None) -> str:
        """
        Angr를 사용하여 심볼릭 실행을 수행합니다.
        
        Args:
            binary_path: 바이너리 경로 (선택사항, self.binary_path 사용 가능)
            find_address: 도달하고자 하는 주소 (16진수 문자열, 예: "0x401200" 또는 "401200")
            avoid_address: 피하고자 하는 주소 (16진수 문자열, 선택사항)
        
        Returns:
            JSON 형식의 실행 결과
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        if not Path(target).exists():
            return json.dumps({"error": f"Binary not found: {target}"}, indent=2)
        
        if not find_address:
            return json.dumps({"error": "find_address is required"}, indent=2)
        
        if not ANGR_AVAILABLE:
            return json.dumps({
                "error": "angr is not available. Protobuf version conflict or angr not installed.",
                "binary_path": target,
                "find_address": find_address,
                "suggestion": "Install compatible protobuf version or use alternative tools"
            }, indent=2, ensure_ascii=False)
        
        try:
            # 주소 문자열을 정수로 변환
            def parse_address(addr_str: str) -> int:
                addr_str = addr_str.replace("0x", "").replace("0X", "")
                return int(addr_str, 16)
            
            find_addr_int = parse_address(find_address)
            avoid_addr_int = None
            if avoid_address:
                avoid_addr_int = parse_address(avoid_address)
            
            project = angr.Project(target)
            sm = project.factory.simulation_manager()
            
            if avoid_addr_int:
                sm.explore(find=find_addr_int, avoid=avoid_addr_int)
            else:
                sm.explore(find=find_addr_int)
            
            if not sm.found:
                return json.dumps({
                    "binary_path": target,
                    "find_address": find_address,
                    "avoid_address": avoid_address,
                    "error": "Target address not reached"
                }, indent=2, ensure_ascii=False)
            
            result_input = sm.found[0].posix.dumps(0)
            
            return json.dumps({
                "binary_path": target,
                "find_address": find_address,
                "avoid_address": avoid_address,
                "result": result_input.decode('latin-1', errors='replace') if isinstance(result_input, bytes) else str(result_input)
            }, indent=2, ensure_ascii=False)
            
        except ValueError as e:
            return json.dumps({
                "error": f"Invalid address format: {str(e)}",
                "binary_path": target
            }, indent=2)
        except Exception as e:
            import traceback
            return json.dumps({
                "error": f"Angr symbolic execution failed: {str(e)}",
                "traceback": traceback.format_exc(),
                "binary_path": target
            }, indent=2)

    def extract_strings(
        self,
        binary_path: Optional[str] = None,
        min_length: int = 4,
        max_results: int = 100
    ) -> str:
        """
        바이너리에서 문자열을 추출합니다.
        
        Args:
            binary_path: 대상 바이너리 경로 (선택사항, self.binary_path 사용 가능)
            min_length: 최소 문자열 길이 (기본: 4)
            max_results: 최대 결과 개수 (기본: 100)
        
        Returns:
            JSON 형식의 문자열 목록
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"}, indent=2)
        
        if not Path(target).exists():
            return json.dumps({"error": f"Binary not found: {target}"}, indent=2)
        
        try:
            # strings 명령어 사용 시도
            cmd = ["strings", "-n", str(min_length), target]
            result = self._run_command(cmd, timeout=30)
            
            if result["success"]:
                strings_list = [s for s in result["stdout"].strip().split("\n") if s.strip()][:max_results]
                
                # 흥미로운 문자열 필터링 (URL, 경로, 패스워드 등)
                interesting = []
                for s in strings_list:
                    s_lower = s.lower()
                    if any(keyword in s_lower for keyword in ["http://", "https://", "/bin/", "/usr/", "password", "flag", "secret", "key", "token"]):
                        interesting.append(s)
                
                return json.dumps({
                    "binary_path": target,
                    "min_length": min_length,
                    "total_found": len(strings_list),
                    "interesting_strings": interesting[:20],  # 최대 20개
                    "all_strings": strings_list,
                    "method": "strings command"
                }, indent=2, ensure_ascii=False)
            
            # strings 명령어가 없으면 Python으로 직접 추출
            strings_list = []
            with open(target, 'rb') as f:
                data = f.read()
                current_string = ""
                for byte in data:
                    if 32 <= byte <= 126:  # 출력 가능한 ASCII 문자
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= min_length:
                            strings_list.append(current_string)
                        current_string = ""
                if len(current_string) >= min_length:
                    strings_list.append(current_string)
            
            strings_list = list(set(strings_list))[:max_results]  # 중복 제거 및 제한
            
            interesting = []
            for s in strings_list:
                s_lower = s.lower()
                if any(keyword in s_lower for keyword in ["http://", "https://", "/bin/", "/usr/", "password", "flag", "secret", "key", "token"]):
                    interesting.append(s)
            
            return json.dumps({
                "binary_path": target,
                "min_length": min_length,
                "total_found": len(strings_list),
                "interesting_strings": interesting[:20],
                "all_strings": strings_list[:100],  # 최대 100개만
                "method": "python extraction"
            }, indent=2, ensure_ascii=False)
            
        except Exception as e:
            return json.dumps({
                "error": f"String extraction failed: {str(e)}",
                "binary_path": target
            }, indent=2)
    
    def checksec(
        self,
        binary_path: Optional[str] = None
    ) -> str:
        """
        바이너리의 보안 기능을 확인합니다 (ASLR, NX, Stack Canary, RELRO 등).
        
        Args:
            binary_path: 대상 바이너리 경로 (선택사항, self.binary_path 사용 가능)
        
        Returns:
            JSON 형식의 보안 기능 정보
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"}, indent=2)
        
        if not Path(target).exists():
            return json.dumps({"error": f"Binary not found: {target}"}, indent=2)
        
        security_features = {
            "binary_path": target
        }
        
        # checksec 명령어 시도 (pwntools의 checksec)
        checksec_result = self._run_command(["checksec", target])
        if checksec_result["success"]:
            security_features["checksec_output"] = checksec_result["stdout"]
            return json.dumps(security_features, indent=2, ensure_ascii=False)
        
        # checksec가 없으면 readelf로 직접 확인
        readelf_result = self._run_command(["readelf", "-W", "-l", target])
        if readelf_result["success"]:
            output = readelf_result["stdout"]
            
            # NX 확인
            security_features["nx"] = "GNU_STACK" in output and "RWE" not in output
            
            # PIE 확인
            readelf_ehdr = self._run_command(["readelf", "-h", target])
            if readelf_ehdr["success"]:
                ehdr_output = readelf_ehdr["stdout"]
                security_features["pie"] = "EXEC" not in ehdr_output or "DYN" in ehdr_output
            
            # RELRO 확인
            readelf_dyn = self._run_command(["readelf", "-d", target])
            if readelf_dyn["success"]:
                dyn_output = readelf_dyn["stdout"]
                security_features["relro"] = "BIND_NOW" in dyn_output or "RELRO" in dyn_output
            
            # Stack Canary 확인
            nm_result = self._run_command(["nm", target])
            if nm_result["success"]:
                nm_output = nm_result["stdout"]
                security_features["stack_canary"] = "__stack_chk_fail" in nm_output or "__stack_chk_guard" in nm_output
        
        return json.dumps(security_features, indent=2, ensure_ascii=False)
    
    def disassemble(
        self,
        binary_path: Optional[str] = None,
        function_name: Optional[str] = None,
        address: Optional[str] = None,
        num_instructions: int = 50
    ) -> str:
        """
        바이너리의 특정 함수나 주소를 디스어셈블합니다.
        
        Args:
            binary_path: 대상 바이너리 경로 (선택사항, self.binary_path 사용 가능)
            function_name: 디스어셈블할 함수명 (예: "main")
            address: 디스어셈블할 주소 (16진수, 예: "0x401200")
            num_instructions: 출력할 명령어 개수 (기본: 50)
        
        Returns:
            JSON 형식의 디스어셈블 결과
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"}, indent=2)
        
        if not Path(target).exists():
            return json.dumps({"error": f"Binary not found: {target}"}, indent=2)
        
        if not function_name and not address:
            return json.dumps({"error": "function_name or address is required"}, indent=2)
        
        try:
            cmd = ["objdump", "-d", "-M", "intel"]
            
            if function_name:
                cmd.extend(["--disassemble", f"={function_name}"])
            elif address:
                # 주소를 정수로 변환
                addr_str = address.replace("0x", "").replace("0X", "")
                addr_int = int(addr_str, 16)
                # objdump는 시작 주소를 직접 지원하지 않으므로 -S 옵션으로 시도
                cmd.append("--start-address")
                cmd.append(hex(addr_int))
                cmd.append("--stop-address")
                cmd.append(hex(addr_int + (num_instructions * 20)))  # 대략적인 범위
            
            cmd.append(target)
            
            result = self._run_command(cmd, timeout=30)
            
            if result["success"]:
                # 출력을 줄 단위로 나누고 필요한 부분만 추출
                lines = result["stdout"].split("\n")
                disassembly_lines = []
                
                for line in lines:
                    if any(marker in line for marker in [":\t", "Disassembly of", "<"]):
                        disassembly_lines.append(line)
                    if len(disassembly_lines) >= num_instructions * 2:  # 여유 있게
                        break
                
                return json.dumps({
                    "binary_path": target,
                    "function_name": function_name,
                    "address": address,
                    "disassembly": "\n".join(disassembly_lines[:num_instructions * 2])
                }, indent=2, ensure_ascii=False)
            else:
                return json.dumps({
                    "error": "objdump failed",
                    "stderr": result.get("stderr", ""),
                    "binary_path": target
                }, indent=2)
                
        except Exception as e:
            return json.dumps({
                "error": f"Disassembly failed: {str(e)}",
                "binary_path": target
            }, indent=2)
    

# ========== LangChain 도구로 변환하는 함수들 ==========

def create_reversing_tools(binary_path: Optional[str] = None, challenge_info: Optional[List[Dict[str, Any]]] = None) -> List[BaseTool]:
    """
    Converts ReversingTool methods into individual LangChain tools
    
    Args:
        binary_path: Default binary path
        challenge_info: Challenge information list (from state["challenge"])
    
    Returns:
        List of LangChain BaseTool
    """
    tool_instance = ReversingTool(binary_path)
    
    # Challenge 정보 추출
    challenge_context = ""
    if challenge_info and len(challenge_info) > 0:
        challenge = challenge_info[0]
        title = challenge.get("title", "")
        description = challenge.get("description", "")
        category = challenge.get("category", "")
        
        challenge_parts = []
        if title:
            challenge_parts.append(f"Challenge: {title}")
        if description:
            challenge_parts.append(f"Description: {description}")
        if category:
            challenge_parts.append(f"Category: {category}")
        
        if challenge_parts:
            challenge_context = "\n".join(challenge_parts) + "\n\n"
    
    # 각 메서드를 별도 도구로 생성
    tools = [
        StructuredTool.from_function(
            func=tool_instance.ghidra_decompile,
            name="ghidra_decompile",
            description=f"{challenge_context}Decompiles specific function of binary using Ghidra. Finds function by name or address and returns decompiled code and assembly code.",
            args_schema=type('GhidraArgs', (BaseModel,), {
                '__annotations__': {
                    'function_name': Optional[str],
                    'binary_path': Optional[str],
                    'function_address': Optional[str],
                    'analyze_binary': bool,
                    'project_path': Optional[str]
                },
                'function_name': Field(default=None, description="Function name or address to decompile (e.g., 'main', '0x401200', '401200')"),
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'function_address': Field(default=None, description="Function address (hex, e.g., '0x401200' or '401200')"),
                'analyze_binary': Field(default=True, description="Whether to analyze binary"),
                'project_path': Field(default=None, description="Ghidra project path (optional)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.pwndbg_debug,
            name="gdb_debug",
            description=f"{challenge_context}Debugs binary using GDB (Pwndbg). Can execute various debugging commands.",
            args_schema=type('GdbArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'command': str
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'command': Field(default="info functions", description="Debugging command (e.g., 'vmmap', 'telescope', 'info functions')")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.angr_symbolic_execution,
            name="angr_symbolic_execution",
            description=f"{challenge_context}Performs symbolic execution using Angr. Finds input that reaches a specific address.",
            args_schema=type('AngrArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'find_address': str,
                    'avoid_address': Optional[str]
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'find_address': Field(description="Target address to reach (hex string, e.g., '0x401200' or '401200')"),
                'avoid_address': Field(default=None, description="Address to avoid (hex string, optional)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.extract_strings,
            name="extract_strings",
            description=f"{challenge_context}Extracts readable strings from binary file. Useful for finding hardcoded passwords, URLs, flags, etc.",
            args_schema=type('ExtractStringsArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'min_length': int,
                    'max_results': int
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'min_length': Field(default=4, description="Minimum string length (default: 4)"),
                'max_results': Field(default=100, description="Maximum number of results (default: 100)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.checksec,
            name="checksec",
            description=f"{challenge_context}Checks security features of binary (ASLR/PIE, NX, Stack Canary, RELRO, etc.). Useful for exploit development.",
            args_schema=type('ChecksecArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str]
                },
                'binary_path': Field(default=None, description="Binary path (optional)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.disassemble,
            name="disassemble",
            description=f"{challenge_context}Disassembles specific function or address in binary using objdump. Returns assembly code.",
            args_schema=type('DisassembleArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'function_name': Optional[str],
                    'address': Optional[str],
                    'num_instructions': int
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'function_name': Field(default=None, description="Function name to disassemble (e.g., 'main')"),
                'address': Field(default=None, description="Address to disassemble (hex, e.g., '0x401200')"),
                'num_instructions': Field(default=50, description="Number of instructions to output (default: 50)")
            })
        ),
    ]
    
    return tools