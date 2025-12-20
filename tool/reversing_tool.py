import subprocess
import json
import re
import os
import shlex
from typing import Optional, List, Dict
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
        """명령어 실행 헬퍼 함수"""
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
        """바이너리 경로 설정"""
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
        """주소로 함수 찾기"""
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
        """함수 하나를 디컴파일하고 결과 반환"""
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

    def xxd_hex(self, binary_path: Optional[str] = None, command: Optional[str] = None) -> str:
        """
        바이너리 파일을 xxd를 사용하여 헥스 덤프로 변환합니다.
        LLM의 컨텍스트 제한을 고려하여 command 인자가 없을 경우 기본적으로 앞부분(512바이트)만 출력합니다.
        
        Args:
            binary_path: 대상 바이너리 경로 (선택사항, self.binary_path 사용 가능)
            command: xxd에 전달할 추가 옵션 (예: "-l 100", "-s 0x400")
        
        Returns:
            JSON 형식의 실행 결과
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"}, indent=2)
        
        if not Path(target).exists():
            return json.dumps({"error": f"Binary not found: {target}"}, indent=2)
        
        try:
            # 기본 명령어 구성
            cmd_list = ["xxd"]
            
            # command 인자가 있으면 파싱해서 추가, 없으면 안전하게 앞부분 512바이트만 (-l 512)
            if command:
                # shlex.split을 사용하여 "-l 100" 같은 문자열을 리스트로 안전하게 변환
                cmd_list.extend(shlex.split(command))
            else:
                # Agent가 실수로 전체 덤프를 시도하지 않도록 안전장치 (Default Limit)
                cmd_list.extend(["-l", "512"])
                
            cmd_list.append(target)

            # _run_command 헬퍼 사용 (타임아웃 포함)
            run_result = self._run_command(cmd_list, timeout=30)
            
            if not run_result["success"]:
                return json.dumps({
                    "error": run_result.get("error", "xxd command failed"),
                    "stderr": run_result.get("stderr", ""),
                    "binary_path": target
                }, indent=2)
            
            return json.dumps({
                "binary_path": target,
                "command": command,
                "result": run_result["stdout"].strip()
            }, indent=2, ensure_ascii=False)

        except FileNotFoundError:
            return json.dumps({
                "error": "'xxd' command not found. Please install xxd or use a minimal python implementation.",
                "binary_path": target
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "error": f"Unexpected error: {str(e)}",
                "binary_path": target
            }, indent=2)


# ========== LangChain 도구로 변환하는 함수들 ==========

def create_reversing_tools(binary_path: Optional[str] = None) -> List[BaseTool]:
    """
    Converts ReversingTool methods into individual LangChain tools
    
    Args:
        binary_path: Default binary path
    
    Returns:
        List of LangChain BaseTool
    """
    tool_instance = ReversingTool(binary_path)
    
    # 각 메서드를 별도 도구로 생성
    tools = [
        StructuredTool.from_function(
            func=tool_instance.ghidra_decompile,
            name="ghidra_decompile",
            description="Decompiles specific function of binary using Ghidra. Finds function by name or address and returns decompiled code and assembly code.",
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
            func=tool_instance.angr_symbolic_execution,
            name="angr_symbolic_execution",
            description="Performs symbolic execution using Angr. Finds input that reaches a specific address.",
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
            func=tool_instance.pwndbg_debug,
            name="gdb_debug",
            description="Debugs binary using GDB (Pwndbg). Can execute various debugging commands.",
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
            func=tool_instance.xxd_hex,
            name="xxd_hex_dump",
            description="Converts binary file to hex dump using xxd. By default, only outputs first 512 bytes to consider LLM context limitations.",
            args_schema=type('XxdArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'command': Optional[str]
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'command': Field(default=None, description="Additional options to pass to xxd (e.g., '-l 100', '-s 0x400')")
            })
        ),
    ]
    
    return tools