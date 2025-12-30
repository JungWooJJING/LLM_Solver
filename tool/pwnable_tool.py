import subprocess
import json
import re
import os
from typing import Optional, List, Dict
from pathlib import Path
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field
from langchain_core.tools.base import ArgsSchema

# PyGhidra는 선택적 의존성 - 있으면 사용, 없으면 에러 메시지
try:
    import pyghidra
    # pyghidra.start() 후에만 ghidra 모듈을 import할 수 있음
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False
    pyghidra = None



class PwnableTool:
    def __init__(self, binary_path: Optional[str] = None):
        """
        Args:
            binary_path: 분석할 바이너리 경로 (선택사항, 나중에 설정 가능)
        """
        self.binary_path = binary_path
        self._check_binary_exists()
    
    def set_binary_path(self, binary_path: str):
        self.binary_path = binary_path
        self._check_binary_exists()
    
    def _check_binary_exists(self):
        if self.binary_path and not Path(self.binary_path).exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
    
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
    
    # ========== 도구 메서드들 ==========
    
    def checksec(self, binary_path: Optional[str] = None) -> str:
        """
        checksec로 바이너리의 보호 기법 분석
        Returns: JSON 문자열
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        # checksec 명령어 실행
        result = self._run_command(['checksec', '--file', target])
        
        if not result["success"]:
            return json.dumps({
                "error": result.get("error", "checksec failed"),
                "stderr": result.get("stderr", "")
            }, indent=2)
        
        # [수정됨] checksec은 결과를 stderr로 출력하는 경우가 많으므로 둘 다 합침
        # stdout이 비어있으면 stderr를 사용
        output = result["stdout"]
        if not output.strip():
            output = result["stderr"]
            
        protections = self._parse_checksec_output(output)
        
        return json.dumps({
            "binary_path": target,
            "protections": protections,
        }, indent=2, ensure_ascii=False)
    
    def _parse_checksec_output(self, output: str) -> Dict[str, any]:
        protections = {}
        lines = output.split('\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                protections[key] = value
        
        return protections
    
    
    def ropgadget_search(
        self, 
        search_pattern: str,
        binary_path: Optional[str] = None,
        gadget_type: Optional[str] = None
    ) -> str:
        """
        ROPgadget으로 가젯 검색
        (ROPgadget --string 옵션은 제거하고, 파이썬에서 필터링합니다)
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        # [중요] --string 옵션 제거! (이게 있으면 가젯을 안 찾고 문자열만 찾습니다)
        cmd = ['ROPgadget', '--binary', target]
        
        # 가젯 타입 필터 (rop, jop, sys 등)
        if gadget_type:
            cmd.extend(['--type', gadget_type])
        
        # 실행 (시간이 좀 걸릴 수 있으니 timeout 주의)
        result = self._run_command(cmd, timeout=60) 
        
        if not result["success"]:
            return json.dumps({
                "error": result.get("error", "ROPgadget failed"),
                "stderr": result.get("stderr", "")
            }, indent=2)
        
        # 1. 모든 가젯 파싱
        all_gadgets = self._parse_ropgadget_output(result["stdout"])
        
        # 2. 파이썬 리스트에서 검색어(search_pattern)로 필터링
        filtered_gadgets = []
        if search_pattern:
            for g in all_gadgets:
                # 가젯 명령어에 검색 패턴이 포함되어 있는지 확인
                if search_pattern in g['instruction']:
                    filtered_gadgets.append(g)
        else:
            filtered_gadgets = all_gadgets
        
        return json.dumps({
            "binary_path": target,
            "search_pattern": search_pattern,
            "gadget_count": len(filtered_gadgets),
            "gadgets": filtered_gadgets
        }, indent=2, ensure_ascii=False)
    
    def _parse_ropgadget_output(self, output: str) -> List[Dict[str, str]]:
        gadgets = []
        lines = output.split('\n')
        
        for line in lines:
            # ROPgadget 출력 형식: 0x0000000000401234 : pop rdi ; ret
            if ':' in line and '0x' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    addr = parts[0].strip()
                    instruction = parts[1].strip()
                    gadgets.append({
                        "address": addr,
                        "instruction": instruction
                    })
        
        return gadgets
    
    def objdump_disassemble(
        self,
        function_name: Optional[str] = None,
        binary_path: Optional[str] = None,
        section: Optional[str] = None
    ) -> str:
        """
        objdump로 디스어셈블
        Args:
            function_name: 특정 함수만 디스어셈블 (선택사항)
            binary_path: 바이너리 경로 (선택사항)
            section: 특정 섹션만 디스어셈블 (선택사항)
        Returns: JSON 문자열
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        cmd = ['objdump', '-d', target]
        
        if function_name:
            cmd.extend(['--disassemble', function_name])
        elif section:
            cmd.extend(['-d', '--section', section])
        
        result = self._run_command(cmd)
        
        if not result["success"]:
            return json.dumps({
                "error": result.get("error", "objdump failed"),
                "stderr": result.get("stderr", "")
            }, indent=2)
        
        return json.dumps({
            "binary_path": target,
            "function": function_name or "all",
            "section": section or "all",
            "disassembly": result["stdout"]
        }, indent=2, ensure_ascii=False)
    
    def strings_extract(
        self,
        binary_path: Optional[str] = None,
        min_length: int = 4,
        filter_pattern: Optional[str] = None
    ) -> str:
        """
        strings로 바이너리에서 문자열 추출
        Args:
            binary_path: 바이너리 경로 (선택사항)
            min_length: 최소 문자열 길이 (기본값: 4)
            filter_pattern: 필터링할 패턴 (정규식, 선택사항)
        Returns: JSON 문자열
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        cmd = ['strings', '-n', str(min_length), target]
        result = self._run_command(cmd)
        
        if not result["success"]:
            return json.dumps({
                "error": result.get("error", "strings failed"),
                "stderr": result.get("stderr", "")
            }, indent=2)
        
        strings_list = result["stdout"].split('\n')
        strings_list = [s.strip() for s in strings_list if s.strip()]
        
        # 패턴 필터링
        if filter_pattern:
            pattern = re.compile(filter_pattern)
            strings_list = [s for s in strings_list if pattern.search(s)]
        
        return json.dumps({
            "binary_path": target,
            "min_length": min_length,
            "filter_pattern": filter_pattern,
            "string_count": len(strings_list),
            "strings": strings_list[:100],  # 최대 100개만 반환
            "total_found": len(strings_list)
        }, indent=2, ensure_ascii=False)
    
    def readelf_info(
        self,
        binary_path: Optional[str] = None,
        section: Optional[str] = None,
        info_type: str = "all"
    ) -> str:
        """
        readelf로 ELF 파일 정보 추출
        Args:
            binary_path: 바이너리 경로 (선택사항)
            section: 특정 섹션 정보만 (선택사항)
            info_type: 정보 타입 ('all', 'headers', 'sections', 'symbols', 'relocs')
        Returns: JSON 문자열
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})
        
        cmd = ['readelf']
        
        if info_type == "headers" or info_type == "all":
            cmd.extend(['-h', target])
        elif info_type == "sections":
            cmd.extend(['-S', target])
        elif info_type == "symbols":
            cmd.extend(['-s', target])
        elif info_type == "relocs":
            cmd.extend(['-r', target])
        else:
            cmd.extend(['-a', target])  # 모든 정보
        
        if section:
            cmd.extend(['--section', section])
        
        result = self._run_command(cmd)
        
        if not result["success"]:
            return json.dumps({
                "error": result.get("error", "readelf failed"),
                "stderr": result.get("stderr", "")
            }, indent=2)
        
        return json.dumps({
            "binary_path": target,
            "info_type": info_type,
            "section": section or "all",
            "elf_info": result["stdout"]
        }, indent=2, ensure_ascii=False)
    
    def one_gadget_search(
        self,
        libc_path: str
    ) -> str:
        """
        one_gadget으로 libc에서 one_gadget 검색
        Args:
            libc_path: libc 파일 경로
        Returns: JSON 문자열
        """
        if not Path(libc_path).exists():
            return json.dumps({"error": f"libc file not found: {libc_path}"})
        
        result = self._run_command(['one_gadget', libc_path])
        
        if not result["success"]:
            return json.dumps({
                "error": result.get("error", "one_gadget failed"),
                "stderr": result.get("stderr", "")
            }, indent=2)
        
        # one_gadget 출력 파싱
        gadgets = self._parse_one_gadget_output(result["stdout"])
        
        return json.dumps({
            "libc_path": libc_path,
            "gadget_count": len(gadgets),
            "gadgets": gadgets,
            "raw_output": result["stdout"]
        }, indent=2, ensure_ascii=False)
    
    def _parse_one_gadget_output(self, output: str) -> List[Dict[str, str]]:
        gadgets = []
        lines = output.split('\n')
        
        for line in lines:
            if line.strip() and not line.startswith('['):
                # one_gadget 출력 형식: 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
                if '0x' in line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        gadgets.append({
                            "address": parts[0],
                            "constraints": parts[1]
                        })
        
        return gadgets
    

    def _remove_ansi_colors(self, text: str) -> str:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def _validate_gdb_command(self, command: str, binary_path: str) -> Dict[str, any]:
        # 1. 바이너리가 실행 가능한지 확인
        if not os.path.exists(binary_path):
            return {"valid": False, "error": f"Binary not found: {binary_path}"}

        if not os.access(binary_path, os.R_OK):
            return {"valid": False, "error": f"Binary is not readable: {binary_path}"}

        # 2. 명령어에서 메모리 주소 추출 및 검증
        addr_pattern = r'0x[0-9a-fA-F]+'
        addresses = re.findall(addr_pattern, command)

        # 3. 위험한 명령어 패턴 확인
        dangerous_patterns = [
            r'rm\s+-rf',
            r'dd\s+if=',
            r'mkfs',
            r'format',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return {"valid": False, "error": f"Dangerous command pattern detected: {pattern}"}

        # 4. GDB 명령어 형식 검증
        valid_gdb_commands = [
            'info', 'x/', 'disassemble', 'break', 'run', 'continue',
            'step', 'next', 'print', 'set', 'vmmap', 'telescope',
            'checksec', 'cyclic', 'ropgadget', 'ropper', 'search',
            'find', 'pattern', 'quit', 'q', 'p', 'display'
        ]

        # 명령어의 첫 단어 추출
        first_word = command.split()[0] if command.split() else ""

        # x/ 명령어는 특별 처리 (메모리 검사)
        if first_word.startswith('x/'):
            # x/NNNxb 0xADDRESS 형식 검증
            if not addresses:
                return {"valid": False, "error": "x/ command requires a valid memory address"}
            return {"valid": True}

        # 일반 GDB 명령어 검증
        if not any(first_word.startswith(cmd) for cmd in valid_gdb_commands):
            return {
                "valid": False,
                "error": f"Unknown or unsafe GDB command: {first_word}. Use standard GDB commands only."
            }

        return {"valid": True}

    def pwndbg_debug(self, binary_path: Optional[str] = None, command: str = "info functions", commands: Optional[List[str]] = None) -> str:
        """
        GDB(Pwndbg)로 바이너리 디버깅
        Args:
            command: 단일 디버깅 명령 (예: 'vmmap', 'telescope', 'info functions')
            commands: 복수 디버깅 명령 리스트 (예: ['break main', 'run', 'info registers'])
            binary_path: 바이너리 경로

        Note:
            - command와 commands 중 하나만 사용
            - 복수 명령어는 GDB 스크립트 파일로 실행됨
        """
        target = binary_path or self.binary_path
        if not target:
            return json.dumps({"error": "binary_path is required"})

        # FreeBSD/비호환 바이너리 감지 및 차단
        try:
            file_check = subprocess.run(
                ["file", target],
                capture_output=True,
                text=True,
                timeout=5
            )
            file_output = file_check.stdout.lower()

            if "freebsd" in file_output:
                # FreeBSD 바이너리: 실행 및 메모리 접근 명령 차단
                all_commands = commands if commands else [command]

                # 실행 필요 명령어 패턴 (run, start, 메모리 검사)
                execution_patterns = [
                    'run', 'start', 'continue', 'step', 'next', 'finish',
                    'x/', 'examine', 'print ', 'p ', 'display', 'watch',
                    'break *', 'b *'  # 메모리 주소 브레이크포인트
                ]

                for cmd in all_commands:
                    if cmd:
                        cmd_lower = cmd.lower().strip()
                        for pattern in execution_patterns:
                            if pattern in cmd_lower:
                                return json.dumps({
                                    "error": "CRITICAL: Cannot execute FreeBSD binary on Linux - Memory commands require execution",
                                    "binary_type": "FreeBSD",
                                    "blocked_command": cmd,
                                    "blocked_pattern": pattern,
                                    "reason": "FreeBSD binaries use /libexec/ld-elf.so.1 (incompatible with Linux). Memory is UNINITIALIZED without execution.",
                                    "why_this_fails": f"Command '{pattern}' requires the binary to be RUNNING. FreeBSD binaries CANNOT run on Linux.",
                                    "allowed_gdb_commands": [
                                        "info functions - List all functions",
                                        "info variables - List global variables",
                                        "info files - Show file/section info",
                                        "disassemble <function> - Disassemble WITHOUT execution"
                                    ],
                                    "recommended_tools": [
                                        "ghidra_decompile(function_address='0x...') - BEST for reading code logic",
                                        "objdump_disassemble(start_address='0x...') - Get assembly",
                                        "strings(binary_path) - Extract hardcoded strings",
                                        "readelf -a - Analyze ELF structure"
                                    ]
                                }, indent=2)

        except Exception:
            pass  # 파일 체크 실패 시 계속 진행

        # 복수 명령어 처리
        if commands and isinstance(commands, list):
            # 임시 GDB 스크립트 파일 생성
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                script_path = f.name
                for cmd in commands:
                    # 각 명령어 검증
                    validation = self._validate_gdb_command(cmd, target)
                    if not validation.get("valid", False):
                        os.unlink(script_path)
                        return json.dumps({
                            "error": "Command validation failed",
                            "details": validation.get("error", "Unknown validation error"),
                            "command": cmd,
                            "suggestion": "Check your GDB commands for correctness"
                        }, indent=2)
                    f.write(cmd + '\n')

            # GDB 스크립트 실행
            gdb_cmd = ['gdb', '--batch', '-x', script_path, target]
            run_result = self._run_command(gdb_cmd, timeout=30)

            # 스크립트 파일 삭제
            try:
                os.unlink(script_path)
            except:
                pass

            if not run_result["success"]:
                return json.dumps({
                    "error": run_result.get("error", "GDB script execution failed"),
                    "stderr": run_result.get("stderr", ""),
                    "commands": commands
                }, indent=2)

            cleaned_output = self._remove_ansi_colors(run_result["stdout"])
            return json.dumps({
                "binary_path": target,
                "commands": commands,
                "result": cleaned_output
            }, indent=2, ensure_ascii=False)

        # 단일 명령어 처리
        validation = self._validate_gdb_command(command, target)
        if not validation.get("valid", False):
            return json.dumps({
                "error": "Command validation failed",
                "details": validation.get("error", "Unknown validation error"),
                "command": command,
                "suggestion": "Try using standard GDB commands like 'info functions', 'disassemble main', or 'vmmap'"
            }, indent=2)

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
        
    def _find_function_by_address(self, fm, address_str: str) -> Optional:
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

# ========== LangChain 도구로 변환하는 함수들 ==========

def create_pwnable_tools(binary_path: Optional[str] = None) -> List[BaseTool]:
    """
    PwnableTool의 메서드들을 개별 LangChain 도구로 변환
    
    Args:
        binary_path: 기본 바이너리 경로
    
    Returns:
        LangChain BaseTool 리스트
    """
    tool_instance = PwnableTool(binary_path)
    
    # 각 메서드를 별도 도구로 생성
    tools = [
        StructuredTool.from_function(
            func=tool_instance.checksec,
            name="checksec_analysis",
            description="Analyzes binary protection mechanisms (NX, PIE, RELRO, Canary, etc.). If binary_path is not specified, uses the path set during initialization."
        ),
        StructuredTool.from_function(
            func=tool_instance.ropgadget_search,
            name="rop_gadget_search",
            description="Searches for ROP gadgets using ROPgadget. Specify the gadget pattern to search with search_pattern (e.g., 'pop rdi', 'ret').",
            args_schema=type('ROPArgs', (BaseModel,), {
                '__annotations__': {
                    'search_pattern': str,
                    'binary_path': Optional[str],
                    'gadget_type': Optional[str]
                },
                'search_pattern': Field(description="Gadget pattern to search (e.g., 'pop rdi', 'ret')"),
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'gadget_type': Field(default=None, description="Gadget type filter (optional)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.objdump_disassemble,
            name="objdump_disassemble",
            description="Disassembles binary using objdump. Can disassemble specific functions or sections only.",
            args_schema=type('ObjdumpArgs', (BaseModel,), {
                '__annotations__': {
                    'function_name': Optional[str],
                    'binary_path': Optional[str],
                    'section': Optional[str]
                },
                'function_name': Field(default=None, description="Function name to disassemble specific function only (optional)"),
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'section': Field(default=None, description="Specific section to disassemble (optional)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.strings_extract,
            name="strings_extract",
            description="Extracts strings from binary. Can specify minimum length and filter pattern.",
            args_schema=type('StringsArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'min_length': int,
                    'filter_pattern': Optional[str]
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'min_length': Field(default=4, description="Minimum string length (default: 4)"),
                'filter_pattern': Field(default=None, description="Regex pattern for filtering (optional)")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.readelf_info,
            name="readelf_info",
            description="Extracts ELF file information. Can query headers, sections, symbols, relocation information, etc.",
            args_schema=type('ReadelfArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'section': Optional[str],
                    'info_type': str
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'section': Field(default=None, description="Specific section to query (optional)"),
                'info_type': Field(default="all", description="Info type: 'all', 'headers', 'sections', 'symbols', 'relocs'")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.one_gadget_search,
            name="one_gadget_search",
            description="Searches for one_gadget in libc file using one_gadget tool.",
            args_schema=type('OneGadgetArgs', (BaseModel,), {
                '__annotations__': {
                    'libc_path': str
                },
                'libc_path': Field(description="Path to libc or binary file")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.pwndbg_debug,
            name="gdb_debug",
            description="Debugs binary using gdb. Supports both single command and multiple commands via script file. For complex debugging scenarios with multiple steps (break, run, examine memory), use 'commands' parameter with a list of GDB commands.",
            args_schema=type('GdbArgs', (BaseModel,), {
                '__annotations__': {
                    'binary_path': Optional[str],
                    'command': str,
                    'commands': Optional[List[str]]
                },
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'command': Field(default="info functions", description="Single debugging command (e.g., 'vmmap', 'disassemble main')"),
                'commands': Field(default=None, description="List of multiple GDB commands for complex debugging sequences (e.g., ['break main', 'run', 'info registers', 'quit'])")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.ghidra_decompile,
            name="ghidra_decompile",
            description="Decompiles specific function of binary using Ghidra. Finds function by name or address and returns decompiled code and assembly code.",
            args_schema=type('GhidraArgs', (BaseModel,), {
                '__annotations__': {
                    'function_name': Optional[str],
                    'binary_path': Optional[str],
                    'function_address': Optional[str],
                    'analyze_binary': bool
                },
                'function_name': Field(default=None, description="Function name or address to decompile (e.g., 'main', '0x401200', '401200')"),
                'binary_path': Field(default=None, description="Binary path (optional)"),
                'function_address': Field(default=None, description="Function address (hex, e.g., '0x401200' or '401200')"),
                'analyze_binary': Field(default=True, description="Whether to analyze binary")
            })
        ),
    ]
    
    return tools
