import subprocess
import json
import re
import os
import shlex
import base64
import urllib.parse
import binascii
from typing import Optional, List, Dict
from pathlib import Path
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False


class WebTool:
    def __init__(self, url: Optional[str] = None):
        """
        Args:
            url: 분석할 웹사이트 URL (선택사항, 나중에 설정 가능)
        """
        self.url = url
        self._check_url_valid()
    
    def set_url(self, url: str):
        """URL 설정"""
        self.url = url
        self._check_url_valid()
    
    def _check_url_valid(self):
        """URL 유효성 검사"""
        if self.url and not (self.url.startswith("http://") or self.url.startswith("https://")):
            raise ValueError(f"Invalid URL format: {self.url}. Must start with http:// or https://")
    
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
    
    def http_request(
        self,
        url: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: int = 10
    ) -> str:
        """
        HTTP 요청을 보내고 응답을 분석합니다.
        
        Args:
            url: 요청할 URL (선택사항, self.url 사용 가능)
            method: HTTP 메서드 (GET, POST, PUT, DELETE 등)
            headers: HTTP 헤더 딕셔너리
            data: 요청 본문 데이터 (POST/PUT용)
            params: URL 쿼리 파라미터
            cookies: 쿠키 딕셔너리
            timeout: 타임아웃 (초)
        
        Returns:
            JSON 형식의 응답 결과
        """
        target_url = url or self.url
        if not target_url:
            return json.dumps({"error": "url is required"}, indent=2)
        
        if not REQUESTS_AVAILABLE:
            return json.dumps({
                "error": "requests library is not available. Please install: pip install requests"
            }, indent=2)
        
        try:
            method = method.upper()
            request_kwargs = {
                "timeout": timeout,
                "allow_redirects": True
            }
            
            if headers:
                request_kwargs["headers"] = headers
            if params:
                request_kwargs["params"] = params
            if cookies:
                request_kwargs["cookies"] = cookies
            
            if method in ["POST", "PUT", "PATCH"]:
                if data:
                    request_kwargs["data"] = data
            
            response = requests.request(method, target_url, **request_kwargs)
            
            # 응답 본문 크기 제한 (LLM 컨텍스트 고려)
            body_preview = response.text[:5000] if len(response.text) > 5000 else response.text
            body_truncated = len(response.text) > 5000
            
            return json.dumps({
                "url": target_url,
                "method": method,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "body_preview": body_preview,
                "body_truncated": body_truncated,
                "body_length": len(response.text),
                "redirect_history": [{"url": r.url, "status": r.status_code} for r in response.history],
                "final_url": response.url
            }, indent=2, ensure_ascii=False)
            
        except requests.exceptions.Timeout:
            return json.dumps({
                "error": f"Request timed out after {timeout} seconds",
                "url": target_url
            }, indent=2)
        except requests.exceptions.RequestException as e:
            return json.dumps({
                "error": f"Request failed: {str(e)}",
                "url": target_url
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "error": f"Unexpected error: {str(e)}",
                "url": target_url
            }, indent=2)
    
    def directory_bruteforce(
        self,
        url: Optional[str] = None,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        status_codes: Optional[List[int]] = None,
        timeout: int = 30
    ) -> str:
        """
        디렉토리/파일 브루트포싱을 수행합니다.
        
        Args:
            url: 대상 URL (선택사항, self.url 사용 가능)
            wordlist: 워드리스트 파일 경로 (없으면 기본 워드리스트 사용)
            extensions: 파일 확장자 리스트 (예: ["php", "html", "txt"])
            status_codes: 유효한 상태 코드 리스트 (기본: [200, 301, 302, 403])
            timeout: 타임아웃 (초)
        
        Returns:
            JSON 형식의 스캔 결과
        """
        target_url = url or self.url
        if not target_url:
            return json.dumps({"error": "url is required"}, indent=2)
        
        # 기본 워드리스트 (간단한 버전)
        default_wordlist = [
            "admin", "api", "backup", "config", "database", "dev", "docs", "download",
            "files", "images", "img", "include", "index", "js", "login", "mail",
            "panel", "php", "private", "public", "scripts", "src", "static", "test",
            "tmp", "upload", "uploads", "www", "assets", "css", "lib", "libs",
            ".git", ".svn", ".env", "robots.txt", "sitemap.xml", ".htaccess"
        ]
        
        if wordlist and Path(wordlist).exists():
            try:
                with open(wordlist, 'r') as f:
                    wordlist_items = [line.strip() for line in f if line.strip()]
            except Exception as e:
                return json.dumps({
                    "error": f"Failed to read wordlist: {str(e)}",
                    "url": target_url
                }, indent=2)
        else:
            wordlist_items = default_wordlist
        
        if not status_codes:
            status_codes = [200, 301, 302, 403]
        
        if not REQUESTS_AVAILABLE:
            return json.dumps({
                "error": "requests library is not available. Please install: pip install requests"
            }, indent=2)
        
        found_paths = []
        total_tested = 0
        
        # 기본 경로 테스트
        for word in wordlist_items[:100]:  # LLM 컨텍스트 고려하여 제한
            total_tested += 1
            test_urls = [f"{target_url.rstrip('/')}/{word}"]
            
            # 확장자 추가
            if extensions:
                for ext in extensions:
                    test_urls.append(f"{target_url.rstrip('/')}/{word}.{ext}")
            
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code in status_codes:
                        found_paths.append({
                            "url": test_url,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "headers": dict(response.headers)
                        })
                except requests.exceptions.RequestException:
                    pass
        
        return json.dumps({
            "url": target_url,
            "wordlist_size": len(wordlist_items),
            "tested": total_tested,
            "found_paths": found_paths,
            "found_count": len(found_paths)
        }, indent=2, ensure_ascii=False)
    
    def encode_decode(
        self,
        data: str,
        operation: str = "auto",
        encoding_type: Optional[str] = None
    ) -> str:
        """
        데이터를 인코딩/디코딩합니다.
        
        Args:
            data: 인코딩/디코딩할 데이터
            operation: "encode", "decode", 또는 "auto" (자동 감지)
            encoding_type: "base64", "url", "hex", "html", "unicode" (operation이 "auto"일 때는 선택사항)
        
        Returns:
            JSON 형식의 결과
        """
        if not data:
            return json.dumps({"error": "data is required"}, indent=2)
        
        results = {}
        
        # 자동 감지 모드
        if operation == "auto":
            # Base64 디코딩 시도
            try:
                decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
                results["base64_decode"] = decoded
            except:
                pass
            
            # URL 디코딩 시도
            try:
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    results["url_decode"] = decoded
            except:
                pass
            
            # Hex 디코딩 시도
            try:
                if all(c in "0123456789abcdefABCDEF" for c in data.replace(" ", "").replace(":", "")):
                    hex_clean = data.replace(" ", "").replace(":", "")
                    decoded = bytes.fromhex(hex_clean).decode('utf-8', errors='ignore')
                    results["hex_decode"] = decoded
            except:
                pass
            
            # HTML 디코딩 시도
            try:
                import html
                decoded = html.unescape(data)
                if decoded != data:
                    results["html_decode"] = decoded
            except:
                pass
            
            # 인코딩도 시도
            results["base64_encode"] = base64.b64encode(data.encode('utf-8')).decode('utf-8')
            results["url_encode"] = urllib.parse.quote(data)
            results["hex_encode"] = data.encode('utf-8').hex()
            
            return json.dumps({
                "input": data,
                "operation": "auto",
                "results": results
            }, indent=2, ensure_ascii=False)
        
        # 특정 인코딩 타입 지정
        if not encoding_type:
            return json.dumps({
                "error": "encoding_type is required when operation is not 'auto'"
            }, indent=2)
        
        encoding_type = encoding_type.lower()
        
        try:
            if operation == "encode":
                if encoding_type == "base64":
                    result = base64.b64encode(data.encode('utf-8')).decode('utf-8')
                elif encoding_type == "url":
                    result = urllib.parse.quote(data)
                elif encoding_type == "hex":
                    result = data.encode('utf-8').hex()
                elif encoding_type == "html":
                    import html
                    result = html.escape(data)
                else:
                    return json.dumps({
                        "error": f"Unsupported encoding type: {encoding_type}"
                    }, indent=2)
                
            elif operation == "decode":
                if encoding_type == "base64":
                    result = base64.b64decode(data).decode('utf-8', errors='replace')
                elif encoding_type == "url":
                    result = urllib.parse.unquote(data)
                elif encoding_type == "hex":
                    hex_clean = data.replace(" ", "").replace(":", "")
                    result = bytes.fromhex(hex_clean).decode('utf-8', errors='replace')
                elif encoding_type == "html":
                    import html
                    result = html.unescape(data)
                else:
                    return json.dumps({
                        "error": f"Unsupported encoding type: {encoding_type}"
                    }, indent=2)
            else:
                return json.dumps({
                    "error": f"Invalid operation: {operation}. Must be 'encode', 'decode', or 'auto'"
                }, indent=2)
            
            return json.dumps({
                "input": data,
                "operation": operation,
                "encoding_type": encoding_type,
                "result": result
            }, indent=2, ensure_ascii=False)
            
        except Exception as e:
            return json.dumps({
                "error": f"Encoding/decoding failed: {str(e)}",
                "input": data,
                "operation": operation,
                "encoding_type": encoding_type
            }, indent=2)
    
    def jwt_decode(
        self,
        token: str,
        secret: Optional[str] = None,
        verify: bool = True
    ) -> str:
        """
        JWT 토큰을 디코딩하고 검증합니다.
        
        Args:
            token: JWT 토큰 문자열
            secret: 검증에 사용할 비밀키 (선택사항)
            verify: 토큰 서명 검증 여부
        
        Returns:
            JSON 형식의 디코딩 결과
        """
        if not token:
            return json.dumps({"error": "token is required"}, indent=2)
        
        if not JWT_AVAILABLE:
            return json.dumps({
                "error": "PyJWT library is not available. Please install: pip install PyJWT"
            }, indent=2)
        
        try:
            # 토큰 파싱 (서명 검증 없이)
            parts = token.split('.')
            if len(parts) != 3:
                return json.dumps({
                    "error": "Invalid JWT format. Expected 3 parts separated by '.'"
                }, indent=2)
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Base64 디코딩 (패딩 추가)
            def decode_base64(data):
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += '=' * padding
                return base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
            
            header = json.loads(decode_base64(header_encoded))
            payload = json.loads(decode_base64(payload_encoded))
            
            result = {
                "token": token,
                "header": header,
                "payload": payload,
                "signature": signature_encoded,
                "algorithm": header.get("alg", "unknown")
            }
            
            # 서명 검증 시도
            if verify and secret:
                try:
                    decoded = jwt.decode(token, secret, algorithms=[header.get("alg", "HS256")])
                    result["verified"] = True
                    result["decoded_payload"] = decoded
                except jwt.InvalidSignatureError:
                    result["verified"] = False
                    result["error"] = "Invalid signature"
                except jwt.ExpiredSignatureError:
                    result["verified"] = False
                    result["error"] = "Token expired"
                except Exception as e:
                    result["verified"] = False
                    result["error"] = str(e)
            elif verify and not secret:
                result["warning"] = "Verification requested but no secret provided"
            
            return json.dumps(result, indent=2, ensure_ascii=False)
            
        except json.JSONDecodeError as e:
            return json.dumps({
                "error": f"Failed to decode JWT payload: {str(e)}",
                "token": token
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "error": f"JWT decoding failed: {str(e)}",
                "token": token
            }, indent=2)
    
    def sqlmap_scan(
        self,
        url: Optional[str] = None,
        data: Optional[str] = None,
        method: str = "GET",
        cookie: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        timeout: int = 60
    ) -> str:
        """
        SQLMap을 사용하여 SQL Injection 취약점을 스캔합니다.
        
        Args:
            url: 대상 URL (선택사항, self.url 사용 가능)
            data: POST 데이터 (예: "id=1&name=test")
            method: HTTP 메서드 (GET 또는 POST)
            cookie: 쿠키 문자열
            level: 스캔 레벨 (1-5, 기본: 1)
            risk: 위험도 (1-3, 기본: 1)
            timeout: 타임아웃 (초)
        
        Returns:
            JSON 형식의 스캔 결과
        """
        target_url = url or self.url
        if not target_url:
            return json.dumps({"error": "url is required"}, indent=2)
        
        # sqlmap 명령어 구성 (가상환경의 sqlmap 우선 사용)
        sqlmap_path = None
        if os.path.exists("/home/wjddn0623/.venv/bin/sqlmap"):
            sqlmap_path = "/home/wjddn0623/.venv/bin/sqlmap"
        else:
            # PATH에서 sqlmap 찾기
            which_result = self._run_command(["which", "sqlmap"])
            if which_result["success"] and which_result["stdout"].strip():
                sqlmap_path = which_result["stdout"].strip()
            else:
                # python -m sqlmap 사용
                sqlmap_path = "python3"
                cmd = [sqlmap_path, "-m", "sqlmap", "-u", target_url, "--batch", "--level", str(level), "--risk", str(risk)]
        
        if sqlmap_path and sqlmap_path != "python3":
            cmd = [sqlmap_path, "-u", target_url, "--batch", "--level", str(level), "--risk", str(risk)]
        
        if method.upper() == "POST" and data:
            cmd.extend(["--data", data])
        
        if cookie:
            cmd.extend(["--cookie", cookie])
        
        # 결과를 파일로 저장
        import tempfile
        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        output_file.close()
        cmd.extend(["--output-dir", os.path.dirname(output_file.name)])
        
        run_result = self._run_command(cmd, timeout=timeout)
        
        result_data = {
            "url": target_url,
            "method": method,
            "command": " ".join(cmd),
            "success": run_result["success"]
        }
        
        if run_result["success"]:
            # stdout에서 취약점 정보 추출
            output = run_result["stdout"]
            
            # SQLMap 출력 파싱
            vulnerabilities = []
            if "sqlmap identified" in output.lower() or "injection" in output.lower():
                # 취약점 발견 패턴 추출
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    if "injection" in line.lower() or "vulnerable" in line.lower():
                        vulnerabilities.append({
                            "line": line.strip(),
                            "context": "\n".join(lines[max(0, i-2):min(len(lines), i+3)])
                        })
            
            result_data["vulnerabilities_found"] = len(vulnerabilities) > 0
            result_data["vulnerabilities"] = vulnerabilities
            result_data["output"] = output[:5000]  # 출력 제한
            result_data["output_truncated"] = len(output) > 5000
        else:
            result_data["error"] = run_result.get("error", "sqlmap scan failed")
            result_data["stderr"] = run_result.get("stderr", "")
        
        # 임시 파일 정리
        try:
            if os.path.exists(output_file.name):
                os.unlink(output_file.name)
        except:
            pass
        
        return json.dumps(result_data, indent=2, ensure_ascii=False)


# ========== LangChain 도구로 변환하는 함수들 ==========

def create_web_tools(url: Optional[str] = None) -> List[BaseTool]:
    """
    Converts WebTool methods into individual LangChain tools
    
    Args:
        url: Default URL
    
    Returns:
        List of LangChain BaseTool
    """
    tool_instance = WebTool(url)
    
    # 각 메서드를 별도 도구로 생성
    tools = [
        StructuredTool.from_function(
            func=tool_instance.http_request,
            name="http_request",
            description="Sends HTTP request and analyzes response. Supports various methods like GET, POST, PUT, DELETE, etc.",
            args_schema=type('HttpRequestArgs', (BaseModel,), {
                '__annotations__': {
                    'url': Optional[str],
                    'method': str,
                    'headers': Optional[Dict[str, str]],
                    'data': Optional[str],
                    'params': Optional[Dict[str, str]],
                    'cookies': Optional[Dict[str, str]],
                    'timeout': int
                },
                'url': Field(default=None, description="URL to request (optional, can use URL set during initialization)"),
                'method': Field(default="GET", description="HTTP method (GET, POST, PUT, DELETE, etc.)"),
                'headers': Field(default=None, description="HTTP headers dictionary (optional)"),
                'data': Field(default=None, description="Request body data (for POST/PUT, optional)"),
                'params': Field(default=None, description="URL query parameters (optional)"),
                'cookies': Field(default=None, description="Cookies dictionary (optional)"),
                'timeout': Field(default=10, description="Timeout in seconds")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.directory_bruteforce,
            name="directory_bruteforce",
            description="Performs directory/file bruteforcing. Can find hidden paths or files.",
            args_schema=type('DirectoryBruteforceArgs', (BaseModel,), {
                '__annotations__': {
                    'url': Optional[str],
                    'wordlist': Optional[str],
                    'extensions': Optional[List[str]],
                    'status_codes': Optional[List[int]],
                    'timeout': int
                },
                'url': Field(default=None, description="Target URL (optional)"),
                'wordlist': Field(default=None, description="Wordlist file path (uses default wordlist if not provided)"),
                'extensions': Field(default=None, description="File extension list (e.g., ['php', 'html', 'txt'])"),
                'status_codes': Field(default=None, description="Valid status codes list (default: [200, 301, 302, 403])"),
                'timeout': Field(default=30, description="Timeout in seconds")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.encode_decode,
            name="encode_decode",
            description="Encodes/decodes data. Supports various formats like Base64, URL, Hex, HTML, etc.",
            args_schema=type('EncodeDecodeArgs', (BaseModel,), {
                '__annotations__': {
                    'data': str,
                    'operation': str,
                    'encoding_type': Optional[str]
                },
                'data': Field(description="Data to encode/decode"),
                'operation': Field(default="auto", description="'encode', 'decode', or 'auto' (auto-detect)"),
                'encoding_type': Field(default=None, description="'base64', 'url', 'hex', 'html' (optional when operation is 'auto')")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.jwt_decode,
            name="jwt_decode",
            description="Decodes and verifies JWT token. Can analyze header, payload, and signature.",
            args_schema=type('JwtDecodeArgs', (BaseModel,), {
                '__annotations__': {
                    'token': str,
                    'secret': Optional[str],
                    'verify': bool
                },
                'token': Field(description="JWT token string"),
                'secret': Field(default=None, description="Secret key for verification (optional)"),
                'verify': Field(default=True, description="Whether to verify token signature")
            })
        ),
        StructuredTool.from_function(
            func=tool_instance.sqlmap_scan,
            name="sqlmap_scan",
            description="Scans for SQL Injection vulnerabilities using SQLMap.",
            args_schema=type('SqlmapScanArgs', (BaseModel,), {
                '__annotations__': {
                    'url': Optional[str],
                    'data': Optional[str],
                    'method': str,
                    'cookie': Optional[str],
                    'level': int,
                    'risk': int,
                    'timeout': int
                },
                'url': Field(default=None, description="Target URL (optional)"),
                'data': Field(default=None, description="POST data (e.g., 'id=1&name=test')"),
                'method': Field(default="GET", description="HTTP method (GET or POST)"),
                'cookie': Field(default=None, description="Cookie string (optional)"),
                'level': Field(default=1, description="Scan level (1-5, default: 1)"),
                'risk': Field(default=1, description="Risk level (1-3, default: 1)"),
                'timeout': Field(default=60, description="Timeout in seconds")
            })
        ),
    ]
    
    return tools
