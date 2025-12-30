from typing import List, Dict, Any, Optional
from templates.prompting import few_Shot

FEWSHOT = few_Shot()

# 카테고리별 기본 few-shot 매핑
CATEGORY_FEWSHOTS = {
    "web": [
        ("sqli", FEWSHOT.web_SQLI),
        ("ssti", FEWSHOT.web_SSTI),
        ("lfi", FEWSHOT.web_LFI),
    ],
    "pwnable": [
        ("bof", FEWSHOT.pwn_stack_bof),
        ("format", FEWSHOT.pwn_format_string),
        ("ret2libc", FEWSHOT.pwn_ret2libc),
    ],
    "reversing": [
        ("static", FEWSHOT.rev_static_analysis),
        ("dynamic", FEWSHOT.rev_dynamic_analysis),
    ],
    "forensics": [
        ("pcap", FEWSHOT.forensics_PCAP),
        ("memory", FEWSHOT.forensics_MEMORY),
    ],
    "crypto": [
        ("rsa", FEWSHOT.crypto_weak_rsa),
        ("xor", FEWSHOT.crypto_xor),
    ],
}

# 키워드 기반 few-shot 매핑 (signals/description에서 감지)
KEYWORD_FEWSHOTS = {
    # Web
    "sql": FEWSHOT.web_SQLI,
    "sqli": FEWSHOT.web_SQLI,
    "injection": FEWSHOT.web_SQLI,
    "login": FEWSHOT.web_SQLI,
    "ssti": FEWSHOT.web_SSTI,
    "template": FEWSHOT.web_SSTI,
    "jinja": FEWSHOT.web_SSTI,
    "lfi": FEWSHOT.web_LFI,
    "file inclusion": FEWSHOT.web_LFI,
    "path traversal": FEWSHOT.web_LFI,

    # Pwnable
    "bof": FEWSHOT.pwn_stack_bof,
    "buffer overflow": FEWSHOT.pwn_stack_bof,
    "stack": FEWSHOT.pwn_stack_bof,
    "gets": FEWSHOT.pwn_stack_bof,
    "strcpy": FEWSHOT.pwn_stack_bof,
    "format string": FEWSHOT.pwn_format_string,
    "printf": FEWSHOT.pwn_format_string,
    "%p": FEWSHOT.pwn_format_string,
    "%n": FEWSHOT.pwn_format_string,
    "ret2libc": FEWSHOT.pwn_ret2libc,
    "rop": FEWSHOT.pwn_ret2libc,
    "nx enabled": FEWSHOT.pwn_ret2libc,

    # Reversing
    "license": FEWSHOT.rev_static_analysis,
    "serial": FEWSHOT.rev_static_analysis,
    "keygen": FEWSHOT.rev_static_analysis,
    "antidebug": FEWSHOT.rev_dynamic_analysis,
    "anti-debug": FEWSHOT.rev_dynamic_analysis,
    "ptrace": FEWSHOT.rev_dynamic_analysis,

    # Forensics
    "pcap": FEWSHOT.forensics_PCAP,
    "wireshark": FEWSHOT.forensics_PCAP,
    "network": FEWSHOT.forensics_PCAP,
    "memory dump": FEWSHOT.forensics_MEMORY,
    "volatility": FEWSHOT.forensics_MEMORY,
    ".dmp": FEWSHOT.forensics_MEMORY,

    # Crypto
    "rsa": FEWSHOT.crypto_weak_rsa,
    "modulus": FEWSHOT.crypto_weak_rsa,
    "public key": FEWSHOT.crypto_weak_rsa,
    "xor": FEWSHOT.crypto_xor,
    "cipher": FEWSHOT.crypto_xor,
}


def select_fewshots(
    category: str,
    description: str = "",
    signals: List[Dict] = None,
    max_examples: int = 3
) -> List[str]:
    category = category.lower()
    signals = signals or []
    selected = []
    seen_types = set()

    # 1. 키워드 기반 선택 (description + signals에서)
    search_text = description.lower()
    for signal in signals:
        search_text += " " + str(signal).lower()

    for keyword, fewshot in KEYWORD_FEWSHOTS.items():
        if keyword in search_text and fewshot not in selected:
            selected.append(fewshot)
            seen_types.add(keyword.split()[0])  # 첫 단어로 타입 구분
            if len(selected) >= max_examples:
                return selected

    # 2. 카테고리별 기본 few-shot 추가
    if category in CATEGORY_FEWSHOTS:
        for vuln_type, fewshot in CATEGORY_FEWSHOTS[category]:
            if fewshot not in selected:
                selected.append(fewshot)
                if len(selected) >= max_examples:
                    return selected

    # 3. 부족하면 다른 카테고리에서 범용적인 것 추가
    fallback_order = ["pwnable", "web", "crypto", "forensics", "reversing"]
    for fallback_cat in fallback_order:
        if fallback_cat == category:
            continue
        if fallback_cat in CATEGORY_FEWSHOTS:
            for _, fewshot in CATEGORY_FEWSHOTS[fallback_cat]:
                if fewshot not in selected:
                    selected.append(fewshot)
                    if len(selected) >= max_examples:
                        return selected

    return selected


def build_fewshot_messages(
    category: str,
    description: str = "",
    signals: List[Dict] = None,
    max_examples: int = 3
) -> List[Dict[str, str]]:

    fewshots = select_fewshots(category, description, signals, max_examples)
    return [{"role": "user", "content": fs} for fs in fewshots]


def get_category_hints(category: str) -> str:
    hints = {
        "web": """
WEB-SPECIFIC HINTS:
- Check for common web vulnerabilities: SQLi, XSS, SSTI, LFI/RFI, SSRF, XXE
- Analyze source code for user input handling and database queries
- Look for authentication/session management flaws
- Test endpoints with various payloads before deeper exploitation
""",
        "pwnable": """
PWNABLE-SPECIFIC HINTS:
- Always start with checksec to understand protections
- Identify the vulnerability type: BOF, format string, heap, race condition
- Calculate offsets precisely using cyclic patterns
- Consider the attack chain: leak -> calculate -> exploit
- Check for win functions, gadgets, or shellcode opportunities
""",
        "reversing": """
REVERSING-SPECIFIC HINTS:
- Start with static analysis: strings, imports, main function
- Identify the validation/check logic
- Look for anti-debugging techniques
- Trace data flow from input to validation
- Consider using dynamic analysis (gdb, ltrace) for complex checks
""",
        "forensics": """
FORENSICS-SPECIFIC HINTS:
- Identify file types and extract embedded data
- For PCAPs: filter by protocol, follow TCP streams
- For memory dumps: identify OS profile first, then extract artifacts
- Look for encoded/encrypted data that needs decoding
- Check file metadata and timestamps
""",
        "crypto": """
CRYPTO-SPECIFIC HINTS:
- Identify the cryptographic algorithm used
- Look for implementation weaknesses, not algorithm breaks
- Check for: small exponents, reused keys, weak PRNGs, ECB mode
- Consider known-plaintext or chosen-plaintext attacks
- Mathematical analysis may be needed for custom algorithms
""",
    }
    return hints.get(category.lower(), "")
