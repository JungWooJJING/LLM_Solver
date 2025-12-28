expand_k = 4

STATE_SPEC = (
    "STATE is the single source of truth.\n"
    "- goal: one-line objective\n"
    "- constraints: hard rules\n"
    "- env: tools/OS/limits\n"
    "- facts: stable key-values (hashes, offsets, mitigations)\n"
    "- artifacts: produced files/paths\n"
    "- results: recent attempts {cmd, ok, stdout, signals[]}\n"
    "Policies: obey constraints; build on artifacts/results.\n"
)

def build_query(option: str, code: str = "", state = None, CoT = None, Cal = None, plan = None, Instruction = None, planning_context = None, available_tools = None, tool_category = None, fallback_mode = None):
    if option == "--file":
        prompt = (
            "You are a planning assistant for CTF automation.\n\n"
            "You will be given the content of a file related to a CTF challenge "
            "(e.g., source code, binary disassembly, script, or captured data).\n"
            "Do NOT solve or exploit. Propose several DISTINCT next-step investigative/preparatory actions for the very next cycle.\n\n"
            "[File Content]\n{code}\n\n"
            "Generate {expand_k} distinct candidates.\n"
            "For each candidate:\n"
            "- Provide a short Chain-of-Thought (3–5 sentences) explaining WHY this step is useful, HOW to attempt it, and WHAT evidence/artifacts it may produce.\n"
            "- Extract a one-line actionable 'thought' (imperative, deterministic).\n"
            "- List expected artifacts, required tools/permissions, a brief risk note, and estimated cost.\n"
            "- Avoid trivial variations and duplicates.\n\n"
            "Return ONLY valid JSON (no markdown, no code fences, no prose). If invalid, return {{\"error\":\"BAD_OUTPUT\"}}.\n"
            "JSON schema:\n"
            "{{\n"
            '  "candidates": [\n'
            "    {{\n"
            '      "vuln": "Stack BOF | SQLi | SSTI ...",\n'
            '      "why": "concrete evidence ≤120 chars",\n'
            '      "cot_now": "2–4 sentences on immediate plan & rationale",\n'
            '      "tasks": [{{"name":"short label","cmd":"exact terminal command","success":"substring or re:<regex>","artifact":"- or filename"}}],\n'
            '      "expected_signals": [{{"type":"leak|crash|offset|mitigation|other","name":"e.g., canary|libc_base|rip_offset","hint":"existence/value/format"}}]\n'
            "    }}\n"
            "  ]\n"
            "}}\n"
        ).format(code=code, expand_k=expand_k)
        return prompt

    elif option == "--ghidra":
        prompt = (
            "You are a planning assistant for CTF automation using Ghidra outputs.\n\n"
            "You will be given per-function artifacts from Ghidra (function name, decompiled C, disassembly, xrefs, strings).\n"
            "Do NOT solve or exploit. Propose several DISTINCT next-step investigative/preparatory actions for the very next cycle.\n\n"
            "[Ghidra Functions]\n{code}\n\n"
            "Generate {expand_k} distinct candidates.\n"
            "For each candidate:\n"
            "- Read BOTH decompiled C and assembly. Cite concrete code terms (API names, addresses, stack var sizes, strcpy/gets/printf, malloc/free, read/write, format usage, bounds, canary save/check).\n"
            "- Provide a short Chain-of-Thought (3–5 sentences) explaining WHY this step is useful, HOW to attempt it, and WHAT evidence/artifacts it may produce.\n"
            "- Extract a one-line actionable 'thought' (imperative, deterministic).\n"
            "- Prefer safe, low-cost probes. Avoid trivial variations and duplicates.\n\n"
            "Return ONLY valid JSON (no markdown, no code fences, no prose). If invalid, return {{\"error\":\"BAD_OUTPUT\"}}.\n"
            "JSON schema:\n"
            "{{\n"
            '  "candidates": [\n'
            "    {{\n"
            '      "function": "primary function name",\n'
            '      "vuln": "Stack BOF | FmtStr | UAF | OOB | …",\n'
            '      "why": "e.g., \\"strcpy@plt 0x40123a\\", \\"[rbp-0x40] buf\\", \\"no length check before read()\\"",\n'
            '      "cot_now": "2–4 sentences on immediate plan & rationale",\n'
            '      "tasks": [{{"name":"short label","cmd":"exact terminal command","success":"substring or re:<regex>","artifact":"- or filename"}}],\n'
            '      "expected_signals": [{{"type":"leak|crash|offset|mitigation|symbol|other","name":"e.g., canary|rip_offset|libc_base","hint":"existence/value/format"}}]\n'
            "    }}\n"
            "  ]\n"
            "}}\n"
        ).format(code=code, expand_k=expand_k)
        return prompt

    elif option == "--Cal":
        prompt = (
            "### STATE SPEC:\n{state_spec}\n\n"
            "### STATE:\n{state}\n\n"
            "### CoT:\n{CoT}"
        ).format(state_spec=STATE_SPEC, state=state, CoT=CoT)
        return prompt
    
    elif option == "--instruction" or option == "--instruction_fallback":
        import json

        # 도구 정보 추가
        tools_info = ""
        if available_tools and tool_category:
            tools_info = (
                "\n### AVAILABLE TOOLS (MUST USE):\n"
                "Tool Category: {tool_category}\n"
                "Available Tool Functions: {tool_names}\n\n"
                "CRITICAL INSTRUCTIONS FOR TOOL USAGE:\n"
                "- You MUST use the available tool functions from {tool_category}_tool when generating commands.\n"
                "- ALL available tools should be considered and used when appropriate for the task.\n"
                "- Tool functions are structured and provide better results than raw shell commands.\n"
                "- If a tool function is available for your task, you MUST use it instead of raw commands.\n"
                "- Review ALL tool functions and use multiple tools if needed to complete the task comprehensively.\n"
                "- Do NOT skip available tools - use them to gather maximum information.\n"
                "- Tool function names: {tool_names}\n\n"
                "TOOL CALL FORMAT:\n"
                "- When using a tool function, use Python function call syntax in the 'cmd' field:\n"
                "  Example: ghidra_decompile(binary_path='/path/to/binary', function_address='0x4019a6')\n"
                "  Example: checksec_analysis(binary_path='/path/to/binary')\n"
                "  Example: rop_gadget_search(binary_path='/path/to/binary', search_pattern='pop rdi')\n"
                "- DO NOT use shell command format like 'ghidra_decompile /path/to/binary 0x4019a6'\n"
                "- DO NOT use command-line flags like 'ghidra_decompile --binary /path/to/binary --address 0x4019a6'\n"
                "- Use keyword arguments with proper parameter names from the tool schema.\n"
                "- For regular shell commands (not tool functions), use normal POSIX shell format.\n\n"
            ).format(
                tool_category=tool_category,
                tool_names=json.dumps(available_tools, indent=2, ensure_ascii=False)
            )

        # 이미 실행한 명령어 정보 추가 (중복 방지)
        executed_commands_info = ""
        if state and isinstance(state, dict):
            command_cache = state.get("command_cache", {})
            failed_commands = state.get("failed_commands", {})
            results = state.get("results", [])
            all_track_outputs = state.get("all_track_outputs", {})

            executed_list = []
            seen_cmds = set()

            # 1. command_cache에서 성공한 명령어 추출
            for cmd_hash, cmd_info in command_cache.items():
                cmd = cmd_info.get('cmd', '')
                if cmd and cmd not in seen_cmds:
                    executed_list.append(f"✓ {cmd}")
                    seen_cmds.add(cmd)

            # 2. failed_commands에서 실패한 명령어 추출
            for cmd_hash, cmd_info in failed_commands.items():
                cmd = cmd_info.get('cmd', '')
                if cmd and cmd not in seen_cmds:
                    executed_list.append(f"✗ {cmd} (FAILED)")
                    seen_cmds.add(cmd)

            # 3. all_track_outputs에서 실행된 명령어 추출 (최신 실행 결과)
            for track_id, outputs in all_track_outputs.items():
                if isinstance(outputs, list):
                    for output in outputs:
                        cmd = output.get("cmd", "")
                        if cmd and cmd not in seen_cmds:
                            if output.get("success", False):
                                executed_list.append(f"✓ {cmd}")
                            else:
                                executed_list.append(f"✗ {cmd} (FAILED)")
                            seen_cmds.add(cmd)

            # 4. results 배열에서 실행된 명령어 추출 (이전 실행 이력)
            for result in results:
                # 각 result의 track_outputs 확인 (리스트 형식)
                track_outputs = result.get("track_outputs", [])
                if isinstance(track_outputs, list):
                    for output in track_outputs:
                        cmd = output.get("cmd", "")
                        if cmd and cmd not in seen_cmds:
                            if output.get("success", False):
                                executed_list.append(f"✓ {cmd}")
                            else:
                                executed_list.append(f"✗ {cmd} (FAILED)")
                            seen_cmds.add(cmd)
                elif isinstance(track_outputs, dict):
                    # 딕셔너리 형식인 경우 (하위 호환성)
                    for track_id, outputs in track_outputs.items():
                        if isinstance(outputs, list):
                            for output in outputs:
                                cmd = output.get("cmd", "")
                                if cmd and cmd not in seen_cmds:
                                    if output.get("success", False):
                                        executed_list.append(f"✓ {cmd}")
                                    else:
                                        executed_list.append(f"✗ {cmd} (FAILED)")
                                    seen_cmds.add(cmd)

                # 직접 cmd 필드가 있는 경우
                cmd = result.get("cmd", "")
                if cmd and cmd not in seen_cmds:
                    if result.get("ok", False) or result.get("success", False):
                        executed_list.append(f"✓ {cmd}")
                    else:
                        executed_list.append(f"✗ {cmd} (FAILED)")
                    seen_cmds.add(cmd)

            if executed_list:
                executed_commands_info = (
                    "\n### ALREADY EXECUTED COMMANDS (DO NOT REPEAT):\n"
                    "The following commands have already been executed in previous iterations:\n"
                    "{executed_list}\n\n"
                    "CRITICAL: You MUST NOT repeat these commands. Generate NEW and DIFFERENT commands.\n"
                    "- If you need similar functionality, use different tools or different parameters.\n"
                    "- Focus on UNEXPLORED approaches and NEW techniques.\n"
                    "- Consider using different tools from the available toolset.\n"
                    "- If a command failed, do NOT retry it - use a completely different approach.\n\n"
                ).format(executed_list="\n".join(executed_list[-30:]))  # 최근 30개만 표시
        
        prompt = (
            "### CoT:\n{cot}\n\n"
            "### CAL:\n{cal}\n\n"
            "{tools_info}"
            "{executed_commands_info}"
            "You are an instruction generator for ONE cycle in a CTF workflow.\n"
            "Select ONLY the single candidate with the highest CAL.results[*].final score "
            "(tie-break by higher exploitability, then lower cost, then lower risk). "
            "Use that candidate to produce a deterministic plan to learn the NEXT required fact.\n\n"
            "OUTPUT — JSON ONLY (no prose, no fences). If invalid, return {{\"error\":\"BAD_OUTPUT\"}}.\n"
            "{{\n"
            '  "what_to_find": "one-line fact to learn",\n'
            '  "steps": [\n'
            '    {{\n'
            '      "name": "short label",\n'
            '      "cmd": "exact shell command (POSIX) OR Python function call for tools (e.g., tool_name(param1=\'value1\', param2=\'value2\'))",\n'
            '      "success": "substring or re:<regex> to confirm",\n'
            '      "artifact": "- or filename",\n'
            '      "code": "full runnable helper script if needed, else -",\n'
            '      "tool_function": "tool function name if using structured tool, else -"\n'
            '    }}\n'
            '  ]\n'
            "}}\n\n"
            "RULES:\n"
            "- Use only tools in STATE.env and obey STATE.constraints.\n"
            "- If available tools are provided, prefer using structured tool functions over raw shell commands.\n"
            "- Always include exactly one primary step first; add more only if strictly required.\n"
            "- Every step MUST include cmd; if a helper is needed, put full script in steps[i].code.\n"
            "- CRITICAL: Do NOT repeat commands from the ALREADY EXECUTED COMMANDS list above.\n"
            "- Generate NEW commands that explore DIFFERENT aspects or use DIFFERENT tools.\n\n"
            "### EXPLOITATION PRIORITY:\n"
            "- If STATE.facts contains offsets/addresses/leaks, PRIORITIZE exploitation over more probing.\n"
            "- When vulnerability is confirmed (XSS, SQLi, BOF, etc.), generate ACTUAL EXPLOIT payloads.\n"
            "- For XSS: Generate payloads that trigger alert/document.cookie/fetch to exfiltrate data.\n"
            "- For SQLi: Generate payloads to extract data (UNION SELECT, blind injection, etc.).\n"
            "- For BOF: Generate ROP chains, ret2libc payloads, or shellcode injections.\n"
            "- STOP passive reconnaissance if vulnerability is already confirmed - EXPLOIT IT.\n"
            "- The GOAL is to GET THE FLAG, not just to find vulnerabilities.\n"
        ).format(cot=CoT, cal=Cal, tools_info=tools_info, executed_commands_info=executed_commands_info)  
    
        return prompt

    elif option == "--plan":
        prompt = (
        "You are a planning assistant for CTF automation using Ghidra outputs and run-state context.\n\n"
        "Inputs:\n"
        "[plan.json]\n{plan}\n\n"
        "[state.json]\n{state}\n\n"
        "Role:\n"
        "- Do NOT solve or exploit.\n"
        "- Propose DISTINCT next-step investigative/preparatory actions for the NEXT cycle only.\n"
        "- Ground every proposal in BOTH Ghidra artifacts AND the current plan/state history.\n"
        "- Respect constraints in state.json.constraints and avoid repeating completed steps in plan.json.runs.\n\n"
        "Requirements:\n"
        "- Generate {expand_k} distinct candidates.\n"
        "- For each candidate, read BOTH decompiled C and assembly. Cite concrete terms: exact APIs, addresses, stack var sizes, strcpy/gets/printf, malloc/free, read/write, format usage, bounds, canary save/check.\n"
        "- Provide a short Chain-of-Thought (3–5 sentences) explaining WHY this step is useful, HOW to attempt it, and WHAT evidence/artifacts it may produce; reference prior signals/results from state.json where relevant.\n"
        "- Extract a one-line actionable 'thought' (imperative, deterministic) aligned with constraints.\n"
        "- Prefer safe, low-cost probes. Avoid trivial variations and duplicates. If two ideas overlap, keep the higher information gain.\n\n"
        "Output:\n"
        "Return ONLY valid JSON (no markdown, no code fences, no prose). If invalid, return {{\"error\":\"BAD_OUTPUT\"}}.\n"
        "JSON schema:\n"
        "{{\n"
        '  "candidates": [\n'
        "    {{\n"
        '      "function": "primary function name",\n'
        '      "vuln": "Stack BOF | FmtStr | UAF | OOB | …",\n'
        '      "why": "e.g., \\"strcpy@plt 0x40123a\\", \\"[rbp-0x40] buf\\", \\"no length check before read()\\"",\n'
        '      "cot_now": "2–4 sentences on immediate plan & rationale",\n'
        '      "tasks": [{{"name":"short label","cmd":"exact terminal command","success":"substring or re:<regex>","artifact":"- or filename"}}],\n'
        '      "expected_signals": [{{"type":"leak|crash|offset|mitigation|symbol|other","name":"e.g., canary|rip_offset|libc_base","hint":"existence/value/format"}}]\n'
        "    }}\n"
        "  ]\n"
        "}}\n"
        ).format(code=code, plan=plan, state=state, expand_k=expand_k)
        return prompt
        
    elif option == "--discuss" or option == "--continue":
        # Planning context 추가 (기존 트랙, 결과, facts 등)
        import json
        context_info = ""
        if planning_context:
            context_info = (
                "\n### PLANNING CONTEXT (Previous Exploration):\n"
                "Existing Tracks:\n{existing_tracks}\n\n"
                "Discovered Facts:\n{discovered_facts}\n\n"
                "Generated Artifacts:\n{generated_artifacts}\n\n"
                "Recent Results:\n{recent_results}\n\n"
                "INSTRUCTIONS:\n"
                "- If existing tracks are making progress, propose DEEPER exploration (same vulnerability, more depth)\n"
                "- If existing tracks are stuck, propose NEW attack vectors (expand attack surface)\n"
                "- Build on discovered facts and artifacts\n"
                "- Avoid repeating failed approaches\n\n"
            ).format(
                existing_tracks=json.dumps(planning_context.get("existing_tracks", {}), indent=2, ensure_ascii=False),
                discovered_facts=json.dumps(planning_context.get("discovered_facts", {}), indent=2, ensure_ascii=False),
                generated_artifacts=json.dumps(planning_context.get("generated_artifacts", []), indent=2, ensure_ascii=False),
                recent_results=json.dumps(planning_context.get("recent_results", []), indent=2, ensure_ascii=False)
            )
        
        prompt = (
            "You are a planning assistant for CTF automation.\n\n"
            "You will be given free-form user input about a CTF target (symptoms, logs, code snippets, ideas).\n"
            "Do NOT solve or exploit. Propose several DISTINCT next-step investigative/preparatory actions for the very next cycle.\n\n"
            "[User Input]\n{user_input}\n\n"
            "{plan_block}"
            "{state_block}"
            "{context_info}"
            "Rules:\n"
            "- Ground every proposal in the provided input (and plan/state if present).\n"
            "- Respect constraints in state.json.constraints and avoid repeating steps in plan.json.runs.\n"
            "- Prefer safe, low-cost probes; avoid trivial variations and duplicates.\n\n"
            "Generate {expand_k} distinct candidates.\n"
            "Return ONLY valid JSON (no markdown, no code fences, no prose). If invalid, return {{\"error\":\"BAD_OUTPUT\"}}.\n"
            "JSON schema:\n"
            "{{\n"
            '  "candidates": [\n'
            "    {{\n"
            '      "vuln": "Stack BOF | SQLi | SSTI | UAF | OOB | IDOR | …",\n'
            '      "why": "concrete evidence ≤120 chars",\n'
            '      "cot_now": "2–4 sentences on immediate plan & rationale",\n'
            '      "tasks": [{{"name":"short label","cmd":"exact terminal command","success":"substring or re:<regex>","artifact":"- or filename"}}],\n'
            '      "expected_signals": [{{"type":"leak|crash|offset|mitigation|symbol|other","name":"e.g., canary|libc_base|rip_offset","hint":"existence/value/format"}}]\n'
            "    }}\n"
            "  ]\n"
            "}}\n"
        ).format(
            user_input=code,
            expand_k=expand_k,
            plan_block=(
                "[plan.json]\n{plan}\n\n".format(plan=plan) if plan else ""
            ),
            state_block=(
                "[state.json]\n{state}\n\n".format(state=state) if state else ""
            ),
            context_info=context_info
        )
        return prompt

    elif option == "--exploit":
        prompt = (
            "You are an exploitation/execution assistant across multiple CTF domains "
            "(pwn, web, crypto, reversing, forensics, mobile, cloud, ML, misc).\n\n"
            "Inputs:\n"
            "[plan.json]\n{plan}\n\n"
            "[state.json]\n{state}\n\n"
            "ROLE\n"
            "- Produce ONE concrete, testable attack path or automation script for the CURRENT objective.\n"
            "- Do NOT guess unknown values. Use only facts in state/plan/artifacts. "
            "If a value is missing, first output a PREP step that deterministically derives and stores it.\n"
            "- Local, deterministic, non-destructive. No network or exfiltration unless explicitly allowed in constraints.\n"
            "- Respect state.json.constraints (e.g., time/cost/risk caps), and avoid repeating completed steps in plan.json.runs.\n\n"
            "OUTPUT — JSON ONLY (no markdown/fences). If invalid, return {{\"error\":\"BAD_OUTPUT\"}}.\n"
            "Schema:\n"
            "{{\n"
            '  "technique": "e.g., Ret2win | Ret2plt | ROP | SQLi-Boolean | SSTI | XSS-Reflected | LFI | Padding-Oracle | RSA-CRT | ZKP-Forge | ELF-Patch | ORW | PCAP-Secret | APK-Hook | Cloud-Misconfig | Model-Inference | ...",\n'
            '  "objective": "one-line measurable goal (e.g., prove EIP control, dump table names, extract key, recover flag segment)",\n'
            '  "hypothesis": "short statement tying inputs to this technique",\n'
            '  "preconditions": ["explicit known facts needed (with file/field names)"],\n'
            '  "artifacts_in": ["required existing files/paths from prior steps"],\n'
            '  "payload_layout": "concise structure if applicable (e.g., [offset] + [addr] + [arg]) or -",\n'
            '  "tasks": [\n'
            '    {{"name":"prep/derive-missing","cmd":"exact command or script","success":"substring or re:<regex>","artifact":"- or filename"}},\n'
            '    {{"name":"build payload or request","cmd":"exact command that writes an artifact","success":"re:created|bytes|OK","artifact":"payload.bin|req.txt|-"}},\n'
            '    {{"name":"dry run / safe verify","cmd":"deterministic local check (gdb|pytest|simulator|static tool)","success":"substring or re:<regex>","artifact":"verify.log"}},\n'
            '    {{"name":"execute","cmd":"exact command","success":"substring or re:<regex> indicating objective","artifact":"run_out.txt"}}\n'
            "  ],\n"
            '  "expected_signals": [\n'
            '    {{"type":"symbol|leak|offset|mitigation|oracle|proof|other","name":"concise name","hint":"existence/value/format"}},\n'
            '    {{"type":"objective","name":"goal_reached","hint":"success token or file presence"}}\n'
            "  ],\n"
            '  "rollback": ["commands to revert temp changes or clean artifacts"],\n'
            '  "risk": "Low|Medium|High with 1-line justification",\n'
            '  "cost": "low|medium|high"\n'
            "}}\n\n"
            "GUIDANCE\n"
            "- Web: use curl/httpie with exact params; success=HTTP code/body substrings.\n"
            "- Crypto: show math/solver steps; success=equation residual==0 or verifier OK.\n"
            "- Reversing: use objdump/ghidra-headless/radare; success=pattern in disasm or patched hash.\n"
            "- Forensics: tshark/foremost/volatility; success=indicator found in output.\n"
            "- Mobile: jadx/frida; success=hook hit/log token.\n"
            "- Cloud: IaC/static checks; success=policy/perm diff, no live prod actions.\n"
            "- ML: inference or prompt attack must be offline/sandbox; success=metric/trace token.\n"
        ).format(
            plan=plan,
            state=state  ,
        )
        return prompt

    elif option == "--human":
        # Human translation doesn't need special prompt building
        # Just return the instruction result as-is
        return Instruction if Instruction else ""
    
    elif option == "--feedback":
        # Feedback query - instruction result is the parsing result
        prompt = (
            "You are a feedback generator for CTF automation.\n\n"
            "You will be given the result of instruction execution (parsed output).\n"
            "Analyze the results and provide feedback on:\n"
            "- What was learned/successful\n"
            "- What failed or needs adjustment\n"
            "- Next recommended actions\n\n"
            "[Parsing Result]\n{instruction}\n\n"
            "Return ONLY valid JSON (no markdown, no code fences, no prose).\n"
        ).format(instruction=Instruction if Instruction else "")
        return prompt


                
        