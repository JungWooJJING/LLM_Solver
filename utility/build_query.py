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

def build_query(option: str, code: str = "", state = None, CoT = None, Cal = None, plan = None):
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
    
    elif option == "--instruction":
        prompt = (
            "### CoT:\n{cot}\n\n"
            "### CAL:\n{cal}\n\n"
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
            '      "cmd": "exact shell command to run",\n'
            '      "success": "substring or re:<regex> to confirm",\n'
            '      "artifact": "- or filename",\n'
            '      "code": "full runnable helper script if needed, else -"\n'
            '    }}\n'
            '  ]\n'
            "}}\n\n"
            "RULES:\n"
            "- Use only tools in STATE.env and obey STATE.constraints.\n"
            "- Always include exactly one primary step first; add more only if strictly required.\n"
            "- Every step MUST include cmd; if a helper is needed, put full script in steps[i].code.\n"
            "- Prefer read-only, low-cost probes; keep commands reproducible.\n"
        ).format(cot= CoT, cal=Cal)  
    
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
        
    elif option == "--discuss":
        prompt = (
            "You are a planning assistant for CTF automation.\n\n"
            "You will be given free-form user input about a CTF target (symptoms, logs, code snippets, ideas).\n"
            "Do NOT solve or exploit. Propose several DISTINCT next-step investigative/preparatory actions for the very next cycle.\n\n"
            "[User Input]\n{user_input}\n\n"
            "{plan_block}"
            "{state_block}"
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
                "[plan.json]\n{plan}\n\n".format(plan=plan) 
            ),
            state_block=(
                "[state.json]\n{state}\n\n".format(state=state) 
            ),
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


                
        