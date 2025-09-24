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

def build_query(option: str, code: str = "", state = None, CoT = None, Cal = None):
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
        ).format(cal=Cal)  
    
        return prompt

    # elif option == "--plan":
        
    # elif option == "--discuss":
    
    # elif option == "--exploit":
        
    