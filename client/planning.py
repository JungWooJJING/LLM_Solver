import os
import json
import re
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/home/wjddn0623/Ghidra/ghidra/build/dist/ghidra_12.0_DEV"
pyghidra.start()

from typing import List, Dict, Any

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from templates.prompting import few_Shot
from rich.console import Console
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

console = Console()
FEWSHOT = few_Shot()
expand_k = 5

w = {"feasibility": 0.25, "info_gain": 0.30, "novelty": 0.20, "cost": 0.15, "risk": 0.15}

STATE_FILE = "state.json"
COT_FILE = "CoT.json"
Cal_FILE = "Cal.json"
Cal_SCORED_FILE = "Cal_scored.json"
INSTRUCTION_FILE = "instruction.json"

MAX_HISTORY_ITERS = 20   
MAX_ACTIVE = 5         

DEFAULT_STATE = {
  "iter": 0,             
  "goal": "",                   
  "constraints": ["no brute-force > 1000"],  
  "env": {},                 
  "cot_history": [],           
  "selected": {},              
  "results": []                  
}

prompt_CoT = [
    {"role": "developer", "content": CTFSolvePrompt.planning_prompt_CoT},
    {"role": "user",   "content": FEWSHOT.web_SQLI},         
    {"role": "user",   "content": FEWSHOT.web_SSTI},
    {"role": "user",   "content": FEWSHOT.forensics_PCAP},
    {"role": "user",   "content": FEWSHOT.stack_BOF},   
    {"role": "user",   "content": FEWSHOT.rev_CheckMapping},
]

def multi_line_input():
    console.print("Enter multiple lines. Type <<<END>>> on a new line to finish input.", style="bold yellow")
    lines = []
    while True:
        line = input(" ")
        if line.strip() == "<<<END>>>":
            break
        lines.append(line)
    return "\n".join(lines)

def cleanUp(all=True):
    targets = [COT_FILE, Cal_FILE, Cal_SCORED_FILE, INSTRUCTION_FILE]
    if all:
        targets.append(STATE_FILE)
    for f in targets:
        if os.path.exists(f):
            os.remove(f)

def load_state():
    if not os.path.exists(STATE_FILE):
        save_state(DEFAULT_STATE.copy())
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(state: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def safe_json_loads(s):
    if isinstance(s, (dict, list)):
        return s
    if not isinstance(s, str):
        return {}
    try:
        return json.loads(s)
    except Exception:
        try:
            s2 = s[s.find("{"): s.rfind("}") + 1]
            s2 = re.sub(r"```(json)?|```", "", s2).strip()
            return json.loads(s2)
        except Exception:
            return {}

def _next_iter():
    s = load_state()
    s["iter"] = int(s.get("iter", 0)) + 1
    save_state(s)
    return s["iter"]

def update_state_json(feedback_json : str):
    st = load_state()
    feedback = safe_json_loads(feedback_json)
    
    summary = feedback.get("summary", "")
    verdict = feedback.get("verdict", "unknown")
    signals = feedback.get("signals") or []
    
    sig = feedback.get("signals") or []
    if isinstance(sig, dict):
        signals = [sig]
    elif isinstance(sig, list):
        signals = [x for x in sig if isinstance(x, dict)]
    else:
        signals = []
        
    patch = {"summary": summary, "verdict": verdict}

    selected = st.get("selected") or {}
    cand_id = selected.get("id")
    if not cand_id:
        raise SystemExit("[!] selected.id가 없습니다.")

    results = st.setdefault("results", [])
    if not isinstance(results, list):
        raise SystemExit("[!] results는 리스트여야 합니다.")

    key = str(cand_id).strip()
    idx = next(
        (i for i, it in enumerate(results)
         if isinstance(it, dict) and str(it.get("id", "")).strip() == key),
        -1
    )

    if idx >= 0:
        item = results[idx]
        item.update(patch)

        cur = item.get("signals")
        if isinstance(cur, list):
            cur.extend(signals)
        else:
            item["signals"] = list(signals)
    else:
        results.append({
            "id": cand_id,
            **patch,
            "signals": list(signals),
        })

    save_state(st)
    
def _norm(s: str) -> str:
    return " ".join((s or "").split()).lower()

def _score(x):
    v = x.get("calculated_score", x.get("score"))
    return float(v) if v is not None else float("-inf")

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

class PlanningClient:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def run_prompt_CoT(self, prompt_query: str):
        state = load_state()
        prompt_CoT.append({"role": "assistant", "content": json.dumps(state, ensure_ascii=False)})
        prompt_CoT.append({"role": "user", "content": prompt_query})
        res = self.client.chat.completions.create(model=self.model, messages=prompt_CoT)

        prompt_CoT.append({"role": "assistant", "content": res.choices[0].message.content})
        return res.choices[0].message.content

    def run_prompt_Cal(self, prompt_query: str):
        prompt = [
            {"role": "developer", "content": CTFSolvePrompt.planning_prompt_Cal},
        ]
        
        state = load_state()
        prompt.append({"role": "assistant", "content": json.dumps(state, ensure_ascii=False)})
        prompt.append({"role": "user", "content": prompt_query})

        res = self.client.chat.completions.create(model=self.model, messages=prompt)
        return res.choices[0].message.content

    def update_state_from_cot(self, cot_text: str):
        data = safe_json_loads(cot_text)
        raw_cands = data.get("candidates", []) or []

        it = _next_iter()
        st = load_state()

        cands = []
        for idx, cand in enumerate(raw_cands, start=1):
            cands.append({
                "id": f"COT-{it}-{idx}",
                "cot": cand.get("cot"),
                "thought": cand.get("thought"),
                "vuln_hypothesis": cand.get("vuln_hypothesis"),
                "attack_path": cand.get("attack_path"),
                "evidence_checks": cand.get("evidence_checks"),
                "mini_poc": cand.get("mini_poc"),
                "success_criteria": cand.get("success_criteria"),
                "rf": None
            })

        st.setdefault("cot_history", []).append({"iter": it, "candidates": cands})

        if len(st["cot_history"]) > MAX_HISTORY_ITERS:
            st["cot_history"] = st["cot_history"][-MAX_HISTORY_ITERS:]

        save_state(st)

    def build_Cal_from_State(self):
        st = load_state()
        if not os.path.exists(COT_FILE):
            return {"candidates": []}

        with open(COT_FILE, "r", encoding="utf-8") as f:
            cot = json.load(f)

        raw = cot.get("candidates", []) or []
        pick = raw[:MAX_ACTIVE]

        iter_no = st.get("iter", 0)
        signals_tail = (st.get("signals", []) or [])[-5:]
        constraints_tail = (st.get("constraints_dynamic", []) or [])[-5:]

        cal_in = []
        for idx, c in enumerate(pick, start=1):
            base_id = c.get("id")
            cid = base_id if base_id else f"COT-{iter_no}-{idx}"

            thought = (c.get("thought") or "").strip()
            if not thought:
                continue  

            cal_in.append({
                "id": cid,
                "thought": thought,
                "vuln_hypothesis": c.get("vuln_hypothesis") or "",
                "attack_path": c.get("attack_path") or "",
                "rf": c.get("refined_from"),
                "hints": {
                    "signals": signals_tail,
                    "constraints": constraints_tail
                }
            })

        return {"candidates": cal_in}

    def cal_CoT(self, cal_json_str: str = None, infile: str = "Cal.json", outfile: str = "Cal_scored.json"):
        if cal_json_str is None:
            with open(infile, "r", encoding="utf-8") as f:
                data = safe_json_loads(f.read())
        else:
            data = safe_json_loads(cal_json_str)

        cal = ["feasibility", "novelty", "info_gain", "cost", "risk"]

        for item in data.get("results", []):
            g = {k: float(item.get(k, 0.5)) for k in cal}
            penalties = sum(float(p.get("value", 0.0)) for p in item.get("penalties", []))

            score = 0.0
            for k in cal:
                v = g[k]
                if k in ("cost", "risk"):
                    score += w[k] * (1 - v)
                else:
                    score += w[k] * v

            score -= penalties
            score = max(0.0, min(1.0, score))
            item["calculated_score"] = round(score, 3)

        data["results"].sort(key=lambda x: x.get("calculated_score", x.get("score", 0.0)), reverse=True)

        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        console.print(f"Save: {outfile}", style='green')
        return data

    def update_state_from_cal(self, cal_result: dict):
        st = load_state()

        last_cands = []
        for entry in reversed(st.get("cot_history", [])):
            if entry.get("candidates"):
                last_cands = entry["candidates"]
                break

        thought_to_id = { _norm(c.get("thought","")): c.get("id")
                        for c in last_cands if c.get("id") }
        idx_to_id = { i: c.get("id") for i, c in enumerate(last_cands) if c.get("id") }

        items = cal_result.get("results") or cal_result.get("candidates") or []
        if not items:
            st["selected"] = {}
            save_state(st)
            return st["selected"]

        top = max(items, key=_score)

        cid = top.get("id")
        if not cid:
            cid = thought_to_id.get(_norm(top.get("thought","")))
        if not cid:
            idx = top.get("idx")
            if isinstance(idx, int):
                cid = idx_to_id.get(idx) or idx_to_id.get(idx - 1)

        record = {
            "id": cid,  
            "score": float(top.get("calculated_score", top.get("score", 0.0))),
            "thought": top.get("thought", ""),
            "notes": top.get("notes", "")
        }

        st.setdefault("results", []).append(record)
        st["selected"] = record

        save_state(st)
        return record

    def save_prompt(self, filename: str, content: str):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[Prompt saved to {filename}]", style="green")

    def check_Option(self, option: str, ctx):
        if option == "--help":
            console.print("--help : Display the available commands.", style="bold yellow")
            console.print("--file : Paste the challenge source code to locate potential vulnerabilities.", style="bold yellow")
            console.print("--discuss : Discuss the approach with the LLM to set a clear direction.", style="bold yellow")
            console.print("--instruction : Get step-by-step guidance based on a Tree-of-Thought plan.", style="bold yellow")
            console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")
            console.print("--result : Update plan based on execution result.", style="bold yellow")
            console.print("--showplan : Show current Tree-of-Thought plan.", style="bold yellow")
            console.print("--add-summary : Append a manual human summary into state.json.", style="bold yellow")
            console.print("--quit : Exit the program.", style="bold yellow")

        elif option == "--showplan":
            if not os.path.exists(Cal_SCORED_FILE):
                console.print("Cal_scored.json not found. Run --file or --discuss first.", style="bold red")
                return
            with open(Cal_SCORED_FILE, "r", encoding="utf-8") as f:
                console.print("[bold cyan]Current Cal Plan (scored):[/bold cyan]\n")
                console.print(f.read(), style="white")

        elif option == "--file":
            console.print("Paste the challenge’s source code. Type <<<END>>> on a new line to finish.", style="blue")
            planning_Code = multi_line_input()

            console.print("wait...", style='bold green')
            planning_Prompt = self.build_prompt(option, query=planning_Code)

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(planning_Prompt)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal_from_State()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt(Cal_FILE, response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')
            
        elif option == "--ghidra":
            console.print("Enter the binary path: ", style="blue", end="")
            binary_path = input()

            file_infor = ghdira_API(binary_path)
            
            console.print("wait...", style='bold green')
            planning_Prompt = self.build_prompt(option="--file", query=file_infor)

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(planning_Prompt)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal_from_State()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt(Cal_FILE, response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--discuss":
            console.print("Ask questions or describe your intended approach.", style="blue")
            planning_Discuss = multi_line_input()

            console.print("wait...", style='bold green')
            planning_Prompt = self.build_prompt(option, planning_Discuss)

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(planning_Prompt)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal_from_State()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt(Cal_FILE, response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--exploit":
            console.print("Please wait. I will prepare an exploit script or a step-by-step procedure.", style="blue")
            
            st = load_state()
            exploit_prompt = self.build_prompt(option=option, state_json=st)
            
            console.print("Creating Exploit...", style="bold green")    
            exploit_code = ctx.exploit.run_prompt_exploit(exploit_prompt)
            
            console.print("=== Human Translation ===", style="bold green")
            parsing_response = ctx.parsing.human_translation(query=exploit_code)
            
            console.print(parsing_response, style="yellow")
            console.print("Input result", style="blue")
            result_output = multi_line_input()
            
            result_build_prompt = self.build_prompt(option="--result", query=result_output, state_json=st)
            
            console.print("=== LLM Translation ===", style="bold green")
            result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)

            console.print("=== Feedback === ", style="bold green")
            result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)

            update_state_json(result_feedback)
            console.print("Update State.json", style="bold green")

            plan_build_prompt = self.build_prompt(option = "--plan", state_json=load_state(), feedback_json=result_feedback)

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(plan_build_prompt)
            self.save_prompt("CoT.json", response_CoT)
            self.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal_from_State()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt("Cal.json", response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            console.print("=== Human Translation ===", style="bold green")
            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')            


        elif option == "--instruction":
            console.print("I will provide step-by-step instructions based on a Tree-of-Thought plan.", style="blue")

            if not os.path.exists(Cal_SCORED_FILE):
                console.print("Cal_scored.json not found. Run --file or --discuss first.", style="bold red")
                return

            state = load_state()
            with open(Cal_SCORED_FILE, "r", encoding="utf-8") as f:
                Cal_scored = json.load(f)

            state_json = json.dumps(state, ensure_ascii=False)
            cal_json = json.dumps(Cal_scored, ensure_ascii=False)

            planning_instruction = self.build_prompt("--instruction", state_json=state_json, cal_json=cal_json)

            console.print("wait...", style='bold green')
            instruction_json = ctx.instruction.run_prompt_instruction(prompt=planning_instruction)
            self.save_prompt(INSTRUCTION_FILE, instruction_json)

            parsing_response = ctx.parsing.human_translation(json.dumps(instruction_json, ensure_ascii=False, indent=2))
            console.print(parsing_response, style="yellow")

        elif option == "--result":            
            st = load_state()
            
            console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
            result_output = multi_line_input()
                        
            result_build_prompt = self.build_prompt(option=option, query=result_output, state_json=st)

            console.print("wait...", style="bold green")
            result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)

            console.print("=== Feedback === ", style="bold green")
            result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)

            update_state_json(result_feedback)
            console.print("Update State.json", style="bold green")

            plan_build_prompt = self.build_prompt("--plan", state_json=load_state(), feedback_json=result_feedback)

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(plan_build_prompt)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal_from_State()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt(Cal_FILE, response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--quit":
            cleanUp()
            console.print("\nGoodbye!\n", style="bold yellow")
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")

    def build_prompt(self, option: str, query: str = "", plan_json: str = "",
                     state_json: str = "", cal_json: str = "", feedback_json: str = ""):

        if option == "--file":
            return (
                f"You are a planning assistant for CTF automation.\n\n"
                f"You will be given the content of a file related to a CTF challenge "
                f"(e.g., source code, binary disassembly, script, or captured data).\n"
                f"Your job is NOT to solve or exploit the challenge directly, "
                f"but to propose multiple distinct investigative or preparatory actions "
                f"for the very next step.\n\n"
                f"[File Content]\n{query}\n\n"
                f"Generate {expand_k} distinct candidates.\n"
                f"For each candidate:\n"
                f"- Provide a short Chain-of-Thought (3–5 sentences) explaining WHY this step is useful, "
                f"HOW to attempt it, and WHAT evidence or artifacts it may produce.\n"
                f"- Extract a one-line actionable 'thought'.\n"
                f"- List expected artifacts, required tools/permissions, a brief risk note, and estimated cost.\n"
                f"- Avoid trivial variations; each candidate must be meaningfully different.\n"
                f"- OPTIONAL KEYS: If and only if you have REAL values from an actual execution, "
                f"you MAY include these extra keys inside a candidate object: "
                f"cmd (string), ok (boolean), result (string), summary (string). "
                f"If not applicable, OMIT these keys entirely (do NOT output null, '-', or empty strings).\n\n"
                f"Respond ONLY in the following STRICT JSON format (required fields shown below):\n"
                "{{\n"
                '  "candidates": [\n'
                "    {\n"
                '      "cot": "3-5 sentences reasoning",\n'
                '      "vuln_hypothesis": "...",\n'
                '      "attack_path": "...",\n'
                '      "evidence_checks": ["...", "..."],\n'
                '      "mini_poc": "one-line safe probe",\n'
                '      "thought": "one-line concrete next step",\n'
                '      "expected_artifacts": ["file1", "file2"],\n'
                '      "requires": ["tool/permission/dependency"],\n'
                '      "success_criteria": ["...", "..."],\n'
                '      "risk": "short note",\n'
                '      "estimated_cost": "low|medium|high"\n'
                "    }\n"
                "  ]\n"
                "}}\n"
                "No prose outside the JSON."
            )

        elif option == "--discuss":
            return (
                f"You are a planning assistant for CTF automation.\n\n"
                f"You will be given a short discussion/note from the user about how they want to proceed.\n"
                f"Your job is NOT to solve or exploit, but to propose multiple distinct investigative or preparatory actions for the very next step.\n\n"
                f"[User Discussion]\n{query}\n\n"
                f"Generate {expand_k} distinct candidates.\n"
                f"For each candidate:\n"
                f"- Provide a short Chain-of-Thought (3–5 sentences) explaining WHY this step is useful, HOW to attempt it, and WHAT artifacts it may produce.\n"
                f"- Extract a one-line actionable 'thought'.\n"
                f"- List expected artifacts, required tools/permissions, a brief risk note, and estimated cost.\n"
                f"- Avoid trivial variations; each candidate must be meaningfully different.\n"
                f"- OPTIONAL KEYS: If and only if you have REAL values from an actual execution, "
                f"you MAY include these extra keys inside a candidate object: "
                f"cmd (string), ok (boolean), result (string), summary (string). "
                f"If not applicable, OMIT these keys entirely (do NOT output null, '-', or empty strings).\n\n"
                f"Respond ONLY in the following STRICT JSON format:\n"
                "{{\n"
                '  "candidates": [\n'
                "    {\n"
                '      "cot": "3-5 sentences reasoning",\n'
                '      "vuln_hypothesis": "...",\n'
                '      "attack_path": "...",\n'
                '      "evidence_checks": ["...", "..."],\n'
                '      "mini_poc": "one-line safe probe",\n'
                '      "thought": "one-line concrete next step",\n'
                '      "expected_artifacts": ["file1", "file2"],\n'
                '      "requires": ["tool/permission/dependency"],\n'
                '      "success_criteria": ["...", "..."],\n'
                '      "risk": "short note",\n'
                '      "estimated_cost": "low|medium|high"\n'
                "    }\n"
                "  ]\n"
                "}}\n"
                "No prose outside JSON."
            )

        elif option == "--instruction":
            return (
                f"You are an instruction generator for CTF automation.\n\n"
                f"INPUT\n"
                f"- You will receive a JSON payload that contains:\n"
                f"  - state: current progress (goal, constraints, env, artifacts.binary, candidates_topk, selected, evidence, optional runs/seen_cmd_hashes)\n"
                f"  - Cal_scored_topk: top-k Cal results for the immediate next step\n\n"
                f"TASK\n"
                f"- Using BOTH inputs, produce a minimal, concrete sequence of terminal actions to execute NEXT.\n"
                f"- BEFORE listing actions, write a brief 2–3 sentence rationale about execution order and expected outcomes.\n"
                f"- Do NOT attempt to solve the challenge; focus on preparation and evidence collection aligned with state.selected.thought.\n\n"
                f"POLICY\n"
                f"- Do NOT repeat any action whose exact cmd already appears in state.runs with ok==True.\n"
                f"- Do NOT propose actions whose expected artifact already exists (same filename or clearly same purpose).\n"
                f"- Prefer DELTA steps that produce NEW evidence/artifacts only.\n"
                f"- If state.selected.thought seems already executed, output ONLY the missing sub-steps.\n"
                f"- Keep commands shell-ready and deterministic.\n\n"
                f"[Payload]\nState.json : {state_json}\nCal_Scored.json : {cal_json}\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                "{{\n"
                '  "intra_cot": "2-3 sentences about order and expectations",\n'
                '  "actions": [\n'
                "    {\n"
                '      "name": "short label",\n'
                '      "cmd": "exact terminal command",\n'
                '      "success": "observable success signal",\n'
                '      "artifact": "output file/log to save (or \'-\')",\n'
                '      "fallback": "alternative command if primary fails (or \'-\')"\n'
                "    }\n"
                "  ]\n"
                "}}\n"
                "No prose outside JSON."
            )

        elif option == "--result":
            return (
                f"You are a post-execution FEEDBACK assistant for CTF workflows (NOT a solver).\n\n"
                f"GOAL\n"
                f"- Read one Executed.json describing: the exact command executed and its output/result.\n"
                f"- Produce feedback ONLY about what happened: concise summary, extracted signals, and issue categorization.\n"
                f"- Do NOT suggest next actions. Do NOT update planning state. Do NOT attempt to solve or print flags.\n\n"
                f"[Executed result]\n{query}\n\n"
                f"[Current state.json]\n {state_json}\n\n"
                f"POLICY\n"
                f"- Be terse and objective. Quote exact substrings from outputs when useful.\n"
                f"- Normalize technical signals (addresses, offsets, canary present/absent, leaks, crash types).\n"
                f"- Classify issues into: env | tool | logical | permission | timeout | network | data-format | other.\n"
                f"- No speculation beyond what the output supports.\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                "{{\n"
                '  "executed": { "cmd": "exact command" },\n'
                '  "summary": "≤2 sentences describing what happened",\n'
                '  "observations": ["concise fact 1", "concise fact 2"],\n'
                '  "signals": [\n'
                '    { "type": "leak|crash|mitigation|offset|symbol|other", "name": "e.g., __libc_start_main+243", "value": "0x7f..", "evidence": "short quoted line" }\n'
                '  ],\n'
                '  "issues": ["env|tool|logical|permission|timeout|network|data-format|other"],\n'
                '  "verdict": "success|partial|failed",\n'
                '  "notes": "≤200 chars optional"\n'
                "}}\n"
                "No prose outside JSON."
            )

        elif option == "--plan":
            return (
                f"You are a planning assistant updating an existing plan based on feedback (NOT a solver).\n"
                f"Do NOT regenerate or reorder the original plan; only append or annotate.\n"
                f"Apply minimal DELTAS based on feedback and propose up to {expand_k} distinct next-step candidates (DELTA actions).\n\n"
                f"[State.json]\n{state_json}\n\n"
                f"[Feedback.json]\n{feedback_json}\n\n"
                f"POLICY\n"
                f"- Keep existing hypothesis IDs/names stable; no wholesale rewrites.\n"
                f"- Generate {expand_k} distinct candidates. Avoid trivial variations; each must be meaningfully different.\n"
                f"- Only DELTA updates (confidence tweaks, short result note, toolset/constraints appends, and small next steps).\n"
                f"- Next steps must be investigative/preparatory; no solving/flags.\n"
                f"- Commands must be shell-ready and non-interactive.\n"
                f"- OPTIONAL KEYS: Only include ok/result/summary if you have REAL values from an actual execution; otherwise OMIT them entirely.\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                "{{\n"
                '  "candidates": [\n'
                "    {\n"
                '      "cot": "3-5 sentences reasoning",\n'
                '      "vuln_hypothesis": "...",\n'
                '      "attack_path": "...",\n'
                '      "evidence_checks": ["...", "..."],\n'
                '      "mini_poc": "one-line safe probe",\n'
                '      "thought": "one-line concrete next step",\n'
                '      "expected_artifacts": ["file1", "file2"],\n'
                '      "requires": ["tool/permission/dependency"],\n'
                '      "success_criteria": ["...", "..."],\n'
                '      "risk": "short note",\n'
                '      "estimated_cost": "low|medium|high"\n'
                "    }\n"
                "  ]\n"
                "}}\n"
                "No prose outside JSON."
            )
            
        elif option == "--exploit":
            return (
                f"You are an EXPLOIT author for CTF automation.\n\n"
                f"OBJECTIVE\n"
                f"- Decide if a runnable exploit can be produced NOW based on the provided context.\n"
                f"- If YES, output a complete exploit program (prefer Python/pwntools; C is acceptable) with clear build/run instructions.\n"
                f"- If NO, output a highly detailed, step-by-step PROCEDURE in English to reach exploitation, including exact commands.\n\n"
                f"INPUT CONTEXT\n"
                f"[State.json]\n{state_json}\n\n"
                f"DECISION RULES\n"
                f"- Choose \"code\" ONLY if you have concrete, non-fabricated values needed to run (e.g., exact offset, leak, function addresses, protocol, IO prompts, remote host/port) from State.json (signals/runs) or the provided notes.\n"
                f"- NEVER invent addresses/offsets/gadgets. If a required value is missing, you MUST choose \"procedural\" and show how to obtain it.\n"
                f"- When mitigations (NX/PIE/Canary/RELRO) are present in signals, adapt technique (e.g., ret2win, ROP, SROP, ret2libc, fmtstr write) accordingly.\n"
                f"- Respect remote vs local setup from env/artifacts (e.g., HOST/PORT, binary path). If remote is present, include a remote path in code.\n\n"
                f"CODE REQUIREMENTS (when decision == code)\n"
                f"- Preferred language order: python(pwntools) → C.\n"
                f"- Provide a SINGLE self-contained file with comments. For Python, include a top-level constants section like BINARY, HOST, PORT, OFFSET, ADDR_WIN, LIBC_PATH, etc.\n"
                f"- If any constant is unknown, use an ALL_CAPS TODO placeholder (e.g., OFFSET=TODO_OFFSET) and ONLY if the rest is runnable. Do not fake values.\n"
                f"- Use deterministic IO (e.g., r.recvuntil, r.sendline), a clean local()/remote() switch, timeouts, and simple error handling.\n"
                f"- For C: include full build and run commands (e.g., gcc flags, -no-pie, -fno-stack-protector if appropriate) and required headers. Keep it non-interactive.\n"
                f"- Include a short 'Run' section (exact commands) and 'Expected' signals (e.g., 'got shell', 'printed flag pattern').\n"
                f"- If ROP is used, show how gadgets/addresses are obtained (from leaks or provided symbols). Do NOT fabricate gadgets.\n\n"
                f"PROCEDURE REQUIREMENTS (when decision == procedural)\n"
                f"- Provide a numbered, concrete sequence to achieve exploitation from the current state, focusing on evidence gaps (offsets, leaks, base calc, gadgets).\n"
                f"- For each step, include: name, exact command (shell-ready), expected success signal, and artifact to save.\n"
                f"- Cover both local repro and (if applicable) remote validation. Include how to extract missing values (e.g., cyclic offset, leak parsing, libc ID, base calc, ROP chain synthesis).\n"
                f"- End with clear criteria for \"ready to write code\" (i.e., which values must be known).\n\n"
                f"OUTPUT POLICY\n"
                f"- Be terse and precise. No fluff. Do NOT include any text outside the JSON.\n"
                f"- Include ONLY the keys specified below. Omit any unused/unknown keys entirely (do NOT output null or empty strings).\n"
                f"- All content must be in English.\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                f"{{\n"
                f"  \"decision\": \"code\" | \"procedural\",\n"
                f"  \"rationale\": \"2–4 sentences explaining why this choice is correct based on the inputs\",\n"
                f"  \"exploit\": {{\n"
                f"    \"language\": \"python|c\",\n"
                f"    \"requirements\": [\"pwntools>=4.10\"],\n"
                f"    \"entrypoint\": \"exploit.py\",\n"
                f"    \"build\": \"-\" ,\n"
                f"    \"run\": \"python3 exploit.py\",\n"
                f"    \"expected\": \"observable success criteria (e.g., got shell, printed flag pattern)\",\n"
                f"    \"code\": \"\"\"<FULL SOURCE CODE HERE>\"\"\"\n"
                f"  }},\n"
                f"  \"procedure\": {{\n"
                f"    \"steps\": [\n"
                f"      {{ \"name\": \"short label\", \"cmd\": \"exact terminal command\", \"expected\": \"success signal\", \"artifact\": \"file to save or '-'\" }}\n"
                f"    ]\n"
                f"  }}\n"
                f"}}\n"
                f"Notes:\n"
                f"- Include the 'exploit' object ONLY when decision==\"code\"; include the 'procedure' object ONLY when decision==\"procedural\".\n"
                f"- NEVER fabricate offsets/addresses/gadgets/libc versions. If unknown, choose \"procedural\" and show how to derive them.\n"
                f"- Keep code/run instructions copy-pasteable and deterministic.\n"
            )
