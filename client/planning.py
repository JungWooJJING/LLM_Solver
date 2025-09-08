import os
import json
import re
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/home/wjddn0623/Ghidra/ghidra/build/dist/ghidra_12.0_DEV"
pyghidra.start()

from typing import List, Dict, Any

from openai import OpenAI
from .todo import add_todos_from_actions, run_ready, load_plan
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
PLAN_FILE = "plan.json"

MAX_HISTORY_ITERS = 20
MAX_ACTIVE = 5

DEFAULT_STATE = {
  "iter": 0,
  "goal": "",
  "constraints": ["no brute-force > 1000"],
  "env": {},
  "selected": {},
  "results": []
}

DEFAULT_PLAN = {
  "todos": [],
  "runs": [],
  "seen_cmd_hashes": [],
  "artifacts": {},
  "backlog" : []
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
    targets = [COT_FILE, Cal_FILE, Cal_SCORED_FILE, INSTRUCTION_FILE, PLAN_FILE]
    if all:
        targets.append(STATE_FILE)
    for f in targets:
        if os.path.exists(f):
            os.remove(f)
            
def load_plan() -> Dict[str, Any]:
    if not os.path.exists(PLAN_FILE):
        save_plan(DEFAULT_PLAN.copy())
    with open(PLAN_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_plan(plan: dict) -> None:
    with open(PLAN_FILE, "w", encoding="utf-8") as f:
        json.dump(plan, f, ensure_ascii=False, indent=2)

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

def plan_view_for_llm(plan: Dict[str, Any], runs_last: int = 8, todos_max: int = 20) -> Dict[str, Any]:
    todos_pending = [
        {"id": t.get("id"), "cmd": t.get("cmd"), "success": t.get("success",""), "artifact": t.get("artifact","-")}
        for t in plan.get("todos", [])
        if isinstance(t, dict) and t.get("status") == "pending" and "cmd" in t
    ][:todos_max]

    runs = [
        {"id": r.get("id"), "todo_id": r.get("todo_id"), "cmd": r.get("cmd"), "ok": r.get("ok"), "ts": r.get("ts")}
        for r in plan.get("runs", [])
        if isinstance(r, dict) and "cmd" in r
    ][-runs_last:]

    already_success_cmds = sorted({r.get("cmd") for r in plan.get("runs", []) if r.get("ok")})
    artifacts = sorted(list(plan.get("artifacts", {}).keys()))
    return {
        "todos_pending": todos_pending,
        "runs_recent": runs,
        "already_success_cmds": already_success_cmds,
        "artifacts": artifacts,
    }

def build_plan_context_json() -> str:
    return json.dumps(plan_view_for_llm(load_plan()), ensure_ascii=False)

class PlanningClient:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def compress_history(self, history : List, ctx):
    
        if not os.path.exists("state.json"):
            print("Error")
            exit(-1)        
        
        console.print("Compress state.json", style="bold green")
        
        with open("state.json", "r", encoding="utf-8") as f:
            state = json.load(f)

        result_pompress = ctx.parsing.run_prompt_state_compress(json.dumps(state))
        
        if isinstance(result_pompress, str):
                obj = json.loads(result_pompress)
        else:
            obj = result_pompress
            
        if not isinstance(obj, dict):
            console.print("Error: compressor returned non-JSON-object", style="red")
            exit(-1)
            
        with open("state.json", "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            
        console.print("Compress history query", style="bolid green")
        
        prompt = [
        {"role": "developer", "content": CTFSolvePrompt.compress_history},
        {"role": "user",      "content": json.dumps(history, ensure_ascii=False)},
        ]
        
        try:
            res = self.client.chat.completions.create(model=self.model, messages=prompt)
            raw = res.choices[0].message.content               
            payload = json.loads(raw)                          
            new_history = payload["messages"]                  

            if not (isinstance(new_history, list) and all(
                isinstance(m, dict) and "role" in m and "content" in m for m in new_history
            )):
                raise ValueError("compressor returned invalid messages[]")

            return new_history

        except Exception:   
            return history
         
    def run_prompt_CoT(self, prompt_query: str, ctx):
        global prompt_CoT  

        state = load_state()
        state_msg = {"role": "developer", "content": "[STATE]\n" + json.dumps(state, ensure_ascii=False)}
        user_msg  = {"role": "user",   "content": prompt_query}

        if not isinstance(prompt_CoT, list):
            prompt_CoT = []

        len0 = len(prompt_CoT)
        prompt_CoT.extend([state_msg, user_msg])

        try:
            res = self.client.chat.completions.create(model=self.model, messages=prompt_CoT)
            prompt_CoT.append({"role": "assistant", "content": res.choices[0].message.content})
            return res.choices[0].message.content

        except Exception as e:
            del prompt_CoT[len0:]   

            compressed = self.compress_history(prompt_CoT, ctx=ctx)  
            prompt_CoT[:] = compressed

            prompt_CoT.extend([state_msg, user_msg])

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

    def build_Cal(self):
        st = load_state()
        plan = load_plan()
        
        backlog = [c for c in plan.get("backlog", []) if isinstance(c, dict)]
        if not backlog and os.path.exists(COT_FILE):
            try:
                with open(COT_FILE, "r", encoding="utf-8") as f:
                    cot = json.load(f)
                backlog = [c for c in cot.get("candidates", []) if isinstance(c, dict)]
            except Exception:
                backlog = []
                
        pv = plan_view_for_llm(plan)
        pending_cmds    = {t.get("cmd") for t in pv.get("todos_pending", []) if t.get("cmd")}
        success_cmds    = set(pv.get("already_success_cmds", []))
        have_artifacts  = set(pv.get("artifacts", []))
        
        picked = []
        seen_thoughts = set()
        
        for c in reversed(backlog):  
            thought = (c.get("thought") or "").strip()
            if not thought:
                continue

            nt = _norm(thought)
            if nt in seen_thoughts:
                continue

            exp_art = set(c.get("expected_artifacts") or [])
            if exp_art and (exp_art & have_artifacts):
                continue

            cmd = c.get("cmd")
            if cmd and (cmd in pending_cmds or cmd in success_cmds):
                continue

            seen_thoughts.add(nt)
            picked.append(c)
            if len(picked) >= MAX_ACTIVE:
                break

        picked.reverse()

        signals_tail = []
        seen_sig = set()
        for res in reversed(st.get("results", [])):
            for s in (res.get("signals") or []):
                key = (s.get("type"), s.get("name"), s.get("value"))
                if key in seen_sig:
                    continue
                seen_sig.add(key)
                signals_tail.append(s)
                if len(signals_tail) >= 5:
                    break
            if len(signals_tail) >= 5:
                break

        constraints_tail = (st.get("constraints") or [])[:3]

        iter_no = int(st.get("iter", 0))
        cal_in = []
        for idx, c in enumerate(picked, start=1):
            cid = (c.get("id")
                or c.get("cid")
                or f"COT-{iter_no}-{idx}")
            cal_in.append({
                "id": cid,
                "thought": (c.get("thought") or "").strip(),
                "vuln_hypothesis": c.get("vuln_hypothesis", "") or "",
                "attack_path": c.get("attack_path", "") or "",
                "rf": c.get("refined_from") or c.get("rf"),
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

    def update_plan_from_CoT(self, cot_text: str):
        data = safe_json_loads(cot_text)
        raw_cands = data.get("candidates", []) or []

        it = _next_iter()              
        plan = load_plan()              
        backlog = plan.setdefault("backlog", [])

        existing = {(b.get("src_id"), b.get("thought")) for b in backlog if isinstance(b, dict)}

        new_ids = []
        for idx, c in enumerate(raw_cands, start=1):
            thought = (c.get("thought") or "").strip()
            if not thought:
                continue

            item = {
                "src_id": f"COT-{it}-{idx}",
                "thought": thought,
                "vuln_hypothesis": c.get("vuln_hypothesis") or "",
                "attack_path": c.get("attack_path") or "",
                "mini_poc": c.get("mini_poc") or "",
                "expected_artifacts": c.get("expected_artifacts") or [],
                "requires": c.get("requires") or [],
                "success_criteria": c.get("success_criteria") or []
            }

            key = (item["src_id"], item["thought"])
            if key not in existing:
                backlog.append(item)
                new_ids.append(item["src_id"])

        save_plan(plan)
        
    def update_state_from_cal(self, cal_result: dict):
        st = load_state()

        try:
            plan = load_plan()
        except Exception:
            plan = {}

        backlog = plan.get("backlog") or []
        thought_to_id = {}
        idx_to_id = {}
        for i, c in enumerate(backlog):
            if isinstance(c, dict):
                tid = c.get("id")
                th = (c.get("thought") or "").strip()
                if th and tid:
                    thought_to_id[_norm(th)] = tid
                    idx_to_id[i] = tid

        items = cal_result.get("results") or cal_result.get("candidates") or []
        if not items:
            st["selected"] = {}
            save_state(st)
            return st["selected"]

        top = max(items, key=_score)

        cid = top.get("id")
        if not cid:
            cid = thought_to_id.get(_norm(top.get("thought", "")))
        if not cid:
            idx = top.get("idx")
            if isinstance(idx, int):
                cid = idx_to_id.get(idx) or idx_to_id.get(idx - 1)
        if not cid:
            it = st.get("iter", 0)
            cid = f"SEL-{it}-{len(st.get('results', [])) + 1:03d}"

        record = {
            "id": cid,
            "score": float(top.get("calculated_score", top.get("score", 0.0)) or 0.0),
            "thought": top.get("thought", ""),
            "notes": top.get("notes", "")
        }

        results = st.setdefault("results", [])
        for r in results:
            if str(r.get("id")) == str(cid):
                r.update(record)
                break
        else:
            results.append(record)

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
            console.print("--instruction : Get step-by-step guidance based on a plan.", style="bold yellow")
            console.print("--exploit : Receive an exploit script or detailed exploitation steps.", style="bold yellow")
            console.print("--result : Update plan based on execution result.", style="bold yellow")
            console.print("--showplan : Show current plan.", style="bold yellow")
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
            response_CoT = self.run_prompt_CoT(planning_Prompt, ctx)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_plan_from_CoT(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal()
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
            response_CoT = self.run_prompt_CoT(planning_Prompt, ctx)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_plan_from_CoT(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal()
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
            response_CoT = self.run_prompt_CoT(planning_Prompt, ctx)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_plan_from_CoT(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt(Cal_FILE, response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--exploit":
            console.print("Please wait. I will prepare an exploit script or a step-by-step procedure.", style="blue")

            st = load_state()
            exploit_prompt = self.build_prompt(option=option, state_json=json.dumps(st, ensure_ascii=False))

            console.print("Creating Exploit...", style="bold green")
            exploit_code = ctx.exploit.run_prompt_exploit(exploit_prompt)

            console.print("=== Human Translation ===", style="bold green")
            parsing_response = ctx.parsing.human_translation(query=exploit_code)

            console.print(parsing_response, style="yellow")
            console.print("Input result", style="blue")
            result_output = multi_line_input()

            result_build_prompt = self.build_prompt(option="--result", query=result_output, state_json=json.dumps(st, ensure_ascii=False))

            console.print("=== LLM Translation ===", style="bold green")
            result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)

            console.print("=== Feedback === ", style="bold green")
            result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)

            update_state_json(result_feedback)
            console.print("Update State.json", style="bold green")

            plan_build_prompt = self.build_prompt(
                option="--plan",
                state_json=json.dumps(load_state(), ensure_ascii=False),
                plan_json=build_plan_context_json(),
                feedback_json=result_feedback
            )

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(plan_build_prompt, ctx)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_plan_from_CoT(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal()
            response_Cal = self.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            self.save_prompt(Cal_FILE, response_Cal)

            cal_result = self.cal_CoT()
            self.update_state_from_cal(cal_result)

            console.print("=== Human Translation ===", style="bold green")
            parsing_response = ctx.parsing.human_translation(json.dumps(cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--instruction":
            console.print("I will provide step-by-step instructions based on a plan.", style="blue")

            if not os.path.exists(Cal_SCORED_FILE):
                console.print("Cal_scored.json not found. Run --file or --discuss first.", style="bold red")
                return

            state = load_state()
            with open(Cal_SCORED_FILE, "r", encoding="utf-8") as f:
                Cal_scored = json.load(f)

            state_json = json.dumps(state, ensure_ascii=False)
            cal_json   = json.dumps(Cal_scored, ensure_ascii=False)
            plan_json  = build_plan_context_json()

            planning_instruction = self.build_prompt("--instruction", state_json=state_json, cal_json=cal_json, plan_json=plan_json)

            console.print("wait...", style='bold green')
            instruction_json = ctx.instruction.run_prompt_instruction(prompt=planning_instruction)
            self.save_prompt(INSTRUCTION_FILE, instruction_json)

            compiled = safe_json_loads(instruction_json)
            added_ids = add_todos_from_actions(compiled)

            summary = run_ready(state_provider=load_state, max_parallel=1, timeout=180)

            console.print(
                f"[TODO] added={len(added_ids)}  done={summary['done']}  "
                f"pending={summary['pending']}  failed={summary['failed']}  skipped={summary['skipped']}",
                style="bold cyan"
            )

            parsing_response = ctx.parsing.human_translation(json.dumps(instruction_json, ensure_ascii=False, indent=2))
            console.print(parsing_response, style="yellow")

        elif option == "--result":
            st = load_state()

            console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
            result_output = multi_line_input()

            result_build_prompt = self.build_prompt(
                option="--result",
                query=result_output,
                state_json=json.dumps(st, ensure_ascii=False)
            )

            console.print("wait...", style="bold green")
            result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)

            console.print("=== Feedback === ", style="bold green")
            result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)

            update_state_json(result_feedback)
            console.print("Update State.json", style="bold green")

            plan_build_prompt = self.build_prompt(
                "--plan",
                state_json=json.dumps(load_state(), ensure_ascii=False),
                plan_json=build_plan_context_json(),
                feedback_json=result_feedback
            )

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(plan_build_prompt, ctx)
            self.save_prompt(COT_FILE, response_CoT)
            self.update_plan_from_CoT(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = self.build_Cal()
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
                f"  - Cal_scored_topk: top-k Cal results for the immediate next step\n"
                f"  - plan_view: todos_pending, runs_recent, already_success_cmds, artifacts\n\n"
                f"[State.json]\n{state_json}\n\n"
                f"[Cal_Scored.json]\n{cal_json}\n\n"
                f"[Plan.view]\n{plan_json}\n\n"
                f"TASK\n"
                f"- Using ALL inputs, produce a minimal, concrete sequence of terminal actions to execute NEXT.\n"
                f"- BEFORE listing actions, write a brief 2–3 sentence rationale about execution order and expected outcomes.\n"
                f"- Do NOT attempt to solve the challenge; focus on preparation and evidence collection aligned with state.selected.thought.\n\n"
                f"POLICY\n"
                f"- Do NOT repeat any action whose exact cmd already appears in plan_view.already_success_cmds or in plan_view.todos_pending.\n"
                f"- Do NOT propose actions whose expected artifact already exists (same filename or clearly same purpose) in plan_view.artifacts.\n"
                f"- Prefer DELTA steps that produce NEW evidence/artifacts only.\n"
                f"- If state.selected.thought seems already executed, output ONLY the missing sub-steps.\n"
                f"- Keep commands shell-ready and deterministic.\n"
                f"- For each action, define 'success' as a plain substring or 're:<regex>'.\n\n"
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
                f"[Plan.view]\n{plan_json}\n\n"
                f"[Feedback.json]\n{feedback_json}\n\n"
                f"POLICY\n"
                f"- Keep existing hypothesis IDs/names stable; no wholesale rewrites.\n"
                f"- Generate {expand_k} distinct candidates. Avoid trivial variations; each must be meaningfully different.\n"
                f"- Only DELTA updates (confidence tweaks, short result note, toolset/constraints appends, and small next steps).\n"
                f"- Next steps must be investigative/preparatory; no solving/flags.\n"
                f"- Do NOT propose actions whose cmd matches any in Plan.view.todos_pending or Plan.view.already_success_cmds.\n"
                f"- Do NOT propose actions whose expected artifact already exists in Plan.view.artifacts.\n"
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
                f"- Choose \"code\" ONLY if you have concrete, non-fabricated values needed to run (e.g., exact offset, leak, function addresses, protocol, IO prompts, remote host/port).\n"
                f"- NEVER invent addresses/offsets/gadgets. If a required value is missing, you MUST choose \"procedural\" and show how to obtain it.\n"
                f"- When mitigations (NX/PIE/Canary/RELRO) are present in signals, adapt technique accordingly.\n"
                f"- Respect remote vs local setup.\n\n"
                f"CODE REQUIREMENTS (when decision == code)\n"
                f"- Preferred language: python(pwntools) → C.\n"
                f"- Provide a SINGLE self-contained file with comments and constants (BINARY, HOST, PORT, OFFSET, ADDR_WIN, LIBC_PATH, ...).\n"
                f"- Unknown constants must be ALL_CAPS TODO; do NOT fake values.\n"
                f"- Deterministic IO, local()/remote() switch, timeouts, error handling.\n"
                f"- For C: full build/run commands.\n\n"
                f"PROCEDURE REQUIREMENTS (when decision == procedural)\n"
                f"- Numbered steps with exact commands, expected success signal, artifact path.\n"
                f"- Cover local repro and remote validation if applicable.\n"
                f"- End with clear 'ready to write code' criteria.\n\n"
                f"OUTPUT POLICY\n"
                f"- Terse. JSON only. No extra keys.\n\n"
                f"{{\n"
                f"  \"decision\": \"code\" | \"procedural\",\n"
                f"  \"rationale\": \"2–4 sentences\",\n"
                f"  \"exploit\": {{\n"
                f"    \"language\": \"python|c\",\n"
                f"    \"requirements\": [\"pwntools>=4.10\"],\n"
                f"    \"entrypoint\": \"exploit.py\",\n"
                f"    \"build\": \"-\" ,\n"
                f"    \"run\": \"python3 exploit.py\",\n"
                f"    \"expected\": \"...\",\n"
                f"    \"code\": \"\"\"<FULL SOURCE CODE HERE>\"\"\"\n"
                f"  }},\n"
                f"  \"procedure\": {{\n"
                f"    \"steps\": [\n"
                f"      {{ \"name\": \"short label\", \"cmd\": \"exact terminal command\", \"expected\": \"success signal\", \"artifact\": \"file to save or '-'\" }}\n"
                f"    ]\n"
                f"  }}\n"
                f"}}\n"
            )
