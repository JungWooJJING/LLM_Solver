import os
import json, re

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

console = Console()
expand_k = 3 

w = { "feasibility":0.20, "info_gain":0.30, "novelty":0.20, "cost":0.15, "risk":0.15 } 

STATE_FILE = "state.json"
COT_FILE = "CoT.json"
TOT_FILE = "ToT.json"
TOT_SCORED_FILE = "ToT_scored.json"
INSTRUCTION_FILE = "instruction.json"

DEFAULT_STATE = {
    "goal": "",
    "constraints": ["no brute-force > 1000"],
    "env": {},
    "artifacts": {"binary": "", "logs": [], "hashes": {}},
    "candidates_topk": [],
    "selected": {},
    "evidence": [],
    "next_action_hint": "",
    "summary": ""
}

def multi_line_input():
    console.print("Enter multiple lines. Type <<<END>>> on a new line to finish input.", style="bold yellow")
    lines = []
    while True:
        line = input(" ")
        if line.strip() == "<<<END>>>":
            break
        lines.append(line)
    return "\n".join(lines)

def cleanUp():
    for f in (COT_FILE, TOT_FILE, TOT_SCORED_FILE, INSTRUCTION_FILE, STATE_FILE):
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
        
def safe_json_loads(s: str):
    try:
        return json.loads(s)
    
    except Exception:
        s = s[s.find("{"): s.rfind("}")+1]
        s = re.sub(r"```(json)?|```", "", s).strip()
        return json.loads(s)


class PlanningClient:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def _build_messages_stateless(self, phase_system_prompt: str, user_prompt: str, include_state: bool = True):
        msgs = [
            {"role": "system", "content": "You are a CTF planning assistant. Keep answers concise."},
            {"role": "system", "content": phase_system_prompt},
        ]
        if include_state:
            state = load_state()
            msgs.append({"role": "user", "content": json.dumps(state, ensure_ascii=False)})
        msgs.append({"role": "user", "content": user_prompt})
        
        return msgs
        
    def _ask_stateless(self, phase_system_prompt: str, user_prompt: str, include_state: bool = True):
        
        messages = self._build_messages_stateless(phase_system_prompt, user_prompt, include_state)
        
        res = self.client.chat.completions.create(model=self.model, messages=messages)
        
        return res.choices[0].message.content

    def run_prompt_CoT(self, prompt: str):

        return self._ask_stateless(CTFSolvePrompt.planning_prompt_CoT, prompt, include_state=True)

    def run_prompt_ToT(self, prompt: str):

        return self._ask_stateless(CTFSolvePrompt.planning_prompt_ToT, prompt, include_state=False)

    def update_state_from_cot(self, cot_text: str):
        data = safe_json_loads(cot_text)
        candidates = data.get("candidates", [])
        compact = []
        for c in candidates:
            compact.append({
                "cot": c.get("cot", "")[:400],
                "thought": c.get("thought", ""),
                "expected_artifacts": c.get("expected_artifacts", [])[:5],
                "requires": c.get("requires", [])[:5],
                "risk": c.get("risk", ""),
                "estimated_cost": c.get("estimated_cost", "low")
            })
        state = load_state()
        state["candidates_topk"] = compact  
        save_state(state)
        
    def update_state_from_tot(self, tot_results_dict: dict, topk: int = 3):
        results = tot_results_dict.get("results", [])
        state = load_state()
        state["candidates_topk"] = [{
            "idx": r.get("idx"),
            "thought": r.get("thought", ""),
            "score": r.get("calculated_score", r.get("score", 0.0)),
            "notes": r.get("notes", "")
        } for r in results[:topk]]

        if results:
            top1 = results[0]
            state["selected"] = {
                "idx": top1.get("idx", 0),
                "thought": top1.get("thought", ""),
                "score": top1.get("calculated_score", 0.0),
                "notes": top1.get("notes", "")
            }
            state["next_action_hint"] = top1.get("thought", "")
        save_state(state)

    def cal_ToT(self, tot_json_str: str = None, infile: str = "ToT.json", outfile: str = "ToT_scored.json"):

        if tot_json_str is None:
            with open(infile, "r", encoding="utf-8") as f:
                data = safe_json_loads(f.read())
        else:
            data = safe_json_loads(tot_json_str)

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

        data["results"].sort(key=lambda x: x.get("calculated_score", 0.0), reverse=True)

        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        console.print(f"Save: {outfile}", style='green')
        
        return data

    def save_prompt(self, filename: str, content: str):
        with open(filename, "w") as f:
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
            console.print("--quit : Exit the program.", style="bold yellow")

        elif option == "--showplan":
            if not os.path.exists(TOT_SCORED_FILE):
                console.print("ToT_scored.json not found. Run --file or --discuss first.", style="bold red")
                return
            with open(TOT_SCORED_FILE, "r", encoding="utf-8") as f:
                console.print("[bold cyan]Current ToT Plan (scored):[/bold cyan]\n")
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

            console.print("=== run_prompt_ToT ===", style='bold green')
            response_ToT = self.run_prompt_ToT(response_CoT)
            self.save_prompt(TOT_FILE, response_ToT)

            tot_cal = self.cal_ToT()  

            self.update_state_from_tot(tot_cal)

            parsing_response = ctx.parsing.human_translation(
                json.dumps(tot_cal, ensure_ascii=False, indent=2)
            )
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

            console.print("=== run_prompt_ToT ===", style='bold green')
            response_ToT = self.run_prompt_ToT(response_CoT)
            self.save_prompt(TOT_FILE, response_ToT)

            tot_cal = self.cal_ToT()
            self.update_state_from_tot(tot_cal)

            parsing_response = ctx.parsing.human_translation(
                json.dumps(tot_cal, ensure_ascii=False, indent=2)
            )
            console.print(parsing_response, style='bold green')
            
        elif option == "--exploit":  
            console.print("Please wait. I will prepare an exploit script or a step-by-step procedure.", style="blue")

        elif option == "--instruction":
            console.print("I will provide step-by-step instructions based on a Tree-of-Thought plan.", style="blue")

            if not os.path.exists(TOT_SCORED_FILE):
                console.print("ToT_scored.json not found. Run --file or --discuss first.", style="bold red")
                return

            state = load_state()
            with open(TOT_SCORED_FILE, "r", encoding="utf-8") as f:
                tot_scored = json.load(f)

            state_json = json.dumps(state, ensure_ascii=False)
            tot_json   = json.dumps(tot_scored, ensure_ascii=False)

            planning_instruction = self.build_prompt(
                "--instruction",
                state_json=state_json,
                tot_json=tot_json
            )
            
            console.print("wait...", style='bold green')
            instruction_json = ctx.instruction.run_prompt_instruction(prompt=planning_instruction)
            self.save_prompt(INSTRUCTION_FILE, instruction_json)
            
            parsing_response = ctx.parsing.human_translation(
                json.dumps(instruction_json, ensure_ascii=False, indent=2)
            )
            
            console.print(parsing_response, style="yellow")
            
        elif option == "--result":
            console.print("Paste the result of your command execution. Submit <<<END>>> to finish.", style="blue")
            result_output = multi_line_input()

            state = load_state()
            
            result_build_prompt = self.build_prompt(option=option, query=result_output, state_json=state)
            
            console.print("wait...", style="bold green")
            result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)
            
            console.print("=== Feedback === ", style="bold green")
            result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)
            
            plan_build_prompt = self.build_prompt(option="--plan", state_json=state, feedback_json=result_feedback)
            
            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = self.run_prompt_CoT(plan_build_prompt)
            self.save_prompt(COT_FILE, response_CoT)

            self.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_ToT ===", style='bold green')
            response_ToT = self.run_prompt_ToT(response_CoT)
            self.save_prompt(TOT_FILE, response_ToT)

            tot_cal = self.cal_ToT()  

            self.update_state_from_tot(tot_cal)

            parsing_response = ctx.parsing.human_translation(
                json.dumps(tot_cal, ensure_ascii=False, indent=2)
            )
            console.print(parsing_response, style='yellow')

        elif option == "--quit":
            cleanUp()
            console.print("\nGoodbye!\n", style="bold yellow")
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")

    def build_prompt(self, option: str, query: str = "", plan_json: str = "",
                 state_json: str = "", tot_json: str = "", feedback_json: str=""):
        
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
                '      "thought": "one-line concrete next step",\n'
                '      "expected_artifacts": ["file1", "file2"],\n'
                '      "requires": ["tool/permission/dependency"],\n'
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
                f"Respond ONLY in the following STRICT JSON format (required fields shown below):\n"
                "{{\n"
                '  "candidates": [\n'
                "    {\n"
                '      "cot": "3-5 sentences reasoning",\n'
                '      "thought": "one-line concrete next step",\n'
                '      "expected_artifacts": ["file1", "file2"],\n'
                '      "requires": ["tool/permission/dependency"],\n'
                '      "risk": "short note",\n'
                '      "estimated_cost": "low|medium|high"\n'
                "    }\n"
                "  ]\n"
                "}}\n"
                "No prose outside the JSON."
        )

        elif option == "--instruction":
            return (
                f"You are an instruction generator for CTF automation.\n\n"
                f"INPUT\n"
                f"- You will receive a JSON payload that contains:\n"
                f"  - state: current progress (goal, constraints, env, artifacts.binary, candidates_topk, selected, evidence, optional runs/seen_cmd_hashes)\n"
                f"  - tot_scored_topk: top-k ToT results for the immediate next step\n\n"
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
                f"[Payload]\nState.json : {state_json}\nToT_Scored.json : {tot_json}\n\n"
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
                f"Apply minimal DELTAS based on feedback and select ONE next action to execute.\n\n"
                f"[State.json]\n{state_json}\n\n"
                f"[Feedback.json]\n{feedback_json}\n\n"
                f"POLICY\n"
                f"- Keep existing hypothesis IDs/names stable; no wholesale rewrites.\n"
                f"- Only DELTA updates (confidence tweaks, short result note, toolset/constraints appends, and small next steps).\n"
                f"- Next steps must be investigative/preparatory; no solving/flags.\n"
                f"- Commands must be shell-ready and non-interactive.\n\n"
                f"Respond ONLY in this STRICT JSON format:\n"
                f"{{\n"
                f"  \"candidates\": [\n"
                f"    {{\n"
                f"      \"cot\": \"3-5 sentences reasoning\",\n"
                f"      \"thought\": \"one-line concrete next step\",\n"
                f"      \"expected_artifacts\": [\"file1\", \"file2\"],\n"
                f"      \"requires\": [\"tool/permission/dependency\"],\n"
                f"      \"risk\": \"short note\",\n"
                f"      \"estimated_cost\": \"low|medium|high\",\n"
                f"      \"cmd\": \"exact terminal command\",\n"
                f"      \"ok\": true,\n"
                f"      \"result\": \"result text (e.g., tail or key line)\",\n"
                f"      \"summary\": \"<=120 chars one-line summary\"\n"
                f"    }}\n"
                f"  ]\n"
                f"}}"
                "No prose outside JSON."
            )