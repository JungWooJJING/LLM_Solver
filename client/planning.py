import os
import json
import re
import hashlib
import time
from typing import List, Dict, Any

from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from rich.console import Console

console = Console()
expand_k = 3

# 가중치(점수 계산용)
w = {"feasibility": 0.25, "info_gain": 0.30, "novelty": 0.20, "cost": 0.15, "risk": 0.15}

# 파일들
STATE_FILE = "state.json"
COT_FILE = "CoT.json"
TOT_FILE = "ToT.json"
TOT_SCORED_FILE = "ToT_scored.json"
INSTRUCTION_FILE = "instruction.json"

# 보관 한도(슬라이딩 윈도우)
MAX_SIGNALS = 50
MAX_RUNS = 50
MAX_SUMMARIES = 50
MAX_HISTORY_ITERS = 20   # cot_history 보관 이터레이션 수 제한
MAX_ACTIVE = 5           # 즉시 시도할 후보 수(활성 후보 노출 상한)

DEFAULT_STATE = {
  "iter": 0,                     # 현재 반복 횟수(Iteration)
  "goal": "",                    # 전체 목표
  "constraints": ["no brute-force > 1000"],  # 고정 제약 조건
  "env": {},                     # 환경 변수/설정 값
  "cot_history": [],             # 각 Iteration별 후보(CoT) 기록
  "selected": {},                # 현재 선택된 후보(id 등)
  "results": []                  # 실행 결과 (id, verdict, signals, artifacts 등)
}

def _now_ts() -> float:
    return time.time()

def _normalize_text(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s

def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def _thought_key(thought: str) -> str:
    norm = _normalize_text(thought)
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]

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
    targets = [COT_FILE, TOT_FILE, TOT_SCORED_FILE, INSTRUCTION_FILE]
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

def _gen_cand_id(iter_no: int, i: int) -> str:
    return f"COT-{iter_no:04d}-{i+1:02d}"

def _prune_state_windows():
    st = load_state()
    if len(st.get("signals", [])) > MAX_SIGNALS:
        st["signals"] = st["signals"][-MAX_SIGNALS:]
    if len(st.get("runs", [])) > MAX_RUNS:
        st["runs"] = st["runs"][-MAX_RUNS:]
    if len(st.get("summaries", [])) > MAX_SUMMARIES:
        st["summaries"] = st["summaries"][-MAX_SUMMARIES:]
    save_state(st)

def append_summary(title: str, text: str, tags=None):
    st = load_state()
    st.setdefault("summaries", []).append({"title": title, "text": text, "tags": tags or []})
    save_state(st)
    _prune_state_windows()

# --------- 후보 풀 관리 ---------

def _upsert_candidates(new_list: List[Dict[str, Any]], source: str, iter_no: int):
    """
    CoT/ToT 로부터 생성된 후보들을 단일 풀(candidates_pool)에 업서트합니다.
    중복(thought 기반)은 key로 통합하고 cot/메타를 최신으로 유지합니다.
    """
    st = load_state()
    pool: Dict[str, Dict[str, Any]] = st.setdefault("candidates_pool", {})

    for c in new_list:
        thought = (c.get("thought") or "").strip()
        cot = (c.get("cot") or "").strip()
        if not thought:
            continue

        k = _thought_key(thought)
        prev = pool.get(k, {})
        if not prev:
            pool[k] = {
                "id": c.get("id") or f"{source}-{iter_no}-{len(pool)+1}",
                "key": k,
                "thought": thought,
                "cot": cot,
                "refined_from": c.get("refined_from"),
                "created_iter": iter_no,
                "updated_ts": _now_ts(),
                "status": "pending",                # pending / selected / executed_success / executed_failed / disabled
                "base_score": float(c.get("calculated_score", c.get("score", 0.0))) if isinstance(c, dict) else 0.0,
                "dynamic_score": 0.0,
                "penalties": 0.0,
                "metadata": {},
                "stats": {"seen": 0, "selected": 0, "executed": 0, "success": 0, "failed": 0}
            }
        else:
            # 기존 항목 업데이트(더 풍부한 cot, refined_from 등 병합)
            if cot:
                pool[k]["cot"] = cot
            if not pool[k].get("refined_from") and c.get("refined_from"):
                pool[k]["refined_from"] = c.get("refined_from")
            # ToT에서 base_score가 들어올 수도 있음
            if "calculated_score" in c or "score" in c:
                pool[k]["base_score"] = float(c.get("calculated_score", c.get("score", 0.0)))
            pool[k]["updated_ts"] = _now_ts()

        # 메타데이터 병합
        md = pool[k].setdefault("metadata", {})
        for fld in ("expected_artifacts", "requires", "risk", "estimated_cost", "notes"):
            if c.get(fld):
                md[fld] = c[fld]

    st["candidates_pool"] = pool
    save_state(st)

def _recompute_scores():

    st = load_state()
    pool: Dict[str, Dict[str, Any]] = st.get("candidates_pool", {})
    sigs = st.get("signals", [])[-5:]
    constraints = st.get("constraints_dynamic", [])[-5:]

    for k, c in pool.items():
        status = c.get("status")
        if status in ("executed_success", "executed_failed", "disabled"):
            c["dynamic_score"] = -1.0
            continue

        base = float(c.get("base_score", 0.0))
        penalties = float(c.get("penalties", 0.0))

        # 최근 신호/제약과의 키워드 매칭(간단 가산)
        bonus = 0.0
        joined = f'{c.get("thought","")} {c.get("cot","")}'.lower()
        for s in sigs:
            s_name = str(s)[:64].lower()
            if s_name and s_name in joined:
                bonus += 0.03
        for cons in constraints:
            cons_l = str(cons).lower()
            if cons_l and cons_l in joined:
                bonus += 0.02

        # 실패/반복 페널티
        tried = c.get("stats", {}).get("executed", 0)
        failed = c.get("stats", {}).get("failed", 0)
        repeat_pen = min(tried * 0.02, 0.1) + min(failed * 0.05, 0.3)

        # 시간 감쇠(오래된 pending은 소폭 감점)
        age = max(1.0, (_now_ts() - c.get("updated_ts", _now_ts())) / 3600.0)
        decay = max(0.9, 1.0 - min(age / 48.0, 0.1))  # 48시간마다 최대 0.1까지 감쇠

        dyn = (base + bonus - penalties - repeat_pen) * decay
        c["dynamic_score"] = round(dyn, 4)

    st["candidates_pool"] = pool
    save_state(st)

def _select_active_topk(k: int = MAX_ACTIVE) -> List[Dict[str, Any]]:
    """
    pending 후보 중 동적 점수 상위 k개를 active_candidates로 노출합니다.
    """
    st = load_state()
    pool: Dict[str, Dict[str, Any]] = st.get("candidates_pool", {})
    pending = [c for c in pool.values() if c.get("status") == "pending"]
    pending.sort(key=lambda x: x.get("dynamic_score", 0.0), reverse=True)
    chosen = pending[:k]
    st["active_candidates"] = [
        {"id": c["id"], "thought": c["thought"], "refined_from": c.get("refined_from")}
        for c in chosen
    ]
    save_state(st)
    return st["active_candidates"]

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

    # 3) results 확인
    results = st.setdefault("results", [])
    if not isinstance(results, list):
        raise SystemExit("[!] results는 리스트여야 합니다.")

    # 4) 업서트: 리스트 내부에서 id 매칭 항목 '수정', 없으면 '추가'
    key = str(cand_id).strip()
    idx = next(
        (i for i, it in enumerate(results)
         if isinstance(it, dict) and str(it.get("id", "")).strip() == key),
        -1
    )

    if idx >= 0:
        item = results[idx]
        # summary / verdict 갱신
        item.update(patch)

        # signals 병합
        cur = item.get("signals")
        if isinstance(cur, list):
            cur.extend(signals)
        else:
            item["signals"] = list(signals)
    else:
        # 없으면 새 항목으로 추가
        results.append({
            "id": cand_id,
            **patch,
            "signals": list(signals),
        })

    # 5) 저장
    save_state(st)

class PlanningClient:
    def __init__(self, api_key: str, model: str = "gpt-5"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def _build_messages_stateless(self, phase_system_prompt: str, user_prompt: str, include_state: bool = True):
        msgs = [
            {"role": "developer", "content": "You are a CTF planning assistant. Keep answers concise."},
            {"role": "developer", "content": phase_system_prompt},
        ]
        if include_state:
            state = load_state()
            msgs.append({"role": "assistant", "content": json.dumps(state, ensure_ascii=False)})
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
        raw_cands = data.get("candidates", []) or []

        it = _next_iter()
        st = load_state()

        cands = []
        for idx, cand in enumerate(raw_cands, start=1):
            cands.append({
                "id": f"COT-{it}-{idx}",
                "cot": cand.get("cot"),
                "thought": cand.get("thought"),
                "requires": cand.get("requires"),
                "rf": None 
            })

        st.setdefault("cot_history", []).append({"iter": it, "candidates": cands})

        if len(st["cot_history"]) > MAX_HISTORY_ITERS:
            st["cot_history"] = st["cot_history"][-MAX_HISTORY_ITERS:]

        save_state(st)

    def build_tot_input_from_state(self):
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

        tot_in = []
        for idx, c in enumerate(pick, start=1):
            cid = f"COT-{iter_no}-{idx}"
            tot_in.append({
                "id": cid,
                "thought": c.get("thought",""),
                "refined_from": c.get("refined_from"),  
                "hints": {
                    "signals": signals_tail,
                    "constraints": constraints_tail
                }
            })
        return {"candidates": tot_in}

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

        data["results"].sort(key=lambda x: x.get("calculated_score", x.get("score", 0.0)), reverse=True)

        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        console.print(f"Save: {outfile}", style='green')
        return data
    
    def update_state_from_tot(self, tot_results: dict):
        st = load_state()

        # 최신 iteration의 후보(생성된 CoT) 가져오기
        last_cands = []
        for entry in reversed(st.get("cot_history", [])):
            if entry.get("candidates"):
                last_cands = entry["candidates"]
                break

        # thought→id, idx(0-based)→id 매핑 준비
        def _norm(s: str) -> str:
            return " ".join((s or "").split()).lower()

        thought_to_id = { _norm(c.get("thought","")): c.get("id")
                        for c in last_cands if c.get("id") }
        idx_to_id = { i: c.get("id") for i, c in enumerate(last_cands) if c.get("id") }

        items = tot_results.get("results") or tot_results.get("candidates") or []
        if not items:
            # 입력이 비었으면 selected는 비우고, results는 변화 없이 두는 게 안전합니다.
            st["selected"] = {}
            save_state(st)
            return st["selected"]

        # 최고 점수 1개 선택 (calculated_score 우선 → score 보조)
        def _score(x):
            v = x.get("calculated_score", x.get("score"))
            return float(v) if v is not None else float("-inf")

        top = max(items, key=_score)

        # id 매핑: thought 우선 → idx 보조(0/1-based 모두 시도)
        cid = top.get("id")
        if not cid:
            cid = thought_to_id.get(_norm(top.get("thought","")))
        if not cid:
            idx = top.get("idx")
            if isinstance(idx, int):
                cid = idx_to_id.get(idx) or idx_to_id.get(idx - 1)

        record = {
            "id": cid,  # 매핑 실패 시 None일 수 있음
            "score": float(top.get("calculated_score", top.get("score", 0.0))),
            "thought": top.get("thought", ""),
            "notes": top.get("notes", "")
        }

        # results: 누적(append) 저장
        st.setdefault("results", []).append(record)
        # selected: 현재 선택으로 덮어쓰기
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
            tot_input = self.build_tot_input_from_state()
            response_ToT = self.run_prompt_ToT(json.dumps(tot_input, ensure_ascii=False))
            self.save_prompt(TOT_FILE, response_ToT)

            tot_cal = self.cal_ToT()
            self.update_state_from_tot(tot_cal)

            parsing_response = ctx.parsing.human_translation(json.dumps(tot_cal, ensure_ascii=False, indent=2))
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
            tot_input = self.build_tot_input_from_state()
            response_ToT = self.run_prompt_ToT(json.dumps(tot_input, ensure_ascii=False))
            self.save_prompt(TOT_FILE, response_ToT)

            tot_cal = self.cal_ToT()
            self.update_state_from_tot(tot_cal)

            parsing_response = ctx.parsing.human_translation(json.dumps(tot_cal, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--exploit":
            console.print("Please wait. I will prepare an exploit script or a step-by-step procedure.", style="blue")
            # state.json -> exploit client -> result print

        elif option == "--instruction":
            console.print("I will provide step-by-step instructions based on a Tree-of-Thought plan.", style="blue")

            if not os.path.exists(TOT_SCORED_FILE):
                console.print("ToT_scored.json not found. Run --file or --discuss first.", style="bold red")
                return

            state = load_state()
            with open(TOT_SCORED_FILE, "r", encoding="utf-8") as f:
                tot_scored = json.load(f)

            state_json = json.dumps(state, ensure_ascii=False)
            tot_json = json.dumps(tot_scored, ensure_ascii=False)

            planning_instruction = self.build_prompt("--instruction", state_json=state_json, tot_json=tot_json)

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

            console.print("=== run_prompt_ToT ===", style='bold green')
            tot_input = self.build_tot_input_from_state()
            response_ToT = self.run_prompt_ToT(json.dumps(tot_input, ensure_ascii=False))
            self.save_prompt(TOT_FILE, response_ToT)

            tot_cal = self.cal_ToT()
            self.update_state_from_tot(tot_cal)

            parsing_response = ctx.parsing.human_translation(json.dumps(tot_cal, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')

        elif option == "--quit":
            cleanUp()
            console.print("\nGoodbye!\n", style="bold yellow")
            exit(0)

        else:
            console.print("This command does not exist.", style="bold yellow")
            console.print("If you are unsure about the commands, run '--help'.", style="bold yellow")

    def build_prompt(self, option: str, query: str = "", plan_json: str = "",
                     state_json: str = "", tot_json: str = "", feedback_json: str = ""):

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
                f"Respond ONLY in the following STRICT JSON format:\n"
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
                "No prose outside JSON."
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
                '      "thought": "one-line concrete next step",\n'
                '      "expected_artifacts": ["file1", "file2"],\n'
                '      "requires": ["tool/permission/dependency"],\n'
                '      "risk": "short note",\n'
                '      "estimated_cost": "low|medium|high",\n'
                '      "cmd": "exact terminal command",\n'
                '      "ok": true,\n'
                '      "result": "result text (e.g., tail or key line)",\n'
                '      "summary": "<=120 chars one-line summary"\n'
                "    }\n"
                "  ]\n"
                "}}\n"
                "No prose outside JSON."
            )
