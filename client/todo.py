import os, json, hashlib, subprocess, re
from datetime import datetime
from typing import Callable, Dict, Any, List

PLAN_FILE = "plan.json"

CMD_ALLOWLIST = re.compile(
  r'^(python3|gdb|ldd|checksec|file|strings|readelf|objdump|nm|ropper|ROPgadget|one_gadget|r2|radare2|strace|valgrind|timeout|env|grep|sed|awk|tee|cat|qemu-[^\s]+|\.\/[^\s]+)\b'
)

DEFAULT_PLAN = {
  "todos": [],
  "runs": [],
  "seen_cmd_hashes": [],
  "artifacts": {},
  "backlog" : []
}

def load_plan() -> Dict[str, Any]:
    if not os.path.exists(PLAN_FILE):
        save_plan(DEFAULT_PLAN.copy())
    with open(PLAN_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_plan(plan: dict) -> None:
    with open(PLAN_FILE, "w", encoding="utf-8") as f:
        json.dump(plan, f, ensure_ascii=False, indent=2)

def now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def cmd_hash(cmd: str, artifact: str = "-") -> str:
    return hashlib.sha256((cmd.strip() + "|" + (artifact or "-").strip()).encode()).hexdigest()

def deps_done(plan: Dict[str, Any], t: Dict[str, Any]) -> bool:
    need = set(t.get("deps") or [])
    if not need:
        return True
    by_id = {x.get("id"): x for x in plan.get("todos", []) if isinstance(x, dict) and "id" in x}
    return all(by_id.get(d, {}).get("status") == "done" for d in need)

def when_ready(t: Dict[str, Any], state_provider: Callable[[], Dict[str, Any]]) -> bool:
    conds = t.get("when") or []
    if not conds:
        return True
    st = state_provider() or {}
    text = json.dumps(st, ensure_ascii=False)
    for c in conds:
        if c.get("match") and c["match"] not in text:
            return False
    return True

def success_match(rule: str, out_text: str) -> bool:
    if not rule:
        return bool(out_text.strip())
    if rule.startswith("re:"):
        return re.search(rule[3:], out_text, re.M) is not None
    return rule in out_text

def default_todo(t: Dict[str, Any]) -> Dict[str, Any]:
    t.setdefault("success", "")
    t.setdefault("artifact", "-")
    t.setdefault("status", "pending")
    t.setdefault("retries", 0)
    t.setdefault("max_retries", 1)
    t.setdefault("deps", [])
    t.setdefault("when", [])
    t.setdefault("created_at", now())
    t.setdefault("last_error", "")
    return t

def write_artifact_reg(plan: Dict[str, Any], path: str, content: str) -> None:
    if not path or path == "-":
        return
    if re.search(r'\.(log|txt|md|json|yaml)$', path):  
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
        size = len(content)
    else:  
        size = os.path.getsize(path) if os.path.exists(path) else 0
    plan.setdefault("artifacts", {})[path] = {"size": size, "ts": now()}


def run_ready(
    state_provider: Callable[[], Dict[str, Any]] = lambda: {},
    max_parallel: int = 1,
    timeout: int = 180
) -> Dict[str, int]:
    plan = load_plan()
    todos = plan.get("todos", [])
    seen = set(plan.get("seen_cmd_hashes", []))

    for t in todos:
        default_todo(t)

    ready = [
        t for t in todos
        if ("cmd" in t)
        and t.get("status", "pending") == "pending"
        and deps_done(plan, t)
        and when_ready(t, state_provider)
        and cmd_hash(t["cmd"], t.get("artifact", "-")) not in seen
    ]
    ready.sort(key=lambda x: (x.get("created_at", ""), x.get("id", "")))

    summary = {"done": 0, "pending": 0, "failed": 0, "skipped": 0}

    for t in ready[:max_parallel]:
        cmd = t["cmd"]
        art = t.get("artifact", "-")
        h = cmd_hash(cmd, art)

        if not CMD_ALLOWLIST.search(cmd):
            t["status"] = "skipped"
            t["last_error"] = "blocked_by_allowlist"
            save_plan(plan)
            summary["skipped"] += 1
            continue

        t["status"] = "running"
        save_plan(plan)

        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            out = (proc.stdout or "") + ("\n" + (proc.stderr or ""))
            ok = (proc.returncode == 0) and success_match(t.get("success", ""), out)

            write_artifact_reg(plan, art, out)

            run_id = f"R-{len(plan.get('runs', [])) + 1:04d}"
            plan.setdefault("runs", []).append({
                "id": run_id,
                "todo_id": t.get("id", ""),
                "cmd": cmd,
                "ok": ok,
                "ts": now(),
                **({"artifact": art} if art and art != "-" else {})
            })

            if ok:
                t["status"] = "done"
                plan.setdefault("seen_cmd_hashes", []).append(h)
                summary["done"] += 1
            else:
                t["retries"] = int(t.get("retries", 0)) + 1
                if t["retries"] <= int(t.get("max_retries", 1)):
                    t["status"] = "pending"
                    t["last_error"] = out.strip()[:4000]
                else:
                    t["status"] = "failed"
                    t["last_error"] = out.strip()[:4000]
                    summary["failed"] += 1

        except subprocess.TimeoutExpired:
            t["status"] = "failed"
            t["last_error"] = f"timeout({timeout}s)"
            summary["failed"] += 1

        save_plan(plan)

    summary["pending"] = sum(1 for t in plan.get("todos", []) if t.get("status") == "pending")
    save_plan(plan)
    return summary

def add_todos_from_actions(actions_json: Dict[str, Any]) -> List[str]:
    plan = load_plan()
    todos = plan.setdefault("todos", [])
    seen = set(plan.get("seen_cmd_hashes", []))

    existing = {
        cmd_hash(x.get("cmd",""), x.get("artifact","-"))
        for x in todos if isinstance(x, dict) and "cmd" in x
    }

    added: List[str] = []
    for act in (actions_json or {}).get("actions", []):
        cmd = (act.get("cmd") or "").strip()
        if not cmd:
            continue
        art = (act.get("artifact") or "-").strip()
        h = cmd_hash(cmd, art)

        if h in seen or h in existing:
            continue

        tid = f"T-{len(todos)+1:04d}"
        todo = {"id": tid, "cmd": cmd}
        if act.get("success"):  todo["success"]  = act["success"].strip()
        if act.get("artifact"): todo["artifact"] = art
        if act.get("deps"):     todo["deps"]     = list(act["deps"])
        if act.get("when"):     todo["when"]     = list(act["when"])

        todos.append(default_todo(todo))
        added.append(tid)
        existing.add(h)

    save_plan(plan)
    return added

add_todos_from_actions({"actions":[{"name":"echo","cmd":"printf 'ok\\n'","success":"ok","artifact":"out.txt"}]})
run_ready()