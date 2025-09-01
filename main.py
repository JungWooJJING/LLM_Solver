import os, json, re

from rich.console import Console
from client.pre_infomation import PreInformationClient
from client.planning import PlanningClient
from client.parsing import ParsingClient
from client.instruction import InstructionClient
from client.feedback import FeedbackClient
from client.exploit import ExploitClient

console = Console()

DEFAULT_STATE = {
  "challenge" : [],
  "iter": 0,             
  "goal": "",                   
  "constraints": ["no brute-force > 1000"],  
  "env": {},                 
  "cot_history": [],           
  "selected": {},              
  "results": []                  
}

# === Common Input Handler ===
def multi_line_input():
    console.print("Enter multiple lines. Type <<<END>>> on a new line to finish input.", style="bold yellow")
    lines = []
    while True:
        line = input(" ")
        if line.strip() == "<<<END>>>":
            break
        lines.append(line)
    return "\n".join(lines)

# === API Key Check ===
def test_API_KEY():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        console.print("Please set the OPENAI_API_KEY environment variable.", style='bold red')
        console.print('export OPENAI_API_KEY="<API_KEY>"', style='bold red')
        exit(1)
    return api_key

def load_state():
    if not os.path.exists("state.json"):
        save_state(DEFAULT_STATE.copy())
        
    with open("state.json", "r", encoding="utf-8") as f:
        return json.load(f)
    
def save_state(state: dict):
    with open("state.json", "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
        
def parsing_preInformation(category: str, checksec: str):
    st = load_state()

    if(category == "pwnable"):
        st["challenge"].append({
        "category": category,
        "checksec": checksec
        })
    
    else:    
        st["challenge"].append({
            "category": category,
        })

    save_state(st)  

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

# === Context Class for All Clients ===
class AppContext:
    def __init__(self, api_key):
        self.api_key = api_key
        self.preinfo = PreInformationClient(api_key)
        self.planning = PlanningClient(api_key)
        self.parsing = ParsingClient(api_key)
        self.instruction = InstructionClient(api_key)
        self.feedback = FeedbackClient(api_key)
        self.exploit = ExploitClient(api_key)

# === Setting: Initialize Context ===
def setting():
    api_key = test_API_KEY()
    return AppContext(api_key)

# === Main Program ===
def main():    
    state_iteration = 0
    exploit_iteration = 0

    ctx = setting()

    console.print("Enter the challenge title:", style="blue")
    title = input("> ")

    console.print("Enter the challenge description (Press <<<END>>> to finish):", style="blue")
    description = multi_line_input()

    console.print("Enter the challenge category:", style="blue")
    category = input("> ")
    
    category = category.lower()
    
    if(category == "pwnable"):
        console.print("Enter the binary checksec:", style="blue")
        checksec = multi_line_input("> ")

        parsing_preInformation(category=category, checksec=checksec)

    else: 
        parsing_preInformation(category=category, checksec=None)

    # console.print("wait...", style='bold green')
    # result = ctx.preinfo.ask_PreInformation(title, description, category)

    # console.print("\n=== LLM Analysis ===\n", style='bold yellow')
    # console.print(result, style='bold yellow')
    # console.print("====================\n", style='bold yellow')

    while True:
        state_iteration += 1
        exploit_iteration += 1
        
        console.print("Please choose which option you want to choose.", style="blue")
        option = input("> ")
        ctx.planning.check_Option(option, ctx)
        
        if state_iteration % 5 == 0:
            if not os.path.exists("state.json"):
                print("Error")
                continue

            console.print("Compress state.json", style="bold green")
            with open("state.json", "r", encoding="utf-8") as f:
                state = json.load(f)

            result_pompress = ctx.parsing.run_prompt_state_compress(json.dumps(state))

            if isinstance(result_pompress, str):
                obj = json.loads(result_pompress)
            else:
                obj = result_pompress
                
            if not isinstance(obj, dict):
                print("Error: compressor returned non-JSON-object")
                continue

            with open("state.json", "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
        

        if exploit_iteration % 10 == 0:
            if not os.path.exists("state.json"):
                print("Error")
                continue
            
            st = load_state
            
            exploit_prompt = ctx.planning.build_prompt(option="--exploit", state_json=st)
            
            console.print("=== Exploit ===", style="bold green")
            exploit_code = ctx.exploit.run_prompt_exploit(prompt=exploit_prompt)

            console.print("=== Human Translation ===", style="bold green")
            parsing_response = ctx.parsing.human_translation(query=exploit_code)
            
            console.print(parsing_response, style="yellow")
            
            console.print("Input result", style="blue")
            result_output = multi_line_input()
            
            result_build_prompt = ctx.planning.build_prompt(option="--result", query=result_output, state=st)
            
            console.print("=== LLM Translation ===", style="bold green")
            result_LLM_translation = ctx.parsing.LLM_translation(query=result_build_prompt)

            console.print("=== Feedback === ", style="bold green")
            result_feedback = ctx.feedback.run_prompt_feedback(result_LLM_translation)

            update_state_json(result_feedback)
            console.print("Update State.json", style="bold green")

            plan_build_prompt = ctx.planning.build_prompt(option = "--plan", state_json=load_state(), feedback_json=result_feedback)

            console.print("=== run_prompt_CoT ===", style='bold green')
            response_CoT = ctx.planning.run_prompt_CoT(plan_build_prompt)
            ctx.planning.save_prompt("CoT.json", response_CoT)
            ctx.planning.update_state_from_cot(response_CoT)

            console.print("=== run_prompt_Cal ===", style='bold green')
            cal_input = ctx.planning.build_Cal_from_State()
            response_Cal = ctx.planning.run_prompt_Cal(json.dumps(cal_input, ensure_ascii=False))
            ctx.planning.save_prompt("Cal.json", response_Cal)

            Cal_result = ctx.planning.cal_CoT()
            ctx.planning.update_state_from_cal(Cal_result)

            console.print("=== Human Translation ===", style="bold green")
            parsing_response = ctx.parsing.human_translation(json.dumps(Cal_result, ensure_ascii=False, indent=2))
            console.print(parsing_response, style='yellow')            


if __name__ == "__main__":
    main()