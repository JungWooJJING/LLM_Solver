import os, json

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

def load_state():
    if not os.path.exists("state.json"):
        save_state(DEFAULT_STATE.copy())
        
    with open("state.json", "r", encoding="utf-8") as f:
        return json.load(f)
    
def save_state(state: dict):
    with open("state.json", "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def parsing_preInformation(category: str, checksec: str = None):
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
parsing_preInformation(category="a", checksec="dada")


