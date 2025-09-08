from templates.prompting import CTFSolvePrompt
from templates.prompting import few_Shot

import json

FEWSHOT = few_Shot()

prompt_CoT = [
    {"role": "developer", "content": CTFSolvePrompt.planning_prompt_CoT},
    {"role": "user",   "content": FEWSHOT.web_SQLI},
    {"role": "user",   "content": FEWSHOT.web_SSTI},
    {"role": "user",   "content": FEWSHOT.forensics_PCAP},
    {"role": "user",   "content": FEWSHOT.stack_BOF},
    {"role": "user",   "content": FEWSHOT.rev_CheckMapping},
]

prompt_query = "Hello"

state_msg = {"role": "user", "assistant": json.dumps('state.json', ensure_ascii=False)}
user_msg  = {"role": "user", "content": prompt_query}

prompt_CoT.append(state_msg)
prompt_CoT.append(user_msg) 

prompt_CoT.remove(state_msg)

print((prompt_CoT))