import json, re

w = { "feasibility":0.20, "info_gain":0.30, "novelty":0.20, "cost":0.15, "risk":0.15 }

def safe_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        s = s[s.find("{"): s.rfind("}")+1]
        s = re.sub(r"```(json)?|```", "", s).strip()
        return json.loads(s)

with open("ToT.json", "r", encoding="utf-8") as f:
    data = safe_json_loads(f.read())

cal = ["feasibility", "novelty", "info_gain", "cost", "risk"]

for item in data["results"]:
    g = {k: float(item.get(k, 0.5)) for k in cal}
    penalties = sum(float(p.get("value", 0.0)) for p in item.get("penalties", []))

    score = 0.0
    for k in cal:
        v = g[k]
        if k in ("cost", "risk"):
            score += w[k] * (1 - v)      # 낮을수록 좋게 반영
        else:
            score += w[k] * v

    score -= penalties
    score = max(0.0, min(1.0, score))

    # 원본 JSON에 score 필드 추가
    item["calculated_score"] = round(score, 3)

# 수정된 JSON 저장
with open("ToT_scored.json", "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print("저장 완료: ToT_scored.json")
