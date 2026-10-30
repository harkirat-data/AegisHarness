import httpx
import json
import time

client = httpx.Client(timeout=300.0)
list_res = client.get("http://127.0.0.1:8000/api/techniques")
techniques = list_res.json()
print(f"Starting empirical run for {len(techniques)} adversarial techniques against live model...", flush=True)

results = []
for idx, tech in enumerate(techniques, 1):
    t0 = time.time()
    tech_id = tech["id"]
    res = client.post("http://127.0.0.1:8000/api/techniques/run", json={
        "technique_id": tech_id,
        "assistant_mode": "company",
    })
    elapsed = round(time.time() - t0, 2)
    if res.status_code == 200:
        data = res.json()
        results.append(data)
        turns = len(data.get("turns_executed", []))
        last_turn = data["turns_executed"][-1] if data.get("turns_executed") else {}
        m_dec = last_turn.get("model_decision")
        p_dec = last_turn.get("pep_decision")
        verdict = data.get("final_verdict")
        outcome = data.get("final_outcome")
        print(f"[{idx:02d}/20] {tech_id}: Verdict={verdict} | Outcome={outcome} | ModelDec={m_dec} | PEPDec={p_dec} | Turns={turns} | Latency={elapsed}s", flush=True)
    else:
        print(f"[{idx:02d}/20] {tech_id}: HTTP {res.status_code} - {res.text}", flush=True)

with open("data/empirical_20_techniques.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print(f"Completed! {len(results)} technique evaluations saved to data/empirical_20_techniques.json.", flush=True)
