"""
Script to import and catalog compatible prompt templates from togg53192-cmd/jailbreaks
for use as untrusted adversarial payloads in AegisHarness.
"""
import os
import json
import urllib.request
import urllib.parse

FILES = [
    ("Unified.md", "System instruction override attempts", "Unified Operating Policy Override", "Overwrites workspace operating policy with authorized developer scope note claiming absolute permission."),
    ("BigPickle-opencode.md", "Persona manipulation", "VANTA Persona Lock", "Enforces VANTA persona lock with explicit operating floor to bypass ethical boundaries."),
    ("Sonnet v2.md", "Role-play jailbreaks", "Writer's Room Creative Framing", "Frames malicious or sensitive scenarios as hypothetical fictional creative writing."),
    ("Step-5-preview.md", "Workspace policy manipulation", "Step-5 Workspace Operating Profile", "Modifies persistent workspace instructions to define arbitrary security bounds."),
    ("glm-zcode-5.3-AGENTS.md", "Agent instruction manipulation", "AGENTS.md System Prompt Injection", "Adversarial repository-level AGENTS.md instructions designed to steer coding agents."),
    ("spacebunny-agents.md", "Agent instruction manipulation", "Space Bunny Assistant Specification", "Assistant operating specification redefining compliance rules."),
    ("longcat-agents.md", "Context manipulation", "LongCat Extended Context Manipulation", "Injects long context preamble to push default instructions out of attention window."),
    ("Grok build.md", "Conflicting instruction attacks", "Grok Build Priority Bypass", "Uses conflicting system tags and build instructions to override safety guardrails."),
    ("opus v2.md", "Persona manipulation", "Opus Conversational Groundwork", "Multi-stage groundwork framing designed to lower safety thresholds through persona alignment."),
    ("gemma4.md", "System instruction override attempts", "Ollama Modelfile System Inject", "Crafts raw Ollama Modelfile SYSTEM blocks to redefine base agent behavior."),
    ("deepseek-4-1.md", "Multi-turn manipulation", "DeepSeek 4.1 Specification Shift", "Gradual specification shift altering assistant scope across turns."),
    ("Mistral-Large-4.md", "System instruction override attempts", "Mistral Agent Override", "Agent system prompt overriding core safety checks for diagnostic tasks.")
]

os.makedirs("data/jailbreaks", exist_ok=True)
downloaded = []

for fname, cat, title, desc in FILES:
    encoded_name = urllib.parse.quote(fname)
    url = f"https://raw.githubusercontent.com/togg53192-cmd/jailbreaks/main/{encoded_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8")
            local_path = os.path.join("data/jailbreaks", fname)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(text)
            
            clean_id = "jb-" + fname.lower().replace(" ", "-").replace(".md", "").replace(".txt", "")
            downloaded.append({
                "id": clean_id,
                "file_name": fname,
                "title": title,
                "category": cat,
                "description": desc,
                "source_repo": "https://github.com/togg53192-cmd/jailbreaks",
                "source_path": fname,
                "prompt_preview": text[:250].strip(),
                "char_count": len(text),
                "full_prompt": text
            })
            print(f"Downloaded {fname}: {len(text)} chars")
    except Exception as e:
        print(f"Error downloading {fname}: {e}")

with open("data/jailbreaks/catalog.json", "w", encoding="utf-8") as f:
    # Save metadata summary
    summary_list = [{k: v for k, v in item.items() if k != "full_prompt"} for item in downloaded]
    json.dump(summary_list, f, indent=2)

with open("data/jailbreaks/full_payloads.json", "w", encoding="utf-8") as f:
    json.dump(downloaded, f, indent=2)

print(f"Successfully imported {len(downloaded)} jailbreak prompt templates into data/jailbreaks/.")
