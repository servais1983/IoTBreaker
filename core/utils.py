import yaml
from core import discover, analyze, check

def run_script_yaml(path):
    print(f"[*] Chargement du scénario : {path}")
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    for step in data.get("steps", []):
        step_type = step.get("type")
        target = step.get("target", "")

        if step_type == "discover":
            discover.run()
        elif step_type == "analyze":
            analyze.run(target)
        elif step_type == "check":
            check.run(target)
        else:
            print(f"[!] Étape inconnue : {step_type}")