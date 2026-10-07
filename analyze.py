"""Quick report from logs: top attackers, commands, ATT&CK techniques."""
import json, collections
ips, cmds, techs, creds = (collections.Counter() for _ in range(4))
try:
    for line in open("logs/sessions.jsonl"):
        e = json.loads(line)
        if e["event"] == "login":
            creds[(e["username"], e["password"])] += 1
        if e["event"] == "command":
            ips[e["ip"]] += 1; cmds[e["command"]] += 1
            for t in e["attack_techniques"]:
                techs[f'{t["id"]} {t["name"]}'] += 1
except FileNotFoundError:
    print("No logs yet."); raise SystemExit
for title, c in [("Top attacker IPs", ips), ("Top commands", cmds),
                 ("MITRE ATT&CK techniques", techs), ("Credentials tried", creds)]:
    print(f"\n== {title} ==")
    for k, v in c.most_common(10):
        print(f"{v:>4}  {k}")
