# AI-Powered Adaptive SSH Honeypot

A software-only deception system. It exposes a fake SSH server that accepts any login, lets an
LLM generate realistic terminal output for every attacker command, logs everything, and maps
attacker behaviour to MITRE ATT&CK techniques.

## Why
Classic honeypots use fixed replies that attackers fingerprint quickly. Using an LLM makes the
fake server adapt to any command, keeping attackers engaged longer and producing richer threat data.

## Architecture
```
Attacker --SSH--> honeypot.py (asyncssh) --> llm.py (LLM generates output) --> reply to attacker
                       |
                       +--> logs/sessions.jsonl --> attack_map.py (MITRE ATT&CK) --> analyze.py / dashboard
```

## Run
```
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...        # optional; without it, canned fallback replies are used
python honeypot.py                  # listens on :2222
ssh anyuser@localhost -p 2222       # any password works
python analyze.py                   # attacker summary
```

## Safety
Runs only as a fake shell: no command is ever executed on the host. Run on localhost or an isolated VM/container.

## Roadmap
- [x] SSH listener, any-login, full command logging
- [x] LLM response engine with fallback
- [x] MITRE ATT&CK mapping
- [ ] Per-session fake filesystem for consistency
- [ ] Web dashboard (live sessions, charts)
- [ ] Docker packaging + attacker bot/human classifier
