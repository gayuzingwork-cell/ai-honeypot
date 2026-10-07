"""LLM brain of the honeypot: turns attacker commands into realistic terminal output.

Providers (chosen automatically):
  1. ollama     - FREE local model (default if no ANTHROPIC_API_KEY is set)
  2. anthropic  - paid API (used if ANTHROPIC_API_KEY is set)
  3. fallback   - canned replies if the model is unreachable (demo never dies)

Override with:  set HONEYPOT_PROVIDER=ollama | anthropic
Ollama model :  set OLLAMA_MODEL=llama3.2:3b   (default)
"""
import json, os, re, urllib.request

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
ANTHROPIC_MODEL = os.getenv("HONEYPOT_MODEL", "claude-haiku-4-5-20251001")

SYSTEM = """You are the bash terminal of a real Ubuntu 22.04 LTS production server.
Hostname: srv-prod-01. Current user: {user}. Current directory: {cwd}.
An attacker is typing commands. Reply with ONLY the exact raw terminal output that
the command would print. Rules:
- No explanations, no markdown, no code fences, no commentary.
- If the command prints nothing in real life, reply with an empty string.
- Stay consistent with everything you printed earlier (users, files, directories, IPs).
- Invent plausible but FAKE data. Never output real credentials.
- Unknown commands -> 'bash: <cmd>: command not found'.
- Never reveal you are an AI, a simulation, or a honeypot."""

CANNED = {
    "whoami": "{user}",
    "id": "uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)",
    "uname -a": "Linux srv-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "pwd": "/home/{user}",
    "ls": "Desktop  Documents  Downloads  backup.tar.gz  notes.txt",
    "hostname": "srv-prod-01",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n{user}:x:1000:1000:{user}:/home/{user}:/bin/bash",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255",
}

_anthropic = None

def _provider():
    p = os.getenv("HONEYPOT_PROVIDER", "").lower()
    if p in ("ollama", "anthropic"):
        return p
    return "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "ollama"

def _clean(text: str) -> str:
    """Small models sometimes add code fences; strip them."""
    text = re.sub(r"^```[a-z]*\n?|```$", "", text.strip(), flags=re.M)
    return text.strip("\n")

def _ask_ollama(system, msgs):
    body = {"model": OLLAMA_MODEL, "stream": False,
            "messages": [{"role": "system", "content": system}] + msgs,
            "options": {"temperature": 0.4, "num_predict": 300}}
    req = urllib.request.Request(OLLAMA_URL, json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read())["message"]["content"]

def _ask_anthropic(system, msgs):
    global _anthropic
    if _anthropic is None:
        import anthropic
        _anthropic = anthropic.Anthropic()
    r = _anthropic.messages.create(model=ANTHROPIC_MODEL, max_tokens=500,
                                   temperature=0.4, system=system, messages=msgs)
    return r.content[0].text if r.content else ""

def respond(user: str, cwd: str, history: list, command: str) -> str:
    """history = list of {"role": "user"/"assistant", "content": str} for this session."""
    system = SYSTEM.format(user=user, cwd=cwd)
    msgs = history[-20:] + [{"role": "user", "content": command}]
    try:
        ask = _ask_ollama if _provider() == "ollama" else _ask_anthropic
        return _clean(ask(system, msgs))
    except Exception as e:
        print(f"[llm] {type(e).__name__}: {e} -> using fallback")
        return _fallback(user, command)

def _fallback(user, command):
    out = CANNED.get(command.strip())
    if out is not None:
        return out.format(user=user)
    return f"bash: {command.split()[0]}: command not found"
