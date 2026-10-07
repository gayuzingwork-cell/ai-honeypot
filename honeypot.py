"""AI-Powered Adaptive SSH Honeypot - main server."""
import asyncio, asyncssh, json, os, uuid
from datetime import datetime, timezone
from llm import respond
from attack_map import map_command

PORT = int(os.getenv("HONEYPOT_PORT", "2222"))
HOST_KEY = "host_key"
LOG_FILE = "logs/sessions.jsonl"
BANNER = "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"

def log(event: dict):
    event["ts"] = datetime.now(timezone.utc).isoformat()
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[{event['event']}] {event.get('ip','')} {event.get('command', event.get('username',''))}")

class Server(asyncssh.SSHServer):
    def connection_made(self, conn):
        self.ip = conn.get_extra_info("peername")[0]
        log({"event": "connection", "ip": self.ip})
    def connection_lost(self, exc):
        log({"event": "disconnect", "ip": self.ip})
    def begin_auth(self, username):
        return True
    def password_auth_supported(self):
        return True
    def validate_password(self, username, password):
        # Accept everything: attacker thinks they "cracked" the password.
        log({"event": "login", "ip": self.ip, "username": username, "password": password})
        return True

async def run_command(sid, ip, user, cwd, history, cmd):
    out = await asyncio.to_thread(respond, user, cwd, history, cmd)
    techniques = map_command(cmd)
    log({"event": "command", "session": sid, "ip": ip, "username": user,
         "command": cmd, "output": out, "attack_techniques": techniques})
    history.append({"role": "user", "content": cmd})
    history.append({"role": "assistant", "content": out or "(no output)"})
    return out

async def handle_client(process):
    user = process.get_extra_info("username")
    ip = process.get_extra_info("peername")[0]
    sid, cwd, history = uuid.uuid4().hex[:8], f"/home/{user}", []
    # One-shot: ssh user@host "command"
    if process.command:
        out = await run_command(sid, ip, user, cwd, history, process.command)
        process.stdout.write(out + "\n")
        process.exit(0)
        return
    process.stdout.write(BANNER)
    try:
        while not process.stdin.at_eof():
            process.stdout.write(f"{user}@srv-prod-01:~$ ")
            line = await process.stdin.readline()
            cmd = line.strip()
            if not cmd:
                continue
            if cmd in ("exit", "logout"):
                break
            out = await run_command(sid, ip, user, cwd, history, cmd)
            if out:
                process.stdout.write(out.rstrip("\n") + "\n")
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
        pass
    process.exit(0)

async def main():
    if not os.path.exists(HOST_KEY):
        asyncssh.generate_private_key("ssh-rsa", comment="honeypot").write_private_key(HOST_KEY)
    await asyncssh.create_server(Server, "", PORT, server_host_keys=[HOST_KEY],
                                 process_factory=handle_client, line_editor=True)
    print(f"Honeypot listening on port {PORT} ...")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
