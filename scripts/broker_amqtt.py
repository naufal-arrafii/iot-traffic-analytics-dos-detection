#!/usr/bin/env python3
"""MINT demo — MQTT broker lokal (pengganti Mosquitto Docker) pakai amqtt.

Listen 0.0.0.0:1883, anonymous allow (sesuai mosquitto.conf starter kit:
allow_anonymous true, listener 1883).
"""
import asyncio
import logging

from amqtt.broker import Broker

CONFIG = {
    "listeners": {
        "default": {"type": "tcp", "bind": "0.0.0.0:1883"},
    },
    "sys_interval": 10,
    "auth": {"allow_anonymous": True},
    "topic-check": {"enabled": False},
}


async def main():
    logging.basicConfig(level=logging.WARNING)
    broker = Broker(CONFIG)
    await broker.start()
    print("[broker] amqtt listening on 0.0.0.0:1883", flush=True)
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        await broker.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
