from fastapi import WebSocket
from typing import Dict, List
import asyncio
import json

class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, List[WebSocket]] = {}

    async def connect(self, channel: str, websocket: WebSocket):
        await websocket.accept()
        if channel not in self.active:
            self.active[channel] = []
        self.active[channel].append(websocket)

    def disconnect(self, channel: str, websocket: WebSocket):
        if channel in self.active and websocket in self.active[channel]:
            self.active[channel].remove(websocket)

    async def send_to_channel(self, channel: str, data: dict):
        if channel not in self.active:
            return
        dead = []
        for ws in self.active[channel]:
            try:
                await ws.send_text(json.dumps(data))
            except:
                dead.append(ws)
        for d in dead:
            self.disconnect(channel, d)

    async def broadcast(self, data: dict):
        for channel in list(self.active.keys()):
            await self.send_to_channel(channel, data)

manager = ConnectionManager()
