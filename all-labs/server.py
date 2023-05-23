import hashlib
import functools
import motor.motor_asyncio
import requests
import uvicorn
from fastapi import FastAPI, UploadFile, Depends, HTTPException, Request
from pydantic import BaseModel
from prometheus_fastapi_instrumentator import Instrumentator
import redis
import json
import aio_pika
from aio_pika import DeliveryMode, ExchangeType
import aiohttp

app = FastAPI()
Instrumentator().instrument(app).expose(app)


class Time(BaseModel):
    a: int
    m: int


class Device(BaseModel):
    id: str
    os: str


class File(BaseModel):
    file_hash: str
    file_path: str
    time: Time


class Process(BaseModel):
    hash: str
    path: str
    pid: str


class Event(BaseModel):
    device: Device
    file: File
    last_access: Process


class Verdict(BaseModel):
    hash: str
    risk_level: int


class EventsResponse(BaseModel):
    file: Verdict
    process: Verdict


# conexiune mongo
@functools.lru_cache()
def mongo_data_collection():
    client = motor.motor_asyncio.AsyncIOMotorClient(
        "mongodb://root:example@mongo:27017"
    )
    db = client["data"]
    collection = db["verdicts"]
    return collection

async def rabbitmq_exchange():
    # Perform connection
    connection = await aio_pika.connect("amqp://user:bitnami@rabbitmq/")
    # Creating a channel
    channel = await connection.channel()
    return await channel.declare_exchange(
        "logs", ExchangeType.FANOUT,
    )


logs_exchange = None

redis_client = redis_client = redis.Redis(host='redis', port=6379, db=0)


@app.post("/events/")
async def events(event: Event, mongo_collection=Depends(mongo_data_collection)) -> EventsResponse:
    global logs_exchange
    if logs_exchange is None:
        logs_exchange = await rabbitmq_exchange()

    response = {}
    message = aio_pika.Message(
        event.json().encode(),
        delivery_mode=DeliveryMode.PERSISTENT,
    )
    await logs_exchange.publish(message, routing_key="test")

    for key, md5 in [('file', event.file.file_hash), ('process', event.last_access.hash)]:
        redis_result = redis_client.get(md5)
        if redis_result is None:
            data = await mongo_collection.find_one({"hash": md5})
            if data is not None:
                data.pop('_id', None)
                redis_client.set(md5, json.dumps(data))
        else:
            data = json.loads(redis_result)
        if data:
            risk_level = data['risk_level']
        else:
            risk_level = -1
        response[key] = Verdict(hash=md5, risk_level=risk_level)

    return EventsResponse(**response)


@app.post("/scan_file/")
async def upload(file: UploadFile, mongo_collection=Depends(mongo_data_collection)) -> Verdict:
    file_content = await file.read()

    url = "https://beta.nimbus.bitdefender.net/liga-ac-labs-cloud/blackbox-scanner/"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data={"file": file_content}) as resp:
            black_box_api_response = await resp.json()

    md5 = black_box_api_response['hash']
    risk_level = black_box_api_response['risk_level']
    verdict = Verdict(hash=md5, risk_level=risk_level)
    await mongo_collection.insert_one(verdict.dict())
    print(f'Item created, {verdict=}')
    return verdict


if __name__ == "__main__":
    uvicorn.run(app, port=8000, host="0.0.0.0")
