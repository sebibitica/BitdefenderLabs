from typing import Union

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()


class Item(BaseModel):
    nume: str
    descriere: str | None = None
    price: int
    taxx: int | None = None


@app.get("/lipire/{x}")
def chestie(x: int, y: str, z: str):
    return {"chestie": x, "y": y+z, "z": z+y}


@app.post("/postare")
def fct_post(item: Item):
    return item


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: str, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
