"""FastAPI application entrypoint for secure chat server."""
import uvicorn
from fastapi import FastAPI

from . import auth, messages, users
from .database import Base, engine
from .logging_config import configure_logging

logger = configure_logging()

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Chat Server", version="1.0.0")
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(messages.router)


@app.get("/")
def root():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("secure_chat.server.main:app", host="0.0.0.0", port=8000, reload=False)
