from fastapi import FastAPI

from src.users.router import router as router_users


app = FastAPI()


app.include_router(router_users)
