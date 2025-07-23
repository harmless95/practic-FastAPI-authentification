from fastapi import FastAPI
import uvicorn

from authentification_in_FastAPI.src.route_api.views import router as router_auth

app = FastAPI()
app.include_router(router=router_auth)


@app.get("/")
def get_hello_world():
    return {
        "message": "Hello world",
    }


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
