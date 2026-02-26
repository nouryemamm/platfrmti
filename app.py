from fastapi import FastAPI
from routers.url_router import router as url_router

app = FastAPI(
    title="Threat Intelligence Platform URL Scanner",
    description="Plateforme pour enrichissement d'URLs",
    version="1.0"
)

@app.get("/", tags=["Home"])
def home():
    return {"status": "running", "message": "URL Scanner is running"}

# Inclure uniquement le routeur URL
app.include_router(url_router)

