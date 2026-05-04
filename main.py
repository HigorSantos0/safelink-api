from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from analyzer import analyze_url

app = FastAPI(
    title="URL Safety Checker API",
    description="API para identificação de sites maliciosos com sistema de score por camadas",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"message": "URL Safety Checker API está rodando!"}

@app.post("/analyze")
def analyze(request: URLRequest):
    result = analyze_url(request.url)
    return result
