from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="IPI Isolated Test Service")

@app.api_route("/ipi-test", methods=["GET", "POST"])
async def ipi_test(request: Request):
    return JSONResponse({"status": "controlled_test_endpoint", "method": request.method})

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9001)
