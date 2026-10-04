from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(
    title="FinTech Payments API (Demo Target)",
    version="v2.4.0",
    description="Intentionally vulnerable test API for defensive security scanning verification.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Simulated in-memory database
USERS_DB = {
    1: {"id": 1, "name": "Alice Johnson", "email": "alice@fintech.example", "role": "admin", "balance": 15420.50},
    2: {"id": 2, "name": "Bob Martinez", "email": "bob@fintech.example", "role": "customer", "balance": 340.00},
    3: {"id": 3, "name": "Charlie Davis", "email": "charlie@fintech.example", "role": "customer", "balance": 2800.75},
}

ORDERS_DB = {
    101: {"order_id": 101, "user_id": 1, "amount": 499.99, "currency": "USD", "status": "COMPLETED"},
    102: {"order_id": 102, "user_id": 2, "amount": 29.50, "currency": "USD", "status": "PENDING"},
}


# 1. Custom Weak CORS Middleware (Intentionally vulnerable: dynamic reflection of arbitrary origin with credentials)
@app.middleware("http")
async def weak_cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin")
    
    if request.method == "OPTIONS":
        response = Response(status_code=200)
    else:
        response = await call_next(request)
        
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, TRACE"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
    
    # Notice: Intentionally omitted Strict-Transport-Security, X-Content-Type-Options
    response.headers["Server"] = "FinTech-PaymentGateway/2.4.0-DEBUG"
    response.headers["X-Debug-Trace"] = "TraceID-8849-Enabled"
    return response


@app.get("/")
def root():
    return {"service": "FinTech Payments API", "status": "operational", "version": "v2.4.0"}


@app.get("/api/v1/users")
def list_users():
    return {"users": list(USERS_DB.values()), "total": len(USERS_DB)}


@app.get("/api/v1/users/{user_id}")
def get_user_by_id(user_id: int):
    user = USERS_DB.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")
    return user


@app.get("/api/v1/orders/{order_id}")
def get_order_by_id(order_id: int):
    order = ORDERS_DB.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    return order


@app.post("/api/v1/orders")
async def create_order(request: Request):
    data = await request.json()
    new_id = max(ORDERS_DB.keys()) + 1
    order = {
        "order_id": new_id,
        "user_id": data.get("user_id", 1),
        "amount": data.get("amount", 0.0),
        "currency": data.get("currency", "USD"),
        "status": "PROCESSED",
    }
    ORDERS_DB[new_id] = order
    return order


# 2. Intentionally vulnerable unauthenticated debug endpoint (Shadow API)
@app.get("/api/v1/admin/debug")
def internal_debug():
    return {
        "debug_mode": True,
        "environment": "staging-sandbox",
        "internal_ip": "10.0.4.15",
        "database": "postgresql://payments_app:Secr3tP@ss!@postgres-db.internal:5432/fintech_db",
        "loaded_modules": ["auth_v2", "stripe_gateway", "risk_engine"],
    }


# 3. Intentionally leaking stack trace on malformed input or error
@app.get("/api/v1/users/crash")
def simulate_stack_trace():
    # Intentionally raising unhandled exception with full python traceback
    raise ZeroDivisionError("division by zero in payment_processing_engine.py at line 142")


@app.post("/api/v1/echo")
async def echo_payload(request: Request):
    payload = await request.json()
    return {"received": payload, "echo_status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)
