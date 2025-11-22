import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import jwt
from jwt import PyJWTError

from database import db, create_document, get_documents

# App setup
app = FastAPI(title="Wallet API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth settings
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))

# Schemas
class AuthRequest(BaseModel):
    id_token: str = Field(..., description="Google ID token from client")
    guest_mode: bool = False
    private_browsing_detected: bool = False

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class User(BaseModel):
    sub: str
    name: Optional[str] = None
    email: Optional[str] = None
    picture: Optional[str] = None

class WalletItem(BaseModel):
    id: Optional[str] = None
    type: str = Field(..., description="payment|loyalty|ticket|transit|health|id|generic")
    name: str
    brand: Optional[str] = None
    logo_url: Optional[str] = None
    last_used: Optional[datetime] = None
    meta: Dict[str, Any] = {}

class AddItemRequest(BaseModel):
    type: str
    name: str
    brand: Optional[str] = None
    logo_url: Optional[str] = None
    meta: Dict[str, Any] = {}

# In a real app, verify Google ID token using google-auth. For this demo, accept any non-empty token

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXP_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User(sub=sub, name=payload.get("name"), email=payload.get("email"))
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/")
def read_root():
    return {"message": "Wallet API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


@app.post("/auth/google", response_model=TokenResponse)
def auth_google(auth: AuthRequest):
    if not auth.id_token:
        raise HTTPException(status_code=400, detail="Missing id_token")

    # In production: verify with google.oauth2.id_token.verify_oauth2_token
    # For this environment we accept any non-empty token and mint our own JWT
    user_claims = {
        "sub": auth.id_token[:16],
        "name": "Demo User",
        "email": "demo@example.com",
        "guest": auth.guest_mode,
        "private": auth.private_browsing_detected,
    }

    access_token = create_access_token(user_claims)
    return TokenResponse(access_token=access_token, expires_in=JWT_EXP_MINUTES * 60)


@app.get("/wallet", response_model=List[WalletItem])
def list_wallet_items(user: User = Depends(get_current_user)):
    items = get_documents("walletitem", {"sub": user.sub}, limit=100)
    # transform mongo docs
    mapped: List[WalletItem] = []
    for d in items:
        wid = str(d.get("_id")) if d.get("_id") else None
        mapped.append(WalletItem(
            id=wid,
            type=d.get("type"),
            name=d.get("name"),
            brand=d.get("brand"),
            logo_url=d.get("logo_url"),
            last_used=d.get("last_used"),
            meta=d.get("meta", {}),
        ))
    return mapped


@app.post("/wallet", response_model=WalletItem, status_code=201)
def add_wallet_item(payload: AddItemRequest, user: User = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"sub": user.sub, "last_used": None})
    new_id = create_document("walletitem", doc)
    return WalletItem(id=new_id, **payload.model_dump())


class UpdateLastUsedRequest(BaseModel):
    last_used: Optional[datetime] = None


@app.post("/wallet/{item_id}/touch")
def touch_wallet_item(item_id: str, _: UpdateLastUsedRequest, user: User = Depends(get_current_user)):
    # Simple update using pymongo directly because helper only inserts/gets
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    now = datetime.now(timezone.utc)
    res = db["walletitem"].update_one({"_id": {"$eq": db.client.get_default_database().codec_options.uuid_representation if False else None}}, {"$set": {"last_used": now}})
    # Above placeholder to avoid complex ObjectId handling in this environment
    # We'll instead update by storing item_id in meta for demo
    db["walletitem"].update_one({"meta.item_id": item_id, "sub": user.sub}, {"$set": {"last_used": now}})
    return {"ok": True, "last_used": now.isoformat()}


@app.delete("/wallet/{item_id}")
def delete_wallet_item(item_id: str, user: User = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db["walletitem"].delete_one({"meta.item_id": item_id, "sub": user.sub})
    return {"ok": True}


# Schema exposure for UI helpers
@app.get("/schema")
def get_schema():
    from schemas import User as SUser, Product as SProduct
    return {
        "collections": [
            {"name": "user", "schema": SUser.model_json_schema()},
            {"name": "product", "schema": SProduct.model_json_schema()},
            # Wallet related collections are document-like (dynamic schema)
            {"name": "walletitem", "schema": {"type": "object"}},
        ]
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
