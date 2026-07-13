
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import tempfile
import uuid
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Literal

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, status, UploadFile, File
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, ConfigDict,model_validator
from supabase import create_client, Client

supabase: Client = create_client(
    os.environ.get("SUPABASE_URL", ""),
    os.environ.get("SUPABASE_ANON_KEY", ""),
)


# ---------------- Config ----------------
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 12  # 12 hours


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


# ---------------- DB ----------------
mongo_url = os.environ["MONGO_URL"]
mongo_client = AsyncIOMotorClient(mongo_url)
db = mongo_client[os.environ["DB_NAME"]]



# ---------------- App ----------------
app = FastAPI(title="Rebild Client Portal API")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("rebild")


# ---------------- Helpers ----------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "type": "access",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def doc_clean(doc: dict) -> dict:
    if not doc:
        return doc
    doc.pop("_id", None)
    doc.pop("password_hash", None)
    return doc


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


async def require_client(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "client":
        raise HTTPException(status_code=403, detail="Client only")
    return user


def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=ACCESS_TOKEN_MINUTES * 60,
        path="/",
    )


# ---------------- Models ----------------
class LoginIn(BaseModel):
    email: EmailStr
    password: str

class ReorderItemsIn(BaseModel):
    item_ids: list[str]

class ReorderChecklistsIn(BaseModel):
    checklist_ids: List[str]

class CreateClientIn(BaseModel):
    name: str
    email: EmailStr
    company: Optional[str] = ""
    phone: Optional[str] = ""
    password: Optional[str] = None  # if not provided, generated
    services: List[str] = []  # service ids
    notes: Optional[str] = ""


class UpdateClientIn(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None
    services: Optional[List[str]] = None
    notes: Optional[str] = None
    active: Optional[bool] = None
    attachment_url: Optional[str] = None
    attachment_name: Optional[str] = None

class DocumentIn(BaseModel):
    title: str
    client_id: Optional[str] = None  # None = visible to all clients
    attachment_url: str
    attachment_name: str
    link_url: Optional[str] = None

class DocumentIn(BaseModel):
    title: str
    client_id: Optional[str] = None  # None = visible to all clients
    attachment_url: Optional[str] = None
    attachment_name: Optional[str] = None
    link_url: Optional[str] = None

    @model_validator(mode="after")
    def check_exactly_one_source(self):
        has_file = bool(self.attachment_url)
        has_link = bool(self.link_url)
        if has_file == has_link:  # both True or both False
            raise ValueError("Provide either a file attachment or a link, not both/neither")
        return self

class ResetPasswordIn(BaseModel):
    password: Optional[str] = None  # if not provided, generated


class ServiceIn(BaseModel):
    name: str
    description: str = ""
    icon: str = "Sparkles"  # lucide icon name
    color: str = "#F77418"


class AddOnIn(BaseModel):
    name: str
    description: str = ""
    price: float = 0.0
    icon: str = "Plus"


class InvoiceItem(BaseModel):
    description: str
    qty: int = 1
    unit_price: float = 0.0


class InvoiceIn(BaseModel):
    client_id: str
    items: List[InvoiceItem]
    tax: float = 0.0
    due_date: Optional[str] = None
    memo: Optional[str] = ""


class UpdateIn(BaseModel):
    title: str
    body: str
    client_id: Optional[str] = None
    category: str = "Update"
    attachment_url: Optional[str] = None
    attachment_name: Optional[str] = None


class TicketIn(BaseModel):
    subject: str
    message: str
    priority: Literal["low", "normal", "high"] = "normal"


class TicketMessageIn(BaseModel):
    message: str


class TicketStatusIn(BaseModel):
    status: Literal["open", "pending", "resolved", "closed"]


class AddOnRequestIn(BaseModel):
    addon_id: str
    note: Optional[str] = ""

class ClientProfileUpdate(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None

class ChecklistItemIn(BaseModel):
    text: str

class ChecklistIn(BaseModel):
    title: str
    client_id: Optional[str] = None  # None = visible to all clients
    items: List[ChecklistItemIn]

class ToggleItemIn(BaseModel):
    checked: bool


# ---------------- Auth Endpoints ----------------
@api.post("/auth/login")
async def login(payload: LoginIn, response: Response):
    email = payload.email.lower().strip()

    user = await db.users.find_one({"email": email})

    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.get("active") is False:
        raise HTTPException(status_code=403, detail="Account disabled")

    token = create_access_token(user["id"], user["email"], user["role"])

    login_time = now_iso()

    await db.users.update_one(
        {"id": user["id"]},
        {
            "$set": {
                "last_login": login_time
            }
        }
    )

    set_auth_cookie(response, token)

    safe = doc_clean(dict(user))
    safe["last_login"] = login_time

    updated_user = await db.users.find_one({"id": user["id"]})

    print(updated_user)

    return {"token": token, "user": safe}

@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


# ---------------- Checklists ----------------
@api.post("/admin/checklists")
async def create_checklist(payload: ChecklistIn, _: dict = Depends(require_admin)):
    items = [
        {"id": str(uuid.uuid4()), "text": it.text, "checked": False}
        for it in payload.items
    ]
    doc = {
        "id": str(uuid.uuid4()),
        "title": payload.title,
        "client_id": payload.client_id,
        "items": items,
        "created_at": now_iso(),
    }
    await db.checklists.insert_one(doc)
    doc.pop("_id", None)

    # notify
    if payload.client_id:
        recipients = [payload.client_id]
    else:
        clients = await db.users.find({"role": "client"}, {"id": 1, "_id": 0}).to_list(2000)
        recipients = [c["id"] for c in clients]
    if recipients:
        await db.notifications.insert_many(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": cid,
                    "title": f"New checklist: {payload.title}",
                    "body": f"{len(items)} item(s) to complete",
                    "type": "checklist",
                    "read": False,
                    "link": "/client/checklists",
                    "created_at": now_iso(),
                }
                for cid in recipients
            ]
        )
    return doc


@api.get("/admin/checklists")
async def admin_list_checklists(_: dict = Depends(require_admin)):
    items = await db.checklists.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return items


@api.delete("/admin/checklists/{checklist_id}")
async def delete_checklist(checklist_id: str, _: dict = Depends(require_admin)):
    await db.checklists.delete_one({"id": checklist_id})
    return {"ok": True}

@api.get("/client/checklists")
async def client_list_checklists(user: dict = Depends(require_client)):
    items = await db.checklists.find(
        {"$or": [{"client_id": user["id"]}, {"client_id": None}]}, {"_id": 0}
    ).sort([("order", 1), ("created_at", -1)]).to_list(1000)
    return items


@api.patch("/checklists/{checklist_id}/items/{item_id}")
async def toggle_checklist_item(
    checklist_id: str,
    item_id: str,
    payload: ToggleItemIn,
    user: dict = Depends(get_current_user),
):
    checklist = await db.checklists.find_one({"id": checklist_id})
    if not checklist:
        raise HTTPException(status_code=404, detail="Checklist not found")

    # Ownership check: clients can only toggle their own or global checklists
    if user.get("role") != "admin":
        if checklist.get("client_id") not in (None, user["id"]):
            raise HTTPException(status_code=403, detail="Not authorized for this checklist")

    actor = "Rebild Team" if user.get("role") == "admin" else user.get("name", "Client")

    update_fields = {"items.$.checked": payload.checked}
    if payload.checked:
        update_fields["items.$.checked_by"] = actor
    else:
        update_fields["items.$.checked_by"] = None

    result = await db.checklists.update_one(
        {"id": checklist_id, "items.id": item_id},
        {"$set": update_fields},
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Checklist item not found")

    return {"ok": True}

@api.patch("/checklists/reorder")
async def reorder_checklists(
    payload: ReorderChecklistsIn,
    user: dict = Depends(get_current_user),
):
    # Fetch only the checklists this user is allowed to reorder
    if user.get("role") == "admin":
        visible_cursor = db.checklists.find({}, {"id": 1, "_id": 0})
    else:
        visible_cursor = db.checklists.find(
            {"$or": [{"client_id": user["id"]}, {"client_id": None}]},
            {"id": 1, "_id": 0},
        )
    visible_ids = {c["id"] for c in await visible_cursor.to_list(2000)}

    # Validate the incoming ids are exactly the same set as the visible checklists
    if set(payload.checklist_ids) != visible_ids:
        raise HTTPException(status_code=400, detail="checklist_ids must match visible checklists")

    for index, checklist_id in enumerate(payload.checklist_ids):
        await db.checklists.update_one(
            {"id": checklist_id},
            {"$set": {"order": index}},
        )

    return {"ok": True}

# ---------------- Documents ----------------
@api.post("/admin/documents")
async def create_document(payload: DocumentIn, _: dict = Depends(require_admin)):
    doc = {
        "id": str(uuid.uuid4()),
        "title": payload.title,
        "client_id": payload.client_id,
        "attachment_url": payload.attachment_url,
        "attachment_name": payload.attachment_name,
        "link_url": payload.link_url,
        "created_at": now_iso(),
    }
    await db.documents.insert_one(doc)
    doc.pop("_id", None)

    # notify
    if payload.client_id:
        recipients = [payload.client_id]
    else:
        clients = await db.users.find({"role": "client"}, {"id": 1, "_id": 0}).to_list(2000)
        recipients = [c["id"] for c in clients]
    if recipients:
        await db.notifications.insert_many(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": cid,
                    "title": f"New document: {payload.title}",
                    "body": payload.attachment_name or payload.link_url,
                    "type": "document",
                    "read": False,
                    "link": "/client/documents",
                    "created_at": now_iso(),
                }
                for cid in recipients
            ]
        )
    return doc


@api.get("/admin/documents")
async def admin_list_documents(_: dict = Depends(require_admin)):
    items = await db.documents.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return items


@api.delete("/admin/documents/{doc_id}")
async def delete_document(doc_id: str, _: dict = Depends(require_admin)):
    await db.documents.delete_one({"id": doc_id})
    return {"ok": True}




@api.get("/client/documents")
async def client_list_documents(user: dict = Depends(require_client)):
    items = await db.documents.find(
        {"$or": [{"client_id": user["id"]}, {"client_id": None}]}, {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    return items

# ---------------- Admin: Clients ----------------
@api.get("/admin/clients")
async def list_clients(_: dict = Depends(require_admin)):
    cursor = db.users.find({"role": "client"}, {"_id": 0, "password_hash": 0})
    items = await cursor.to_list(1000)
    return items


@api.post("/admin/clients")
async def create_client(payload: CreateClientIn, _: dict = Depends(require_admin)):
    email = payload.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    plain_password = payload.password or secrets.token_urlsafe(10)
    user_doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "name": payload.name,
        "company": payload.company or "",
        "phone": payload.phone or "",
        "role": "client",
        "services": payload.services or [],
        "notes": payload.notes or "",
        "active": True,
        "avatar_url": "",
        "password_hash": hash_password(plain_password),
        "created_at": now_iso(),
    }
    await db.users.insert_one(user_doc)
    safe = doc_clean(dict(user_doc))
    return {"user": safe, "generated_password": plain_password}


@api.patch("/admin/clients/{client_id}")
async def update_client(client_id: str, payload: UpdateClientIn, _: dict = Depends(require_admin)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    res = await db.users.update_one({"id": client_id, "role": "client"}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    user = await db.users.find_one({"id": client_id}, {"_id": 0, "password_hash": 0})
    return user


@api.post("/admin/clients/{client_id}/reset-password")
async def reset_client_password(client_id: str, payload: ResetPasswordIn, _: dict = Depends(require_admin)):
    user = await db.users.find_one({"id": client_id, "role": "client"})
    if not user:
        raise HTTPException(status_code=404, detail="Client not found")
    new_password = payload.password or secrets.token_urlsafe(10)
    await db.users.update_one({"id": client_id}, {"$set": {"password_hash": hash_password(new_password)}})
    return {"generated_password": new_password}


@api.delete("/admin/clients/{client_id}")
async def delete_client(client_id: str, _: dict = Depends(require_admin)):
    res = await db.users.delete_one({"id": client_id, "role": "client"})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    # cascade
    await db.invoices.delete_many({"client_id": client_id})
    await db.updates.delete_many({"client_id": client_id})
    await db.tickets.delete_many({"client_id": client_id})
    await db.notifications.delete_many({"user_id": client_id})
    await db.addon_requests.delete_many({"client_id": client_id})
    return {"ok": True}
@api.patch("/client/profile")
async def update_client_profile(
    payload: ClientProfileUpdate,
    user: dict = Depends(require_client),
):
    updates = {
        k: v for k, v in payload.model_dump().items()
        if v is not None
    }

    await db.users.update_one(
        {"id": user["id"]},
        {"$set": updates}
    )

    return {"ok": True}

# ---------------- Admin: Services ----------------
@api.get("/services")
async def list_services(_: dict = Depends(get_current_user)):
    items = await db.services.find({}, {"_id": 0}).to_list(500)
    return items


@api.post("/admin/services")
async def create_service(payload: ServiceIn, _: dict = Depends(require_admin)):
    doc = {"id": str(uuid.uuid4()), **payload.model_dump(), "created_at": now_iso()}
    await db.services.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.delete("/admin/services/{service_id}")
async def delete_service(service_id: str, _: dict = Depends(require_admin)):
    await db.services.delete_one({"id": service_id})
    return {"ok": True}


# ---------------- Admin: Add-ons ----------------
@api.get("/addons")
async def list_addons(_: dict = Depends(get_current_user)):
    items = await db.addons.find({}, {"_id": 0}).to_list(500)
    return items


@api.post("/admin/addons")
async def create_addon(payload: AddOnIn, _: dict = Depends(require_admin)):
    doc = {"id": str(uuid.uuid4()), **payload.model_dump(), "created_at": now_iso()}
    await db.addons.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.delete("/admin/addons/{addon_id}")
async def delete_addon(addon_id: str, _: dict = Depends(require_admin)):
    await db.addons.delete_one({"id": addon_id})
    return {"ok": True}


# ---------------- Invoices ----------------
def calc_invoice_totals(items: List[dict], tax: float) -> dict:
    subtotal = sum(it["qty"] * it["unit_price"] for it in items)
    total = subtotal + tax
    return {"subtotal": round(subtotal, 2), "tax": round(tax, 2), "total": round(total, 2)}


@api.post("/admin/invoices")
async def create_invoice(payload: InvoiceIn, _: dict = Depends(require_admin)):
    client = await db.users.find_one({"id": payload.client_id, "role": "client"})
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = [it.model_dump() for it in payload.items]
    totals = calc_invoice_totals(items, payload.tax)
    invoice = {
        "id": str(uuid.uuid4()),
        "number": "INV-" + secrets.token_hex(4).upper(),
        "client_id": payload.client_id,
        "client_name": client["name"],
        "items": items,
        **totals,
        "due_date": payload.due_date or "",
        "memo": payload.memo or "",
        "status": "open",
        "created_at": now_iso(),
        "paid_at": None,
    }
    await db.invoices.insert_one(invoice)
    invoice.pop("_id", None)
    # notification
    await db.notifications.insert_one(
        {
            "id": str(uuid.uuid4()),
            "user_id": payload.client_id,
            "title": "New invoice issued",
            "body": f"{invoice['number']} • ₹{invoice['total']:.2f}",
            "type": "invoice",
            "read": False,
            "link": "/client/invoices",
            "created_at": now_iso(),
        }
    )
    return invoice


@api.get("/admin/invoices")
async def admin_list_invoices(_: dict = Depends(require_admin)):
    items = await db.invoices.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return items


@api.post("/admin/invoices/{invoice_id}/mark-paid")
async def mark_invoice_paid(invoice_id: str, _: dict = Depends(require_admin)):
    inv = await db.invoices.find_one({"id": invoice_id})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    await db.invoices.update_one({"id": invoice_id}, {"$set": {"status": "paid", "paid_at": now_iso()}})
    return {"ok": True}


@api.delete("/admin/invoices/{invoice_id}")
async def delete_invoice(invoice_id: str, _: dict = Depends(require_admin)):
    await db.invoices.delete_one({"id": invoice_id})
    return {"ok": True}


@api.get("/client/invoices")
async def client_invoices(user: dict = Depends(require_client)):
    items = await db.invoices.find({"client_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return items


@api.post("/client/invoices/{invoice_id}/pay")
async def client_pay_invoice(invoice_id: str, user: dict = Depends(require_client)):
    inv = await db.invoices.find_one({"id": invoice_id, "client_id": user["id"]})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if inv["status"] == "paid":
        return {"ok": True, "message": "Already paid"}
    await db.invoices.update_one({"id": invoice_id}, {"$set": {"status": "paid", "paid_at": now_iso()}})
    return {"ok": True}


# ---------------- Updates ----------------


@api.post("/admin/updates")
async def create_update(payload: UpdateIn, _: dict = Depends(require_admin)):
    doc = {
        "id": str(uuid.uuid4()),
        "title": payload.title,
        "body": payload.body,
        "client_id": payload.client_id,  # None = broadcast
        "category": payload.category,
        "created_at": now_iso(),
        "attachment_url": payload.attachment_url or None,
        "attachment_name": payload.attachment_name or None,
    }
    await db.updates.insert_one(doc)
    doc.pop("_id", None)
    # notify
    if payload.client_id:
        recipients = [payload.client_id]
    else:
        clients = await db.users.find({"role": "client"}, {"id": 1, "_id": 0}).to_list(2000)
        recipients = [c["id"] for c in clients]
    if recipients:
        await db.notifications.insert_many(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": cid,
                    "title": f"New {payload.category.lower()}: {payload.title}",
                    "body": payload.body[:120],
                    "type": "update",
                    "read": False,
                    "link": "/client/updates",
                    "created_at": now_iso(),
                }
                for cid in recipients
            ]
        )
    return doc



@api.post("/admin/uploads")
async def upload_file(
    file: UploadFile = File(...),
    _: dict = Depends(require_admin)
):
    MAX_SIZE = 10 * 1024 * 1024
    content = await file.read()
    print("FILE CONTENT TYPE:", file.content_type)

    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    allowed_types = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/html",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/csv",
    "text/plain",
}


    if file.content_type not in allowed_types:
        raise HTTPException(status_code=415, detail="Only PDF and Word files allowed")

    file_id = str(uuid.uuid4())
    suffix = os.path.splitext(file.filename)[-1] or ".pdf"
    storage_path = f"{file_id}{suffix}"

    try:
        supabase.storage.from_("reports").upload(
            path=storage_path,
            file=content,
            file_options={"content-type": file.content_type}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

    # get public URL — works immediately since bucket is public
    public_url = supabase.storage.from_("reports").get_public_url(storage_path)

    return {
        "url": public_url,
        "filename": file.filename,
    }



@api.get("/admin/updates")
async def admin_list_updates(_: dict = Depends(require_admin)):
    items = await db.updates.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return items


@api.delete("/admin/updates/{update_id}")
async def delete_update(update_id: str, _: dict = Depends(require_admin)):
    await db.updates.delete_one({"id": update_id})
    return {"ok": True}


@api.get("/client/updates")
async def client_updates(user: dict = Depends(require_client)):
    cursor = db.updates.find(
        {"$or": [{"client_id": user["id"]}, {"client_id": None}]}, {"_id": 0}
    ).sort("created_at", -1)
    items = await cursor.to_list(1000)
    return items


# ---------------- Tickets ----------------
@api.post("/client/tickets")
async def client_create_ticket(payload: TicketIn, user: dict = Depends(require_client)):
    doc = {
        "id": str(uuid.uuid4()),
        "client_id": user["id"],
        "client_name": user["name"],
        "subject": payload.subject,
        "priority": payload.priority,
        "status": "open",
        "messages": [
            {
                "id": str(uuid.uuid4()),
                "author_id": user["id"],
                "author_name": user["name"],
                "author_role": "client",
                "message": payload.message,
                "created_at": now_iso(),
            }
        ],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.tickets.insert_one(doc)
    doc.pop("_id", None)
    # notify all admins
    admins = await db.users.find({"role": "admin"}, {"id": 1, "_id": 0}).to_list(50)
    if admins:
        await db.notifications.insert_many(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": a["id"],
                    "title": f"New ticket from {user['name']}",
                    "body": payload.subject,
                    "type": "ticket",
                    "read": False,
                    "link": "/admin/tickets",
                    "created_at": now_iso(),
                }
                for a in admins
            ]
        )
    return doc


@api.get("/client/tickets")
async def client_list_tickets(user: dict = Depends(require_client)):
    items = await db.tickets.find({"client_id": user["id"]}, {"_id": 0}).sort("updated_at", -1).to_list(1000)
    return items


@api.post("/client/tickets/{ticket_id}/messages")
async def client_reply_ticket(ticket_id: str, payload: TicketMessageIn, user: dict = Depends(require_client)):
    ticket = await db.tickets.find_one({"id": ticket_id, "client_id": user["id"]})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    msg = {
        "id": str(uuid.uuid4()),
        "author_id": user["id"],
        "author_name": user["name"],
        "author_role": "client",
        "message": payload.message,
        "created_at": now_iso(),
    }
    await db.tickets.update_one(
        {"id": ticket_id},
        {"$push": {"messages": msg}, "$set": {"updated_at": now_iso(), "status": "open"}},
    )
    return msg


@api.get("/admin/tickets")
async def admin_list_tickets(_: dict = Depends(require_admin)):
    items = await db.tickets.find({}, {"_id": 0}).sort("updated_at", -1).to_list(1000)
    return items


@api.post("/admin/tickets/{ticket_id}/messages")
async def admin_reply_ticket(ticket_id: str, payload: TicketMessageIn, admin: dict = Depends(require_admin)):
    ticket = await db.tickets.find_one({"id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    msg = {
        "id": str(uuid.uuid4()),
        "author_id": admin["id"],
        "author_name": admin["name"],
        "author_role": "admin",
        "message": payload.message,
        "created_at": now_iso(),
    }
    await db.tickets.update_one(
        {"id": ticket_id},
        {"$push": {"messages": msg}, "$set": {"updated_at": now_iso(), "status": "pending"}},
    )
    # notify client
    await db.notifications.insert_one(
        {
            "id": str(uuid.uuid4()),
            "user_id": ticket["client_id"],
            "title": "Support reply",
            "body": payload.message[:120],
            "type": "ticket",
            "read": False,
            "link": "/client/support",
            "created_at": now_iso(),
        }
    )
    return msg


@api.patch("/admin/tickets/{ticket_id}/status")
async def admin_set_ticket_status(ticket_id: str, payload: TicketStatusIn, _: dict = Depends(require_admin)):
    ticket = await db.tickets.find_one({"id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    await db.tickets.update_one(
        {"id": ticket_id}, {"$set": {"status": payload.status, "updated_at": now_iso()}}
    )

    # notify client
    await db.notifications.insert_one(
        {
            "id": str(uuid.uuid4()),
            "user_id": ticket["client_id"],
            "title": "Ticket status updated",
            "body": f"Your ticket \"{ticket['subject']}\" is now {payload.status}",
            "type": "ticket",
            "read": False,
            "link": "/client/support",
            "created_at": now_iso(),
        }
    )
    return {"ok": True}


# ---------------- Add-on requests ----------------
@api.post("/client/addons/request")
async def client_request_addon(payload: AddOnRequestIn, user: dict = Depends(require_client)):
    addon = await db.addons.find_one({"id": payload.addon_id})
    if not addon:
        raise HTTPException(status_code=404, detail="Add-on not found")
    doc = {
        "id": str(uuid.uuid4()),
        "client_id": user["id"],
        "client_name": user["name"],
        "addon_id": payload.addon_id,
        "addon_name": addon["name"],
        "addon_price": addon.get("price", 0),
        "note": payload.note or "",
        "status": "pending",
        "created_at": now_iso(),
    }
    await db.addon_requests.insert_one(doc)
    doc.pop("_id", None)
    admins = await db.users.find({"role": "admin"}, {"id": 1, "_id": 0}).to_list(50)
    if admins:
        await db.notifications.insert_many(
            [
                {
                    "id": str(uuid.uuid4()),
                    "user_id": a["id"],
                    "title": f"Add-on request: {addon['name']}",
                    "body": f"From {user['name']}",
                    "type": "addon",
                    "read": False,
                    "link": "/admin/addons",
                    "created_at": now_iso(),
                }
                for a in admins
            ]
        )
    return doc


@api.get("/client/addons/requests")
async def client_list_addon_requests(user: dict = Depends(require_client)):
    items = await db.addon_requests.find({"client_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items

@api.delete("/client/addons/request/{req_id}")
async def client_delete_addon_request(
    req_id: str,
    user: dict = Depends(require_client)
):
    res = await db.addon_requests.delete_one({
        "id": req_id,
        "client_id": user["id"]
    })

    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Request not found")

    return {"ok": True}


@api.get("/admin/addons/requests")
async def admin_list_addon_requests(_: dict = Depends(require_admin)):
    items = await db.addon_requests.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return items


@api.patch("/admin/addons/requests/{req_id}")
async def admin_update_addon_request(
    req_id: str,
    payload: TicketStatusIn,
    _: dict = Depends(require_admin),
):
    request_doc = await db.addon_requests.find_one({"id": req_id})

    if not request_doc:
        raise HTTPException(status_code=404, detail="Request not found")

    await db.addon_requests.update_one(
        {"id": req_id},
        {"$set": {"status": payload.status}}
    )

    # notify client
    await db.notifications.insert_one(
        {
            "id": str(uuid.uuid4()),
            "user_id": request_doc["client_id"],
            "title": f"Add-on request {payload.status}",
            "body": f"{request_doc['addon_name']} request was {payload.status}",
            "type": "addon",
            "read": False,
            "link": "/client/addons",
            "created_at": now_iso(),
        }
    )

    return {"ok": True}

# ---------------- Notifications ----------------
@api.get("/notifications")
async def list_notifications(user: dict = Depends(get_current_user)):
    items = await db.notifications.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).limit(50).to_list(50)
    return items


@api.post("/notifications/mark-all-read")
async def mark_all_read(user: dict = Depends(get_current_user)):
    await db.notifications.update_many({"user_id": user["id"], "read": False}, {"$set": {"read": True}})
    return {"ok": True}


@api.post("/notifications/{nid}/read")
async def mark_read(nid: str, user: dict = Depends(get_current_user)):
    await db.notifications.update_one({"id": nid, "user_id": user["id"]}, {"$set": {"read": True}})
    return {"ok": True}


# ---------------- Dashboards ----------------
@api.get("/admin/stats")
async def admin_stats(_: dict = Depends(require_admin)):
    total_clients = await db.users.count_documents({"role": "client"})
    active_clients = await db.users.count_documents({"role": "client", "active": {"$ne": False}})
    open_invoices = await db.invoices.count_documents({"status": "open"})
    paid_invoices_cursor = db.invoices.find({"status": "paid"}, {"total": 1, "_id": 0})
    paid_invoices = await paid_invoices_cursor.to_list(10000)
    revenue = round(sum(i.get("total", 0) for i in paid_invoices), 2)
    pending_revenue_cursor = db.invoices.find({"status": "open"}, {"total": 1, "_id": 0})
    pending = await pending_revenue_cursor.to_list(10000)
    pending_revenue = round(sum(i.get("total", 0) for i in pending), 2)
    open_tickets = await db.tickets.count_documents({"status": {"$in": ["open", "pending"]}})
    addon_pending = await db.addon_requests.count_documents({"status": "pending"})
    recent_invoices = await db.invoices.find({}, {"_id": 0}).sort("created_at", -1).limit(5).to_list(5)
    recent_tickets = await db.tickets.find({}, {"_id": 0, "messages": 0}).sort("updated_at", -1).limit(5).to_list(5)
    return {
        "total_clients": total_clients,
        "active_clients": active_clients,
        "open_invoices": open_invoices,
        "revenue": revenue,
        "pending_revenue": pending_revenue,
        "open_tickets": open_tickets,
        "addon_pending": addon_pending,
        "recent_invoices": recent_invoices,
        "recent_tickets": recent_tickets,
    }


@api.get("/client/dashboard")
async def client_dashboard(user: dict = Depends(require_client)):
    open_invoices = await db.invoices.find(
        {"client_id": user["id"], "status": "open"}, {"_id": 0}
    ).to_list(500)
    paid_count = await db.invoices.count_documents({"client_id": user["id"], "status": "paid"})
    services = await db.services.find({"id": {"$in": user.get("services", [])}}, {"_id": 0}).to_list(100)
    updates = await db.updates.find(
        {"$or": [{"client_id": user["id"]}, {"client_id": None}]}, {"_id": 0}
    ).sort("created_at", -1).limit(5).to_list(5)
    open_tickets = await db.tickets.count_documents(
        {"client_id": user["id"], "status": {"$in": ["open", "pending"]}}
    )
    pending_total = round(sum(i.get("total", 0) for i in open_invoices), 2)
    return {
        "user": user,
        "open_invoices_count": len(open_invoices),
        "pending_amount": pending_total,
        "paid_invoices_count": paid_count,
        "services": services,
        "updates": updates,
        "open_tickets": open_tickets,
        "next_invoice": open_invoices[0] if open_invoices else None,
    }


@api.get("/")
async def root():
    return {"app": "Rebild Client Portal API", "status": "ok"}


# ---------------- Startup ----------------
DEFAULT_SERVICES = [
    {"name": "Meta & Google Ads", "description": "Paid advertising campaigns across Meta and Google.", "icon": "Megaphone", "color": "#F77418"},
    {"name": "Photography", "description": "Product, brand and event photography.", "icon": "Camera", "color": "#F77418"},
    {"name": "Video Production", "description": "Reels, ads, brand films and YouTube content.", "icon": "Video", "color": "#F77418"},
    {"name": "Graphic Design", "description": "Logos, branding, creatives and social design.", "icon": "Palette", "color": "#F77418"},
    {"name": "Social Media Management", "description": "Content calendar, posting and engagement.", "icon": "Share2", "color": "#F77418"},
]

DEFAULT_ADDONS = [
    {"name": "Logo Animation", "description": "5-second animated logo intro for videos.", "price": 199.0, "icon": "Sparkles"},
    {"name": "Drone Coverage", "description": "Aerial drone shots add-on for photo/video shoots.", "price": 349.0, "icon": "Plane"},
    {"name": "Extra Reels (5)", "description": "Five additional short-form reels per month.", "price": 499.0, "icon": "Film"},
    {"name": "Influencer Outreach", "description": "Curated influencer partnership pack.", "price": 899.0, "icon": "Users"},
]


@app.on_event("startup")
async def on_startup():
    # indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.invoices.create_index("id", unique=True)
    await db.updates.create_index("id", unique=True)
    await db.tickets.create_index("id", unique=True)
    await db.services.create_index("id", unique=True)
    await db.addons.create_index("id", unique=True)
    await db.notifications.create_index("user_id")
    await db.checklists.create_index("id", unique=True)
    await db.documents.create_index("id", unique=True)

    # seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@rebild.com").lower().strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "Rebild@2026")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one(
            {
                "id": str(uuid.uuid4()),
                "email": admin_email,
                "name": "Rebild Admin",
                "company": "Rebild",
                "phone": "",
                "role": "admin",
                "active": True,
                "avatar_url": "",
                "password_hash": hash_password(admin_password),
                "created_at": now_iso(),
            }
        )
        logger.info(f"Seeded admin: {admin_email}")
    else:
        # if password env changed, sync it
        if not verify_password(admin_password, existing.get("password_hash", "")):
            await db.users.update_one(
                {"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}}
            )

    # seed services if empty
    services_count = await db.services.count_documents({})
    if services_count == 0:
        await db.services.insert_many(
            [{"id": str(uuid.uuid4()), **s, "created_at": now_iso()} for s in DEFAULT_SERVICES]
        )
        logger.info("Seeded default services")

    addons_count = await db.addons.count_documents({})
    if addons_count == 0:
        await db.addons.insert_many(
            [{"id": str(uuid.uuid4()), **a, "created_at": now_iso()} for a in DEFAULT_ADDONS]
        )
        logger.info("Seeded default add-ons")


@app.on_event("shutdown")
async def on_shutdown():
    mongo_client.close()


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.environ.get("FRONTEND_URL", ""),
        "http://localhost:3000",
        "https://portal.rebild.in",
        "https://client-onboard-rebild.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
