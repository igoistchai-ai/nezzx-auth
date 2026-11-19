"""NEZZX AUTH | Single-file Discord Lua licensing service (loader v2).

Deployment on Render, only one bot.py file in a private GitHub repo.
Build Command:
  pip install "fastapi>=0.115,<1" "uvicorn>=0.34,<1" "httpx>=0.28,<1" "SQLAlchemy>=2,<3" "psycopg[binary]>=3.2,<4" "cryptography>=44,<48" "python-dotenv>=1,<2"
Start Command:
  python bot.py

ENV required (ONLY THREE):
  DISCORD_BOT_TOKEN         Discord Developer Portal -> Bot Token
  DATABASE_URL              PostgreSQL Internal Database URL from Render
  AUTH_SECRET               Random secret of 32+ characters (Render: Generate)

ENV optional:
  OWNER_IDS                 Owner Discord IDs, comma-separated. Normally detected
                            automatically from the Discord application owner.
  PORT                      Automatically set by Render.

Bot application ID, signature verification public key and (for a personal
app) owner Discord ID are loaded from Discord's application API at startup.
Commands are registered globally and work in guilds (not DMs). Use
/publishpanel in a public text channel to post a persistent buyer panel.
Buyer keys, loaders and license status are sent as private interaction responses.

Use Render -> Environment -> Generate Value for AUTH_SECRET, or python bot.py --secret.
Discord Developer Portal -> Interactions Endpoint URL:
  https://YOUR-RENDER-DOMAIN.onrender.com/interactions
Health check:
  https://YOUR-RENDER-DOMAIN.onrender.com/health

Interaction response fix: instant ephemeral acknowledgement for commands, then
async edit with bounded work and detailed Render error logging.

Five protections: Discord Ed25519, owner/whitelist/blacklist controls,
HMAC-indexed licenses, device binding+reset limit, AES-256-GCM at rest.
Security limit: client-executed Lua cannot be made impossible to extract.
The bot stores Lua without executing it. HTTPS is provided by Render.
Loader v2: compatible HTTP API resolution and clearer client-side failures;
new files are generated automatically from /loader and buyer panel.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nezzx-auth")
# HTTP library otherwise logs the full Discord interaction webhook URL (secret token).
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# App ID and public key are obtained from the official Discord API at startup.
APP_ID = ""
PUBLIC_KEY = ""
BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
OWNER_IDS = {v.strip() for v in os.environ.get("OWNER_IDS", "").split(",") if v.strip()}
STRICT_WHITELIST = False
MAX_SCRIPT_BYTES = 10 * 1024 * 1024  # 10 MiB, no ENV required.
AUTH_SECRET = os.environ.get("AUTH_SECRET", "").strip()
DB_URL = os.environ.get("DATABASE_URL", "").strip()
if not DB_URL:
    if os.environ.get("RENDER") or os.environ.get("RENDER_EXTERNAL_HOSTNAME"):
        raise RuntimeError("DATABASE_URL is required on Render to preserve licenses and scripts")
    DB_URL = "sqlite:///./local.db"
if DB_URL.startswith("postgres://"):
    DB_URL = "postgresql://" + DB_URL[len("postgres://"):]
if DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg://", 1)

AES_KEY: Optional[bytes] = None
HMAC_SECRET: Optional[bytes] = None
if AUTH_SECRET:
    if len(AUTH_SECRET) < 32:
        raise RuntimeError("AUTH_SECRET must be at least 32 random characters")
    master_key = AUTH_SECRET.encode("utf-8")
    # Independent encryption and HMAC keys derived from one persistent master key.
    AES_KEY = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"nezzx-auth-v2-aes").derive(master_key)
    HMAC_SECRET = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                      info=b"nezzx-auth-v2-hmac").derive(master_key)

connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class ScriptAsset(Base):
    __tablename__ = "scripts"
    slug: Mapped[str] = mapped_column(String(48), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    encrypted_blob: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(30), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


class License(Base):
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    script_slug: Mapped[str] = mapped_column(ForeignKey("scripts.slug"), nullable=False, index=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(30), index=True, nullable=True)
    device_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reset_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_loaded_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    guild_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    script_slug: Mapped[str] = mapped_column(ForeignKey("scripts.slug"), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(30))
    license_id: Mapped[Optional[int]] = mapped_column(Integer)


class PublicPanel(Base):
    __tablename__ = "public_panels"
    guild_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    channel_id: Mapped[str] = mapped_column(String(30), nullable=False)
    message_id: Mapped[str] = mapped_column(String(30), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


class UserFlag(Base):
    __tablename__ = "user_flags"
    __table_args__ = (UniqueConstraint("user_id", "flag", name="uq_user_flag"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    flag: Mapped[str] = mapped_column(String(12), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(30), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    detail: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now)


def record(db: Session, actor: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, detail=detail[:300]))


def secret_digest(value: str) -> str:
    return hmac.new(HMAC_SECRET, value.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt(text: str, aad: str) -> str:
    assert AES_KEY is not None
    nonce = os.urandom(12)
    raw = nonce + AESGCM(AES_KEY).encrypt(nonce, text.encode("utf-8"), aad.encode("utf-8"))
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decrypt(blob: str, aad: str) -> str:
    assert AES_KEY is not None
    raw = base64.urlsafe_b64decode(blob)
    return AESGCM(AES_KEY).decrypt(raw[:12], raw[12:], aad.encode("utf-8")).decode("utf-8")


def has_flag(db: Session, user_id: str, flag: str) -> bool:
    return db.scalar(select(UserFlag.id).where(UserFlag.user_id == user_id, UserFlag.flag == flag)) is not None


def allowed(db: Session, user_id: str) -> bool:
    if has_flag(db, user_id, "blacklist"):
        return False
    return not STRICT_WHITELIST or has_flag(db, user_id, "whitelist") or user_id in OWNER_IDS


def valid_license(lic: License) -> bool:
    return not lic.revoked and (lic.expires_at is None or lic.expires_at > now())


def get_user_license(db: Session, user: str, slug: str) -> Optional[License]:
    licenses = db.scalars(select(License).where(License.user_id == user, License.script_slug == slug).order_by(License.id.desc())).all()
    return next((lic for lic in licenses if valid_license(lic)), None)


def normalize_slug(value: str) -> str:
    value = (value or "").lower().strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,47}", value):
        raise ValueError("Use 2 to 48 letters, digits, underscores or hyphens for the script name.")
    return value


def new_license(db: Session, slug: str, user: Optional[str], days: int) -> tuple[License, str]:
    if db.get(ScriptAsset, slug) is None:
        raise ValueError("Script not found. Upload it with /upload first.")
    if days < 0 or days > 3650:
        raise ValueError("Choose a license duration from 0 to 3650 days.")
    key = "NZX-" + secrets.token_urlsafe(30)
    lic = License(
        script_slug=slug,
        digest=secret_digest(key),
        key_encrypted=encrypt(key, "license-key"),
        user_id=user,
        expires_at=now() + timedelta(days=days) if days else None,
    )
    db.add(lic)
    db.flush()
    return lic, key


def user_id_from_interaction(payload: dict) -> str:
    user = (payload.get("member") or {}).get("user") or payload.get("user") or {}
    return str(user.get("id", ""))


def options(payload: dict) -> dict:
    return {v["name"]: v.get("value") for v in (payload.get("data") or {}).get("options", [])}


def button(label: str, custom_id: str, style: int = 2) -> dict:
    return {"type": 2, "style": style, "label": label, "custom_id": custom_id}


def buttons_row(*items: dict) -> list:
    return [{"type": 1, "components": list(items)}]


def embed(title: str, description: str, color: int = 0xF1C40F) -> dict:
    return {"title": title, "description": description[:4000], "color": color, "footer": {"text": "NEZZX AUTH"}}


def message(content: str = "", *, embed_obj: Optional[dict] = None, components: Optional[list] = None, file: Optional[tuple[str, bytes]] = None) -> dict:
    out: dict = {"content": content[:1900], "allowed_mentions": {"parse": []}}
    if embed_obj:
        out["embeds"] = [embed_obj]
    if components:
        out["components"] = components
    if file:
        out["_file"] = file
    return out


async def discord_request(method: str, path: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=4.0)) as client:
        r = await client.request(method, f"https://discord.com/api/v10{path}", headers={"Authorization": f"Bot {BOT_TOKEN}"}, **kwargs)
        if r.status_code >= 400:
            log.warning("Discord API %s %s => %s %s", method, path.split("?")[0], r.status_code, r.text[:180])
        return r


async def ensure_buyer_role(guild_id: str) -> Optional[str]:
    r = await discord_request("GET", f"/guilds/{guild_id}/roles")
    if not r.is_success:
        return None
    for role in r.json():
        if role.get("name") == "BUYER":
            return str(role["id"])
    r = await discord_request("POST", f"/guilds/{guild_id}/roles", json={"name": "BUYER", "color": 0xF1C40F, "permissions": "0", "mentionable": False, "hoist": True})
    return str(r.json()["id"]) if r.is_success else None


async def assign_buyer(user: str, guild_id: str) -> bool:
    role_id = await ensure_buyer_role(guild_id)
    if not role_id:
        return False
    r = await discord_request("PUT", f"/guilds/{guild_id}/members/{user}/roles/{role_id}")
    return r.is_success


def panel(owner: bool) -> dict:
    if owner:
        text = ("**OWNER CONTROL CENTER**\n\n"
                "`/upload` Upload or update a script.\n"
                "`/createkey` Create an unclaimed key.\n"
                "`/grant` Issue a key to a member.\n"
                "`/whitelist` and `/blacklist` Manage access.\n"
                "`/licenses` and `/revoke` Manage licenses.\n"
                "`/stats` and `/audit` View activity.")
        return message(embed_obj=embed("Owner control panel", text), components=(
            *buttons_row(button("Requests", "owner:requests", 1), button("Scripts", "owner:scripts", 1),
                         button("Licenses", "owner:licenses", 1), button("Statistics", "owner:stats", 1)),
            *buttons_row(button("Publish panel help", "owner:publish", 3), button("Commands", "owner:help", 2))))
    return buyer_public_panel()


def buyer_public_panel() -> dict:

    return message(
        embed_obj={
            "title": "NEZZX AUTH | Access center",
            "description": (
                "Manage your licenses and devices.\n\n"
                "**Get key** shows your license key.\n"
                "**Activate** links a new key to your Discord account.\n"
                "**Get loader** downloads your personal Lua file.\n"
                "**Reset device** lets you change devices once every 24 hours.\n"
                "**My licenses** shows status and expiry.\n\n"
                "Need a license? Select **Request access**."
            ),
            "color": 0xF1C40F,
            "fields": [
                {"name": "Privacy", "value": "Only you can see your key and loader.", "inline": True},
                {"name": "Buyer role", "value": "Granted after activation.", "inline": True},
            ],
            "footer": {"text": "NEZZX AUTH"},
        },
        components=(
            buttons_row(button("Get key", "buyer:get_key", 1),
                        button("Activate", "buyer:redeem", 3),
                        button("Get loader", "buyer:get_loader", 1))
            + buttons_row(button("Reset device", "buyer:reset_hwid", 2),
                          button("My licenses", "buyer:my_licenses", 2),
                          button("Request access", "buyer:request_access", 2))
        ),
    )


def buyer_licenses(db: Session, user: str) -> list[License]:
    all_licenses = db.scalars(select(License).where(License.user_id == user)
                              .order_by(License.id.desc())).all()
    by_script: dict[str, License] = {}
    for license_item in all_licenses:
        if valid_license(license_item) and license_item.script_slug not in by_script:
            by_script[license_item.script_slug] = license_item
    return sorted(by_script.values(), key=lambda item: item.script_slug)


def select_screen(db: Session, user: str, action: str, page: int = 0) -> dict:
    if action == "request":
        active = {lic.script_slug for lic in buyer_licenses(db, user)}
        slugs = [item.slug for item in db.scalars(select(ScriptAsset).order_by(ScriptAsset.slug)).all()
                 if item.slug not in active]
        title = "Request access"
        empty_text = "There are no scripts available to request."
    else:
        slugs = [lic.script_slug for lic in buyer_licenses(db, user)]
        title = {"key": "Get key", "loader": "Get loader", "reset": "Reset device"}[action]
        empty_text = "No active licenses. Select **Request access** or activate a key."
    if not slugs:
        components = buttons_row(button("Request access", "buyer:request_access", 1)) if action != "request" else None
        return message(embed_obj=embed(title, empty_text), components=components)
    total_pages = (len(slugs) - 1) // 25 + 1
    page = max(0, min(page, total_pages - 1))
    if len(slugs) == 1 and action != "request":
        return message("__INTERNAL_SINGLE__:" + action + ":" + slugs[0])
    options_list = [{"label": slug, "value": slug,
                     "description": "Select a script for " + {"key": "key lookup", "loader": "loader", "reset": "device reset", "request": "an access request"}[action]}
                    for slug in slugs[page * 25:(page + 1) * 25]]
    picker = {"type": 3, "custom_id": f"buyer:select:{action}:{page}",
              "placeholder": "Select a script", "min_values": 1, "max_values": 1, "options": options_list}
    components: list[dict] = [{"type": 1, "components": [picker]}]
    if total_pages > 1:
        nav = []
        if page > 0:
            nav.append(button("Back", f"buyer:page:{action}:{page-1}"))
        if page + 1 < total_pages:
            nav.append(button("Next", f"buyer:page:{action}:{page+1}"))
        components += buttons_row(*nav)
    return message(embed_obj=embed(title, f"Select a script. Page **{page+1}/{total_pages}**."),
                   components=components)


def customer_status(db: Session, user: str) -> dict:
    licenses = db.scalars(select(License).where(License.user_id == user).order_by(License.id.desc()).limit(40)).all()
    if not licenses:
        return message(embed_obj=embed("My licenses", "No licenses yet. Select **Request access** or activate a key."),
                       components=buttons_row(button("Request access", "buyer:request_access", 1)))
    lines = []
    for lic in licenses[:20]:
        status = "Revoked" if lic.revoked else "Expired" if not valid_license(lic) else "Active"
        expiration = lic.expires_at.strftime("%d.%m.%Y") if lic.expires_at else "Never"
        device = "Linked" if lic.device_digest else "Unlinked"
        lines.append(f"**{lic.script_slug}** (#{lic.id})\n{status} | Expires: {expiration} | Device: {device}")
    return message(embed_obj=embed("My licenses", "\n\n".join(lines)))


def reset_confirmation(slug: str) -> dict:
    return message(embed_obj=embed("Confirm device reset", f"Reset the device for **{slug}**? Your key stays valid. You can reset again after 24 hours."),
                   components=buttons_row(button("Confirm", f"buyer:confirmreset:{slug}", 3),
                                          button("Cancel", "buyer:cancel", 2)))


async def publish_panel(guild_id: str, channel_id: str, actor: str) -> dict:
    if not guild_id or not channel_id or not guild_id.isdigit() or not channel_id.isdigit():
        return message("Run `/publishpanel` in the channel where you want the panel.")
    panel_data = buyer_public_panel()

    with SessionLocal() as db:
        old = db.get(PublicPanel, guild_id)
        old_channel, old_message = (old.channel_id, old.message_id) if old else ("", "")
    result = None
    if old and old_channel == channel_id:
        result = await discord_request("PATCH", f"/channels/{channel_id}/messages/{old_message}", json=panel_data)
    if result is None or not result.is_success:
        result = await discord_request("POST", f"/channels/{channel_id}/messages", json=panel_data)
    if not result.is_success:
        return message(f"Could not publish the panel (Discord HTTP {result.status_code}). "
                       "Check View Channel, Send Messages and Embed Links. "
                       "For HTTP 401 or 403, verify the bot token and role permissions.")
    message_id = str(result.json()["id"])
    with SessionLocal() as db:
        row = db.get(PublicPanel, guild_id)
        if row is None:
            db.add(PublicPanel(guild_id=guild_id, channel_id=channel_id, message_id=message_id))
        else:
            row.channel_id, row.message_id, row.updated_at = channel_id, message_id, now()
        record(db, actor, "publishpanel", f"channel={channel_id} message={message_id}")
        db.commit()
    return message(f"Buyer panel published.\n"
                   f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}\n"
                   "Run `/publishpanel` to update this message.")


def create_access_request(db: Session, guild_id: str, user: str, slug: str) -> str:
    if db.get(ScriptAsset, slug) is None:
        return "Script not found."
    if get_user_license(db, user, slug):
        return "You already have this license. Select **Get key**."
    old = db.scalar(select(AccessRequest).where(AccessRequest.user_id == user,
                    AccessRequest.guild_id == guild_id,
                    AccessRequest.script_slug == slug, AccessRequest.status == "pending"))
    if old:
        return f"Request **#{old.id}** is awaiting approval."
    if not throttle("access_request:" + user, limit=3, window_s=3600):
        return "Too many requests. Try again in an hour."
    item = AccessRequest(user_id=user, guild_id=guild_id, script_slug=slug, status="pending")
    db.add(item)
    db.flush()
    record(db, user, "request_access", f"request#{item.id} {slug}")
    db.commit()
    return (f"Request **#{item.id}** submitted for **{slug}**.\n"
            "After the owner approves it, select **Get key**.")


def owner_requests(db: Session) -> str:
    rows = db.scalars(select(AccessRequest).where(AccessRequest.status == "pending")
                      .order_by(AccessRequest.id.asc()).limit(20)).all()
    if not rows:
        return "No pending requests."
    body = "\n".join(f"`#{x.id}` | <@{x.user_id}> | `{x.script_slug}` | server `{x.guild_id}`" for x in rows)
    return body + "\n\nApprove with `/approve id [days]` or decline with `/deny id`."


def license_listing(db: Session) -> str:
    result = db.scalars(select(License).order_by(License.id.desc()).limit(15)).all()
    if not result:
        return "No licenses yet."
    return "\n".join(f"`#{v.id}` **{v.script_slug}** | {'REVOKED' if v.revoked else 'EXPIRED' if not valid_license(v) else 'ACTIVE'} | {('<@' + v.user_id + '>') if v.user_id else 'unclaimed'}" for v in result)


def script_listing(db: Session) -> str:
    scripts = db.scalars(select(ScriptAsset).order_by(ScriptAsset.slug.asc()).limit(40)).all()
    if not scripts:
        return "No scripts yet. The owner can add one with `/upload`."
    return "\n".join(f"`{s.slug}` | v{s.version}" for s in scripts)


def statistics(db: Session) -> str:
    return (f"Scripts: **{db.scalar(select(func.count()).select_from(ScriptAsset)) or 0}**\n"
            f"Licenses: **{db.scalar(select(func.count()).select_from(License)) or 0}**\n"
            f"Blocked users: **{db.scalar(select(func.count()).select_from(UserFlag).where(UserFlag.flag == 'blacklist')) or 0}**\n"
            f"Audit entries: **{db.scalar(select(func.count()).select_from(AuditLog)) or 0}**")


HELP_TEXT = ("**Buyers**\nUse the panel or run `/access`, `/redeem`, `/key`, `/loader` or `/resetdevice`.\n\n"
             "**Owner commands**\n`/publishpanel`, `/panel`, `/requests`, `/approve id [days]`, `/deny id`, "
             "`/upload script file`, `/createkey script [days]`, `/grant user script [days]`, "
             "`/whitelist action user`, `/blacklist action user`, `/revoke id`, `/forcereset user script`, `/licenses`, `/stats`, `/audit`.\n\n"
             "Keys and loaders are delivered privately. The owner reviews access requests.")


def modal_text_value(items: list, name: str) -> str:

    for entry in items:
        if not isinstance(entry, dict):
            continue
        if entry.get("custom_id") == name and isinstance(entry.get("value"), str):
            return entry["value"].strip()
        nested = entry.get("components") or []
        if isinstance(entry.get("component"), dict):
            nested = list(nested) + [entry["component"]]
        value = modal_text_value(nested, name)
        if value:
            return value
    return ""


async def selected_action(user: str, guild_id: str, action: str, slug: str, api_url: str) -> dict:
    if action not in {"key", "loader", "reset", "confirmreset", "request"}:
        return message("Unknown action.")
    with SessionLocal() as db:
        if not allowed(db, user):
            return message("Access denied. Contact the owner.")
        if action == "request":
            return message(create_access_request(db, guild_id, user, slug))
        lic = get_user_license(db, user, slug)
        if lic is None:
            return message("No active license for this script. Select **Request access**.")
        if action == "reset":
            if lic.device_digest is None:
                return message("No device is linked yet.")
            return reset_confirmation(slug)
        if action == "confirmreset":
            if lic.device_digest is None:
                return message("The device binding is already clear.")
            if lic.reset_at and now() - lic.reset_at < timedelta(hours=24):
                remain = timedelta(hours=24) - (now() - lic.reset_at)
                hours, seconds = divmod(int(remain.total_seconds()), 3600)
                return message(f"You can reset again in **{hours}h {seconds // 60}m**.")
            lic.device_digest = None
            lic.reset_at = now()
            record(db, user, "resetdevice", f"license#{lic.id}")
            db.commit()
            return message("Device reset. The next successful sign-in links your device. You can reset again in 24 hours.")
        key = decrypt(lic.key_encrypted, "license-key")
    if action == "key":
        return message(f"**Your key for {slug}**\n```{key}```\n"
                       "Keep this key private.")
    lua = build_loader(api_url, slug, key)
    return message(f"Your loader for **{slug}** is attached.\n"
                   "The file contains your private license key.",
                   file=(f"nezzx_{slug}_loader.lua", lua.encode("utf-8")))


async def process_command(payload: dict, api_url: str) -> dict:
    user = user_id_from_interaction(payload)
    guild_id = str(payload.get("guild_id", ""))
    if not guild_id:
        return message("Use this command in a Discord server.")
    data = payload.get("data") or {}
    name = data.get("name", "")
    cid = data.get("custom_id", "")
    opts = options(payload)
    owner = user in OWNER_IDS
    if cid.startswith("owner:") and not owner:
        return message("Only the owner can open this panel.")
    if name in {"panel", "publishpanel", "requests", "approve", "deny", "upload", "createkey", "grant", "whitelist", "blacklist", "revoke", "licenses", "stats", "audit", "forcereset"} and not owner:
        return message("Only the owner can use this command.")

    # Owner-controlled button pages. No unsafe GET mutation.
    if cid in {"owner:scripts", "owner:licenses", "owner:stats", "owner:requests", "owner:help", "buyer:scripts", "buyer:help"}:
        with SessionLocal() as db:
            mapping = {
                "owner:scripts": ("Scripts", script_listing(db)),
                "owner:licenses": ("Licenses", license_listing(db)),
                "owner:stats": ("Statistics", statistics(db)),
                "owner:requests": ("Buyer requests", owner_requests(db)),
                "owner:help": ("Commands", HELP_TEXT),
                "buyer:scripts": ("Available Scripts", script_listing(db)),
                "buyer:help": ("Help", HELP_TEXT),
            }
            title, body = mapping[cid]
            return message(embed_obj=embed(title, body))
    if name == "publishpanel" or cid == "owner:publish":
        return await publish_panel(guild_id, str(payload.get("channel_id", "")), user)

    if cid in {"buyer:cancel", "buyer:my_licenses"}:
        if cid == "buyer:cancel":
            return message("Cancelled.")
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Access denied. Contact the owner.")
            return customer_status(db, user)

    if cid in {"buyer:get_key", "buyer:get_loader", "buyer:reset_hwid", "buyer:request_access"} or cid.startswith("buyer:page:"):
        if cid.startswith("buyer:page:"):
            parts = cid.split(":")
            if len(parts) != 4 or parts[2] not in {"key", "loader", "reset", "request"}:
                return message("Invalid action.")
            action, page = parts[2], min(10000, max(0, int(parts[3])))
        else:
            action = {"buyer:get_key": "key", "buyer:get_loader": "loader",
                      "buyer:reset_hwid": "reset", "buyer:request_access": "request"}[cid]
            page = 0
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Access denied. Contact the owner.")
            screen = select_screen(db, user, action, page)
        single = screen.get("content", "")
        if single.startswith("__INTERNAL_SINGLE__:"):
            _, action, slug = single.split(":")
            return await selected_action(user, guild_id, action, slug, api_url)
        return screen

    if cid.startswith("buyer:select:"):
        parts = cid.split(":")
        if len(parts) != 4 or parts[2] not in {"key", "loader", "reset", "request"}:
            return message("Invalid selection.")
        values = data.get("values") or []
        if len(values) != 1 or not isinstance(values[0], str):
            return message("Select one script.")
        try:
            slug = normalize_slug(values[0])
        except ValueError:
            return message("Invalid script name.")
        return await selected_action(user, guild_id, parts[2], slug, api_url)

    if cid.startswith("buyer:confirmreset:"):
        slug = normalize_slug(cid.split(":", 2)[2])
        return await selected_action(user, guild_id, "confirmreset", slug, api_url)

    if name == "requests":
        with SessionLocal() as db:
            return message(embed_obj=embed("Buyer requests", owner_requests(db)))

    if name in {"approve", "deny"}:
        request_id = int(opts.get("id", 0))
        days = int(opts.get("days", 30))
        if days < 0 or days > 3650:
            return message("Choose 0 to 3650 days. Use 0 for lifetime access.")
        with SessionLocal() as db:
            item = db.scalar(select(AccessRequest).where(AccessRequest.id == request_id).with_for_update())
            if item is None or item.status != "pending":
                return message("Request missing or already processed.")
            if name == "deny":
                item.status = "rejected"
                item.resolved_by, item.resolved_at = user, now()
                record(db, user, "deny_access", f"request#{item.id}")
                db.commit()
                return message(f"Request **#{request_id}** declined.")
            if not allowed(db, item.user_id):
                return message("The user is blocked or lacks the required access.")
            prior = get_user_license(db, item.user_id, item.script_slug)
            if prior is None:
                lic, _ = new_license(db, item.script_slug, item.user_id, days)
            else:
                lic = prior
            item.status = "approved"
            item.resolved_by, item.resolved_at, item.license_id = user, now(), lic.id
            record(db, user, "approve_access", f"request#{item.id} license#{lic.id}")
            target_id, target_guild, slug = item.user_id, item.guild_id, item.script_slug
            db.commit()
        role_ok = await assign_buyer(target_id, target_guild)
        return message(f"Approved request **#{request_id}** for <@{target_id}> and **{slug}**.\n"
                       "The buyer can now use **Get key** and **Get loader**."
                       + ("\nCould not grant the BUYER role. Check bot permissions." if not role_ok else "\nBUYER role granted."))

    if name == "help":
        return message(embed_obj=embed("Help", HELP_TEXT))
    if name == "access":
        # Fast response: BUYER role is created when granting/activating a license.
        return panel(False)
    if name == "panel":
        return panel(True)

    if name == "upload":
        slug = normalize_slug(str(opts.get("script", "")))
        attachment_id = str(opts.get("file", ""))
        attachment = (((payload.get("data") or {}).get("resolved") or {}).get("attachments") or {}).get(attachment_id)
        if not attachment:
            return message("Discord attachment missing.")
        filename = attachment.get("filename", "").lower()
        if not (filename.endswith(".lua") or filename.endswith(".txt")):
            return message("Choose a .lua or .txt file.")
        if int(attachment.get("size", MAX_SCRIPT_BYTES + 1)) > MAX_SCRIPT_BYTES:
            return message(f"File size limit: {MAX_SCRIPT_BYTES // 1024} KiB.")
        url = str(attachment.get("url", ""))
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in {"cdn.discordapp.com", "media.discordapp.net"}:
            return message("Unrecognized attachment host.")
        async with httpx.AsyncClient(timeout=16, follow_redirects=False) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_SCRIPT_BYTES:
                        return message("The file is empty or exceeds the size limit.")
                    chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw:
            return message("The file is empty.")
        try:
            source = raw.decode("utf-8-sig")
        except UnicodeError:
            return message("Use UTF-8 encoding.")
        with SessionLocal() as db:
            existing = db.get(ScriptAsset, slug)
            version = 1 if existing is None else existing.version + 1
            encrypted = encrypt(source, f"script:{slug}:{version}")
            if existing is None:
                db.add(ScriptAsset(slug=slug, version=version, encrypted_blob=encrypted, uploaded_by=user, updated_at=now()))
            else:
                existing.version = version
                existing.encrypted_blob = encrypted
                existing.uploaded_by = user
                existing.updated_at = now()
            record(db, user, "upload", f"{slug}@{version}")
            db.commit()
        return message(embed_obj=embed("Script saved", f"**{slug}** updated to **v{version}**. Existing licenses receive this version on their next load."))

    if name in {"scripts", "licenses", "stats", "audit"}:
        with SessionLocal() as db:
            if name == "audit":
                recent = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(15)).all()
                body = "\n".join(f"`{v.created_at.strftime('%m-%d %H:%M')}` {v.action} / {v.actor}: {v.detail}" for v in recent) or "The audit log is empty."
            else:
                body = {"scripts": script_listing, "licenses": license_listing, "stats": statistics}[name](db)
        return message(embed_obj=embed(name.capitalize(), body))

    if name in {"createkey", "grant"}:
        slug = normalize_slug(str(opts.get("script", "")))
        days = int(opts.get("days", 0))
        target = str(opts.get("user")) if name == "grant" else None
        with SessionLocal() as db:
            lic, key = new_license(db, slug, target, days)
            record(db, user, name, f"license#{lic.id} {slug} assigned={target or 'unclaimed'}")
            db.commit()
            lic_id = lic.id
        role_note = ""
        if target:
            ok = await assign_buyer(target, guild_id)
            role_note = "\nBUYER role: added." if ok else "\nCould not grant BUYER. Check bot permissions and role order."
        return message(f"**License #{lic_id}** for `{slug}`\n```{key}```\n{'User: <@' + target + '>' if target else 'Unclaimed key'}\nExpires: {'never' if not days else str(days) + ' days'}{role_note}\nKeep this key private.")

    if name == "redeem" or cid == "modal:redeem":
        key = str(opts.get("key", "")) if name == "redeem" else modal_text_value((payload.get("data") or {}).get("components") or [], "key")
        if len(key) > 256:
            return message("Invalid key format.")
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Access denied. Contact the owner.")
            lic = db.scalar(select(License).where(License.digest == secret_digest(key)))
            if lic is None or not valid_license(lic):
                return message("Key invalid, revoked or expired.")
            if lic.user_id not in (None, user):
                return message("This key is linked to another Discord account.")
            if lic.user_id is None:
                # Race-safe claim even under concurrent submissions.
                changed = db.execute(update(License).where(License.id == lic.id, License.user_id.is_(None)).values(user_id=user)).rowcount
                db.commit()
                if not changed:
                    lic = db.get(License, lic.id)
                    if lic.user_id != user:
                        return message("Another user has claimed this key.")
            record(db, user, "redeem", f"license#{lic.id} {lic.script_slug}")
            db.commit()
            slug = lic.script_slug
        role_ok = await assign_buyer(user, guild_id)
        return message(f"License activated for **{slug}**. Use `/key {slug}` or `/loader {slug}`." + ("\nCould not grant BUYER. Ask the owner to check bot permissions." if not role_ok else "\nBUYER role granted."))

    if name in {"key", "loader", "resetdevice"}:
        slug = normalize_slug(str(opts.get("script", "")))
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Access denied. Contact the owner.")
            lic = get_user_license(db, user, slug)
            if lic is None:
                return message("No active license. Activate a key using `/redeem` or `/access`.")
            if name == "resetdevice":
                if lic.device_digest is None:
                    return message("This license has no linked device.")
                if lic.reset_at and now() - lic.reset_at < timedelta(hours=24):
                    remain = timedelta(hours=24) - (now() - lic.reset_at)
                    hours, seconds = divmod(int(remain.total_seconds()), 3600)
                    return message(f"You can reset again in {hours}h {seconds // 60}m.")
                lic.device_digest = None
                lic.reset_at = now()
                record(db, user, "resetdevice", f"license#{lic.id}")
                db.commit()
                return message("Device reset. The next successful sign-in links your device. You can reset again in 24 hours.")
            key = decrypt(lic.key_encrypted, "license-key")
        if name == "key":
            return message(f"Your key for **{slug}**\n```{key}```\nKeep this key private.")
        lua = build_loader(api_url, slug, key)
        return message(f"Your loader for **{slug}** contains your private license key.", file=(f"nezzx_{slug}_loader.lua", lua.encode("utf-8")))

    if name in {"whitelist", "blacklist"}:
        action = str(opts.get("action", ""))
        target = str(opts.get("user", ""))
        if target in OWNER_IDS and name == "blacklist":
            return message("The owner cannot be blocked.")
        with SessionLocal() as db:
            existing = db.scalar(select(UserFlag).where(UserFlag.user_id == target, UserFlag.flag == name))
            if action == "add" and existing is None:
                db.add(UserFlag(user_id=target, flag=name))
            elif action == "remove" and existing is not None:
                db.delete(existing)
            record(db, user, f"{name}:{action}", target)
            db.commit()
        return message(f"**{name}**: `{action}` for <@{target}>.")

    if name == "forcereset":
        target = str(opts.get("user", ""))
        slug = normalize_slug(str(opts.get("script", "")))
        with SessionLocal() as db:
            lic = get_user_license(db, target, slug)
            if lic is None:
                return message("This user has no active license for this script.")
            lic.device_digest = None
            lic.reset_at = None
            record(db, user, "forcereset", f"license#{lic.id} user={target}")
            db.commit()
        return message(f"Device binding cleared for <@{target}> and `{slug}`.")

    if name == "revoke":
        lic_id = int(opts.get("id", 0))
        with SessionLocal() as db:
            lic = db.get(License, lic_id)
            if lic is None:
                return message("License not found.")
            lic.revoked = True
            record(db, user, "revoke", f"license#{lic.id}")
            db.commit()
        return message(f"License **#{lic_id}** revoked.")

    return message("Unknown command. Use `/help`.")


def boot_database() -> None:
    required = {
        "DISCORD_BOT_TOKEN": BOT_TOKEN,
        "AUTH_SECRET": AES_KEY,
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise RuntimeError("Missing environment settings: " + ", ".join(missing))
    Base.metadata.create_all(bind=engine)
    log.info("NEZZX AUTH started. Database ready.")


def load_discord_identity() -> None:
    """Fetch public verification key, application ID, owner from official Discord API."""
    global APP_ID, PUBLIC_KEY
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    with httpx.Client(timeout=20) as client:
        response = client.get("https://discord.com/api/v10/applications/@me", headers=headers)
        response.raise_for_status()
        data = response.json()
    APP_ID = str(data["id"])
    PUBLIC_KEY = str(data["verify_key"])
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_KEY))
    if not OWNER_IDS:
        owner = (data.get("owner") or {}).get("id")
        if not owner and isinstance(data.get("team"), dict):
            owner = data["team"].get("owner_user_id")
        if owner:
            OWNER_IDS.add(str(owner))
    if not OWNER_IDS:
        raise RuntimeError("Cannot detect owner; set OWNER_IDS to your Discord user ID")
    log.info("Discord app %s ready; owner access configured.", APP_ID)


# ---------------- Slash command declarations (embedded) ----------------
"""Discord slash commands (globally registered; Guild context only)."""
STRING = 3
USER = 6
ATTACHMENT = 11
BOOL = 5

def option(name, description, kind=STRING, required=True, choices=None):
    item = {"type": kind, "name": name, "description": description, "required": required}
    if choices:
        item["choices"] = choices
    return item

COMMANDS = [
    {"name": "ping", "description": "Check NEZZX AUTH response speed"},
    {"name": "panel", "description": "Owner management panel"},
    {"name": "publishpanel", "description": "OWNER: post or refresh the public buyer panel in this channel"},
    {"name": "requests", "description": "OWNER: pending access requests"},
    {"name": "approve", "description": "OWNER: approve an access request and create a license", "options": [option("id", "Request ID", kind=4), option("days", "Days valid (0 = forever, default 30)", kind=4, required=False)]},
    {"name": "deny", "description": "OWNER: reject an access request", "options": [option("id", "Request ID", kind=4)]},
    {"name": "access", "description": "Open buyer access panel"},
    {"name": "upload", "description": "OWNER: upload or replace a Lua script", "options": [option("script", "Script short name"), option("file", "Lua/TXT file", ATTACHMENT)]},
    {"name": "scripts", "description": "View available scripts"},
    {"name": "createkey", "description": "OWNER: create an unclaimed license key", "options": [option("script", "Script name"), option("days", "Lifetime in days (0 = never expires)", kind=4, required=False)]},
    {"name": "grant", "description": "OWNER: create a key for a buyer", "options": [option("user", "Buyer", USER), option("script", "Script name"), option("days", "Lifetime days, 0 = forever", kind=4, required=False)]},
    {"name": "redeem", "description": "Activate a license key on your Discord account", "options": [option("key", "Your private license key")]},
    {"name": "key", "description": "Show your saved key privately", "options": [option("script", "Script name")]},
    {"name": "loader", "description": "Get your Lua loader privately", "options": [option("script", "Script name")]},
    {"name": "resetdevice", "description": "Reset your device binding once every 24h", "options": [option("script", "Script name")]},
    {"name": "blacklist", "description": "OWNER: add/remove a blocked Discord user", "options": [option("action", "Add or remove", choices=[{"name": "add", "value": "add"}, {"name": "remove", "value": "remove"}]), option("user", "Discord user", USER)]},
    {"name": "whitelist", "description": "OWNER: add/remove allowed Discord user", "options": [option("action", "Add or remove", choices=[{"name": "add", "value": "add"}, {"name": "remove", "value": "remove"}]), option("user", "Discord user", USER)]},
    {"name": "revoke", "description": "OWNER: revoke license by its public ID", "options": [option("id", "License ID", kind=4)]},
    {"name": "licenses", "description": "OWNER: recent licenses and status"},
    {"name": "stats", "description": "OWNER: server statistics"},
    {"name": "audit", "description": "OWNER: recent security events"},
    {"name": "forcereset", "description": "OWNER: clear a buyer device lock", "options": [option("user", "Buyer", USER), option("script", "Script name")]},
    {"name": "help", "description": "Show command guide"},
]


# ---------------- Client loader template (embedded) ----------------
LUA_LOADER_TEMPLATE = r'''
-- NEZZX AUTH | Lua Loader v2
-- Generated by NEZZX AUTH. This file contains a personal license key.
local API_URL = __API_URL__
local SCRIPT_NAME = __SCRIPT_NAME__
local LICENSE_KEY = __LICENSE_KEY__

local HttpService = game:GetService("HttpService")

-- Executor APIs might be exposed in the current environment or in getgenv().
-- Resolve globals by name to avoid unresolved-global warnings for syn/http.
local environment = nil
if type(getfenv) == "function" then
    local ok, value = pcall(getfenv)
    if ok and type(value) == "table" then
        environment = value
    end
end

local globalEnvironment = nil
if environment and type(environment.getgenv) == "function" then
    local ok, value = pcall(environment.getgenv)
    if ok and type(value) == "table" then
        globalEnvironment = value
    end
end

local function findApi(name)
    if globalEnvironment and globalEnvironment[name] ~= nil then
        return globalEnvironment[name]
    end
    if environment and environment[name] ~= nil then
        return environment[name]
    end
    if type(_G) == "table" then
        return _G[name]
    end
    return nil
end

local synApi = findApi("syn")
local httpApi = findApi("http")
local requestFn = findApi("request") or findApi("http_request")
if type(requestFn) ~= "function" and type(synApi) == "table" then
    requestFn = synApi.request
end
if type(requestFn) ~= "function" and type(httpApi) == "table" then
    requestFn = httpApi.request
end
assert(type(requestFn) == "function",
    "NEZZX AUTH: This Lua environment does not support HTTP requests")

-- This is an installation identifier if real HWID is unavailable.
-- It is NOT a secure hardware fingerprint.
local function deviceId()
    local hwidFn = findApi("gethwid")
    if type(hwidFn) == "function" then
        local ok, value = pcall(hwidFn)
        if ok and type(value) == "string" and #value >= 8 then
            return "hwid:" .. value
        end
    end

    local isFileFn = findApi("isfile")
    local readFileFn = findApi("readfile")
    local writeFileFn = findApi("writefile")
    assert(type(isFileFn) == "function" and type(readFileFn) == "function"
        and type(writeFileFn) == "function",
        "NEZZX AUTH: gethwid() or a persistent file API is required")

    local filename = "nezzx_auth_device_id.txt"
    local checked, exists = pcall(isFileFn, filename)
    if checked and exists then
        local readOK, value = pcall(readFileFn, filename)
        if readOK and type(value) == "string" and #value >= 16 then
            return "install:" .. value
        end
    end

    local value = HttpService:GenerateGUID(false)
    assert(type(value) == "string" and #value >= 16,
        "NEZZX AUTH: Cannot create installation identifier")
    local saved, errorMessage = pcall(writeFileFn, filename, value)
    assert(saved, "NEZZX AUTH: Cannot save device ID: " .. tostring(errorMessage))
    return "install:" .. value
end

local payload = HttpService:JSONEncode({
    key = LICENSE_KEY,
    device_id = deviceId(),
    script = SCRIPT_NAME,
})

local ok, response = pcall(requestFn, {
    Url = API_URL .. "/api/v1/load",
    Method = "POST",
    Headers = { ["Content-Type"] = "application/json" },
    Body = payload,
})
if not ok then
    error("NEZZX AUTH: HTTP request failed: " .. tostring(response))
end
assert(type(response) == "table", "NEZZX AUTH: Invalid HTTP response")

local status = tonumber(response.StatusCode or response.Status or 0) or 0
local rawBody = response.Body
assert(type(rawBody) == "string", "NEZZX AUTH: Server response has no body (HTTP " .. tostring(status) .. ")")
local parsed, data = pcall(HttpService.JSONDecode, HttpService, rawBody)
assert(parsed and type(data) == "table",
    "NEZZX AUTH: Server returned invalid JSON (HTTP " .. tostring(status) .. ")")
if status ~= 200 or data.ok ~= true then
    error("NEZZX AUTH: " .. tostring(data.error or ("Authorization failed, HTTP " .. tostring(status))))
end
assert(type(data.code) == "string" and #data.code > 0,
    "NEZZX AUTH: The server returned no Lua code")
local compileFn = findApi("loadstring")
assert(type(compileFn) == "function", "NEZZX AUTH: loadstring() is not supported")
local fn, compileError = compileFn(data.code)
assert(type(fn) == "function", "NEZZX AUTH: Lua compile error: " .. tostring(compileError))
return fn()
'''


def build_loader(api_url: str, slug: str, key: str) -> str:
    """Build the same client code for /loader and the public panel button."""
    api_url = api_url.rstrip("/")
    if not api_url.startswith("https://") and not api_url.startswith("http://localhost:"):
        raise ValueError("Loader requires an HTTPS API base URL")
    slug = normalize_slug(slug)
    return (LUA_LOADER_TEMPLATE
            .replace("__API_URL__", json.dumps(api_url))
            .replace("__SCRIPT_NAME__", json.dumps(slug))
            .replace("__LICENSE_KEY__", json.dumps(key)))


def startup_discord_setup() -> None:
    """Global slash command registration. Guild ID is no longer needed."""
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    # Restrict slash commands to Discord guilds (no direct messages).
    payload = [dict(command, contexts=[0], integration_types=[0]) for command in COMMANDS]
    with httpx.Client(timeout=30) as client:
        cmds = client.put(f"https://discord.com/api/v10/applications/{APP_ID}/commands",
                          headers=headers, json=payload)
        cmds.raise_for_status()
        log.info("Registered %s global Discord commands.", len(COMMANDS))


async def connect_discord(app: FastAPI) -> None:
    delay = 2
    while True:
        try:
            if not app.state.discord_ready:
                await asyncio.to_thread(load_discord_identity)
                app.state.discord_ready = True
            await asyncio.to_thread(startup_discord_setup)
            return
        except (httpx.HTTPError, RuntimeError, KeyError, ValueError) as exc:
            log.warning("Discord setup failed (%s). Retrying in %ss.", type(exc).__name__, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    boot_database()
    app.state.discord_ready = False
    setup = asyncio.create_task(connect_discord(app))
    try:
        yield
    finally:
        setup.cancel()
        with suppress(asyncio.CancelledError):
            await setup


app = FastAPI(title="NEZZX AUTH", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
rate_lock = threading.Lock()
rate_buckets: dict[str, deque] = defaultdict(deque)


def throttle(bucket: str, limit: int = 20, window_s: int = 60) -> bool:
    timestamp = time.monotonic()
    with rate_lock:
        if len(rate_buckets) > 5000:
            for old_key in list(rate_buckets)[:1000]:
                if not rate_buckets[old_key] or timestamp - rate_buckets[old_key][-1] > window_s:
                    del rate_buckets[old_key]
        hits = rate_buckets[bucket]
        while hits and timestamp - hits[0] >= window_s:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(timestamp)
        return True


@app.get("/")
def index():
    return {"service": "NEZZX AUTH", "status": "online", "discord": "Use /publishpanel in your server"}


@app.get("/health")
def health():
    return {"status": "ok"}


# Keep strong references to background tasks until they finish.
background_tasks: set[asyncio.Task] = set()


def enqueue_task(coro) -> None:
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)


def instant_result(payload: dict) -> Optional[dict]:
    """Answer interaction types that require no network or database round trips."""
    data = payload.get("data") or {}
    command = data.get("name", "")
    user = user_id_from_interaction(payload)
    owner = user in OWNER_IDS
    if command == "ping":
        result = message("NEZZX AUTH is online.")
    elif command == "panel":
        result = panel(True) if owner else message("Only the owner can open this panel.")
    elif command == "access":
        result = panel(False)
    elif command == "help":
        result = message(embed_obj=embed("NEZZX AUTH | Help", HELP_TEXT))
    elif command == "publishpanel":
        if not owner:
            return {"type": 4, "data": {**message("Only the owner can use this command."), "flags": 64}}
        if not payload.get("guild_id") or not payload.get("channel_id"):
            return {"type": 4, "data": {**message("Run `/publishpanel` in a server text channel."), "flags": 64}}
        # Publish the actual PUBLIC panel *as the HTTP interaction response*.
        # No BOT-token POST /channels/{id}/messages, no webhook PATCH, no 403/429.
        # Anyone with permission to view this channel can use its buttons.
        result = buyer_public_panel()
        return {"type": 4, "data": result}
    elif data.get("custom_id") == "owner:publish":
        result = message("Run `/publishpanel` in the channel where buyers should see it.")
    else:
        return None
    return {"type": 4, "data": {**result, "flags": 64}}


async def edit_original_response(payload: dict, result: dict) -> bool:
    """Fallback for slow operations only; the fast path uses direct callbacks."""
    token = payload["token"]
    url = f"https://discord.com/api/v10/webhooks/{APP_ID}/{token}/messages/@original"
    result = dict(result)
    attached = result.pop("_file", None)
    # Retry only if Discord provides a safe Retry-After value.
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=4.0)) as client:
            for attempt in range(2):
                if attached:
                    filename, content = attached
                    result["attachments"] = [{"id": 0, "filename": filename}]
                    response = await client.patch(url, data={"payload_json": json.dumps(result, ensure_ascii=False)},
                                                  files={"files[0]": (filename, content, "text/plain")})
                else:
                    response = await client.patch(url, json=result)
                if response.is_success:
                    log.info("Reply delivered for interaction id=%s", payload.get("id", "?"))
                    return True
                if response.status_code == 429:
                    delay = None
                    try:
                        raw_delay = response.json().get("retry_after")
                        if isinstance(raw_delay, (int, float)):
                            delay = float(raw_delay)
                    except (ValueError, TypeError, AttributeError):
                        pass
                    if delay is None:
                        try:
                            delay = float(response.headers.get("Retry-After", ""))
                        except (TypeError, ValueError):
                            pass
                    if attempt == 0 and delay is not None and 0 < delay <= 7:
                        log.warning("Discord 429: honoring Retry-After %.2fs, one retry only", delay)
                        await asyncio.sleep(delay)
                        continue
                    log.error("Discord API returned 429, retry later. %s",
                              "Rate-limit response had no usable Retry-After" if delay is None else f"Retry-After={delay}")
                    return False
                # Never leak interaction token or the full webhook URL into logs.
                log.error("Discord reply failed: HTTP %s, code=%s", response.status_code,
                          response.json().get("code") if response.headers.get("content-type", "").startswith("application/json") else "non-json")
                return False
    except httpx.HTTPError as exc:
        log.error("Discord reply network error: %s", type(exc).__name__)
    return False


def direct_response(result: dict, *, private: bool = True) -> Response:
    """Reply from /interactions itself, avoiding rate-limited outbound requests."""
    data = dict(result)
    attached = data.pop("_file", None)
    if private:
        data["flags"] = 64
    body = {"type": 4, "data": data}
    if not attached:
        return JSONResponse(body)
    filename, content = attached
    # A multipart Interaction Callback with a file, supported by Discord's API.
    data["attachments"] = [{"id": 0, "filename": filename}]
    json_blob = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    boundary = "nezzx_" + secrets.token_hex(16)
    sep = ("--" + boundary + "\r\n").encode("ascii")
    close = ("--" + boundary + "--\r\n").encode("ascii")
    encoded_filename = filename.replace('"', '').replace("\r", "").replace("\n", "")
    upload = (sep + b'Content-Disposition: form-data; name="payload_json"\r\n'
              + b'Content-Type: application/json\r\n\r\n' + json_blob + b'\r\n'
              + sep + f'Content-Disposition: form-data; name="files[0]"; filename="{encoded_filename}"\r\n'.encode("utf-8")
              + b'Content-Type: text/plain\r\n\r\n' + content + b'\r\n' + close)
    return Response(content=upload, media_type=f"multipart/form-data; boundary={boundary}")


async def run_interaction(job: asyncio.Task, payload: dict, started: float) -> None:
    """Complete an already-started slow job once (do not run commands twice)."""
    kind = (payload.get("data") or {}).get("name") or (payload.get("data") or {}).get("custom_id") or "unknown"
    try:
        result = await asyncio.wait_for(job, timeout=44)
    except asyncio.TimeoutError:
        log.error("Discord interaction timed out: %s", kind)
        result = message("Command timed out. Check the database and service logs.")
    except Exception:
        log.exception("Discord interaction failed: %s", kind)
        result = message("Command failed. Check the service logs.")
    if not await edit_original_response(payload, result):
        log.error("Unable to complete interaction %s after %.2f s", kind, time.monotonic() - started)
    else:
        log.info("Completed %s in %.2f s", kind, time.monotonic() - started)


@app.post("/interactions")
async def interactions(request: Request):
    if not getattr(request.app.state, "discord_ready", False):
        return JSONResponse({"error": "Discord is connecting"}, status_code=503,
                            headers={"Retry-After": "5"})
    signature = request.headers.get("X-Signature-Ed25519", "")
    timestamp = request.headers.get("X-Signature-Timestamp", "")
    raw = await request.body()
    try:
        if abs(time.time() - int(timestamp)) > 300:
            raise ValueError("stale timestamp")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_KEY)).verify(
            bytes.fromhex(signature), timestamp.encode() + raw)
    except (InvalidSignature, ValueError, TypeError):
        raise HTTPException(401, detail="Invalid Discord signature")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, detail="Invalid JSON")
    if payload.get("type") == 1:
        return JSONResponse({"type": 1})
    data = payload.get("data") or {}
    if payload.get("type") == 3 and data.get("custom_id") == "buyer:redeem":
        return JSONResponse({"type": 9, "data": {"custom_id": "modal:redeem", "title": "Activate your license", "components": [{"type": 18, "label": "License key", "component": {"type": 4, "custom_id": "key", "style": 1, "placeholder": "NZX-...", "required": True, "max_length": 200}}]}})
    if payload.get("type") not in (2, 3, 5):
        return JSONResponse({"type": 4, "data": {"content": "Unsupported interaction", "flags": 64}})

    kind = data.get("name") or data.get("custom_id") or "unknown"
    log.info("Discord interaction received: %s", kind)
    instant = instant_result(payload)
    if instant is not None:
        log.info("Instant reply: %s", kind)
        return JSONResponse(instant)

    public_base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not public_base:
        hostname = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip()
        public_base = "https://" + hostname if hostname else str(request.base_url).rstrip("/")
    started = time.monotonic()
    # For normal, quick database operations, answer in the ORIGINAL interaction
    # callback. This avoids a subsequent PATCH that can fail with Discord 429.
    # For slow operations, keep the SAME running job and finish via webhook.
    job = asyncio.create_task(asyncio.to_thread(lambda: asyncio.run(process_command(payload, public_base))))
    try:
        result = await asyncio.wait_for(asyncio.shield(job), timeout=1.7)
    except asyncio.TimeoutError:
        enqueue_task(run_interaction(job, payload, started))
        return JSONResponse({"type": 4, "data": {
            "content": "Processing your request.",
            "flags": 64, "allowed_mentions": {"parse": []},
        }})
    except Exception:
        log.exception("Discord command failed immediately: %s", kind)
        return direct_response(message("Command failed. Check the service logs."))
    else:
        log.info("Direct reply completed: %s in %.2f s", kind, time.monotonic() - started)
        return direct_response(result)



class LoadRequest(BaseModel):
    key: str = Field(min_length=15, max_length=256)
    device_id: str = Field(min_length=8, max_length=256)
    script: str = Field(min_length=2, max_length=48)


def denied(reason: str, status_code: int = 403) -> JSONResponse:
    return JSONResponse({"ok": False, "error": reason}, status_code=status_code, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/v1/load":
        return denied("Invalid request. Send a JSON object with key, device_id and script.", 422)
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(SQLAlchemyError)
async def database_error(request: Request, exc: SQLAlchemyError):
    # SQL exceptions can include secrets in their parameters.
    log.error("Database error (%s)", type(exc).__name__)
    return denied("Database unavailable. Try again shortly.", 503)


@app.exception_handler(Exception)
async def internal_error(request: Request, exc: Exception):
    incident = secrets.token_hex(6)
    log.error("Internal error %s (%s)", incident, type(exc).__name__)
    return denied(f"Internal service error. Reference {incident}.", 500)


@app.post("/api/v1/load")
def load_script(params: LoadRequest, request: Request):
    # Avoid persistent storage of raw user keys, client IPs or device identifiers.
    try:
        slug = normalize_slug(params.script)
    except ValueError:
        return denied("Invalid script name", 400)
    if not params.key.startswith("NZX-"):
        return denied("Invalid key", 403)
    digest = secret_digest(params.key)
    if not throttle("key:" + digest, limit=24, window_s=60):
        return denied("Too many requests; retry shortly", 429)
    with SessionLocal() as db:
        lic = db.scalar(select(License).where(License.digest == digest))
        if lic is None or not valid_license(lic) or lic.script_slug != slug or not lic.user_id:
            return denied("License invalid, unclaimed or expired")
        if not allowed(db, lic.user_id):
            return denied("User access denied")
        script = db.get(ScriptAsset, slug)
        if script is None:
            return denied("Script not found", 404)
        device_digest = secret_digest("device:" + params.device_id)
        if lic.device_digest is not None and not hmac.compare_digest(lic.device_digest, device_digest):
            record(db, lic.user_id, "device_mismatch", f"license#{lic.id}")
            db.commit()
            return denied("Device mismatch. Use /resetdevice in Discord")

        source = decrypt(script.encrypted_blob, f"script:{slug}:{script.version}")
        if lic.device_digest is None:
            changed = db.execute(
                update(License)
                .where(License.id == lic.id, License.device_digest.is_(None))
                .values(device_digest=device_digest)
            ).rowcount
            if not changed:
                db.refresh(lic)
                if lic.device_digest != device_digest:
                    return denied("Device mismatch. Use /resetdevice in Discord")
        lic.last_loaded_at = now()
        record(db, lic.user_id, "load", f"license#{lic.id} {slug}@{script.version}")
        db.commit()
    return JSONResponse({"ok": True, "version": script.version, "code": source}, headers={"Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


# ---------------- Single-file CLI entrypoint ----------------
if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="NEZZX AUTH: Discord bot + licensing API")
    parser.add_argument("--secret", action="store_true", help="Print one AUTH_SECRET for Render ENV")
    parser.add_argument("--register", action="store_true", help="Manually register global Discord commands")
    args = parser.parse_args()
    if args.secret:
        print("AUTH_SECRET=" + secrets.token_urlsafe(48))
    elif args.register:
        boot_database()
        load_discord_identity()
        startup_discord_setup()
    else:
        uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), workers=1, access_log=False)
