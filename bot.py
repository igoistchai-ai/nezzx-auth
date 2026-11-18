"""NEZZX AUTH | Single-file Discord Lua licensing service.

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

Five protections: Discord Ed25519, owner/whitelist/blacklist controls,
HMAC-indexed licenses, device binding+reset limit, AES-256-GCM at rest.
Security limit: client-executed Lua cannot be made impossible to extract.
The bot stores Lua without executing it. HTTPS is provided by Render.
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
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, func, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nezzx-auth")

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
        raise ValueError("Имя скрипта: 2–48 символов, латиница, цифры, _ или -.")
    return value


def new_license(db: Session, slug: str, user: Optional[str], days: int) -> tuple[License, str]:
    if db.get(ScriptAsset, slug) is None:
        raise ValueError("Скрипт не найден. Сначала /upload.")
    if days < 0 or days > 3650:
        raise ValueError("Срок ключа должен быть от 0 до 3650 дней.")
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
    return {"title": title, "description": description[:4000], "color": color, "footer": {"text": "NEZZX AUTH  •  Protected License System"}}


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
    async with httpx.AsyncClient(timeout=20) as client:
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
                "`/upload` — загрузить или обновить .lua\n"
                "`/createkey` — создать свободный ключ\n"
                "`/grant` — выдать ключ пользователю\n"
                "`/whitelist` / `/blacklist` — управление доступом\n"
                "`/licenses` / `/revoke` — выданные ключи\n"
                "`/stats` / `/audit` — статистика и журнал")
        return message(embed_obj=embed("OWNER • Control Panel", text), components=(
            *buttons_row(button("📨 Заявки", "owner:requests", 1), button("Scripts", "owner:scripts", 1),
                         button("Licenses", "owner:licenses", 1), button("Statistics", "owner:stats", 1)),
            *buttons_row(button("📢 Опубликовать панель", "owner:publish", 3), button("Команды", "owner:help", 2))))
    return buyer_public_panel()


def buyer_public_panel() -> dict:
    # Публичное сообщение без пользовательских секретов.
    return message(
        embed_obj={
            "title": "✦  NEZZX AUTH  |  ACCESS CENTER",
            "description": (
                "**Личный кабинет для доступа к Lua-скриптам**\n"
                "Управляй ключами и устройствами прямо в Discord — без команд и без публичной отправки данных.\n\n"
                "**01 · Получить ключ** — посмотреть уже выданные лицензии.\n"
                "**02 · Активировать** — безопасно привязать новый ключ.\n"
                "**03 · Loader** — получить персональный Lua-файл.\n"
                "**04 · Сброс HWID** — сменить устройство раз в 24 часа.\n"
                "**05 · Мои лицензии** — статус, сроки и привязка.\n\n"
                "Нет ключа? Нажми **Запросить доступ**. Заявку рассмотрит владелец."
            ),
            "color": 0xF1C40F,
            "fields": [
                {"name": "🔒 ПРИВАТНОСТЬ", "value": "Ключи и loader видны только тебе.", "inline": True},
                {"name": "🟡 BUYER", "value": "Роль выдаётся после активации.", "inline": True},
            ],
            "footer": {"text": "NEZZX AUTH • Secure access • Нажми на кнопку ниже"},
        },
        components=(
            buttons_row(button("🔑 Получить ключ", "buyer:get_key", 1),
                        button("✅ Активировать", "buyer:redeem", 3),
                        button("📦 Получить loader", "buyer:get_loader", 1))
            + buttons_row(button("🔄 Сброс HWID", "buyer:reset_hwid", 2),
                          button("📋 Мои лицензии", "buyer:my_licenses", 2),
                          button("✉️ Запросить доступ", "buyer:request_access", 2))
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
        title = "Запросить доступ"
        empty_text = "У тебя уже есть все доступные лицензии либо скрипты пока не загружены."
    else:
        slugs = [lic.script_slug for lic in buyer_licenses(db, user)]
        title = {"key": "Получить ключ", "loader": "Получить loader", "reset": "Сброс HWID"}[action]
        empty_text = "У тебя пока нет активных лицензий. Нажми **Запросить доступ** или активируй полученный ключ."
    if not slugs:
        components = buttons_row(button("✉️ Запросить доступ", "buyer:request_access", 1)) if action != "request" else None
        return message(embed_obj=embed(title, empty_text), components=components)
    total_pages = (len(slugs) - 1) // 25 + 1
    page = max(0, min(page, total_pages - 1))
    if len(slugs) == 1 and action != "request":
        return message("__INTERNAL_SINGLE__:" + action + ":" + slugs[0])
    options_list = [{"label": slug, "value": slug,
                     "description": "Выбрать скрипт • " + {"key": "ключ", "loader": "loader", "reset": "сброс HWID", "request": "запрос доступа"}[action]}
                    for slug in slugs[page * 25:(page + 1) * 25]]
    picker = {"type": 3, "custom_id": f"buyer:select:{action}:{page}",
              "placeholder": "Выбери скрипт…", "min_values": 1, "max_values": 1, "options": options_list}
    components: list[dict] = [{"type": 1, "components": [picker]}]
    if total_pages > 1:
        nav = []
        if page > 0:
            nav.append(button("◀ Назад", f"buyer:page:{action}:{page-1}"))
        if page + 1 < total_pages:
            nav.append(button("Вперёд ▶", f"buyer:page:{action}:{page+1}"))
        components += buttons_row(*nav)
    return message(embed_obj=embed(title, f"Выбери скрипт из списка. Страница **{page+1}/{total_pages}**."),
                   components=components)


def customer_status(db: Session, user: str) -> dict:
    licenses = db.scalars(select(License).where(License.user_id == user).order_by(License.id.desc()).limit(40)).all()
    if not licenses:
        return message(embed_obj=embed("Мои лицензии", "У тебя ещё нет лицензий. Нажми **Запросить доступ** или активируй полученный ключ."),
                       components=buttons_row(button("✉️ Запросить доступ", "buyer:request_access", 1)))
    lines = []
    for lic in licenses[:20]:
        status = "⛔ Отозвана" if lic.revoked else "⌛ Истекла" if not valid_license(lic) else "🟢 Активна"
        expiration = lic.expires_at.strftime("%d.%m.%Y") if lic.expires_at else "Бессрочно"
        device = "Привязано" if lic.device_digest else "Не привязано"
        lines.append(f"**{lic.script_slug}** · #{lic.id}\n{status} · до: {expiration} · HWID: {device}")
    return message(embed_obj=embed("Мои лицензии", "\n\n".join(lines)))


def reset_confirmation(slug: str) -> dict:
    return message(embed_obj=embed("Подтверждение сброса", f"Сбросить HWID для **{slug}**?\n\nПовторный самостоятельный сброс возможен только через **24 часа**. Это действие не меняет ключ."),
                   components=buttons_row(button("✅ Подтвердить", f"buyer:confirmreset:{slug}", 3),
                                          button("Отмена", "buyer:cancel", 2)))


async def publish_panel(guild_id: str, channel_id: str, actor: str) -> dict:
    if not guild_id or not channel_id or not guild_id.isdigit() or not channel_id.isdigit():
        return message("Не удалось определить текстовый канал. Выполни `/publishpanel` в нужном канале.")
    panel_data = buyer_public_panel()
    # Вместо публикации дублей обновляем сохранённое сообщение, если оно доступно.
    with SessionLocal() as db:
        old = db.get(PublicPanel, guild_id)
        old_channel, old_message = (old.channel_id, old.message_id) if old else ("", "")
    result = None
    if old and old_channel == channel_id:
        result = await discord_request("PATCH", f"/channels/{channel_id}/messages/{old_message}", json=panel_data)
    if result is None or not result.is_success:
        result = await discord_request("POST", f"/channels/{channel_id}/messages", json=panel_data)
    if not result.is_success:
        return message("❌ Не удалось отправить панель. Проверь права **View Channel**, **Send Messages**, **Embed Links** и настройки канала.")
    message_id = str(result.json()["id"])
    with SessionLocal() as db:
        row = db.get(PublicPanel, guild_id)
        if row is None:
            db.add(PublicPanel(guild_id=guild_id, channel_id=channel_id, message_id=message_id))
        else:
            row.channel_id, row.message_id, row.updated_at = channel_id, message_id, now()
        record(db, actor, "publishpanel", f"channel={channel_id} message={message_id}")
        db.commit()
    return message(f"✅ Панель покупателей опубликована и доступна всем участникам с доступом к каналу.\n"
                   f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}\n"
                   "Новые публикации командой `/publishpanel` обновят это сообщение, не создавая дубликатов.")


def create_access_request(db: Session, guild_id: str, user: str, slug: str) -> str:
    if db.get(ScriptAsset, slug) is None:
        return "Такого скрипта пока нет."
    if get_user_license(db, user, slug):
        return "У тебя уже есть лицензия на этот скрипт. Нажми **Получить ключ**."
    old = db.scalar(select(AccessRequest).where(AccessRequest.user_id == user,
                    AccessRequest.guild_id == guild_id,
                    AccessRequest.script_slug == slug, AccessRequest.status == "pending"))
    if old:
        return f"📨 Заявка **#{old.id}** уже ожидает подтверждения владельца."
    if not throttle("access_request:" + user, limit=3, window_s=3600):
        return "Слишком много запросов. Повтори через час."
    item = AccessRequest(user_id=user, guild_id=guild_id, script_slug=slug, status="pending")
    db.add(item)
    db.flush()
    record(db, user, "request_access", f"request#{item.id} {slug}")
    db.commit()
    return (f"📨 Заявка **#{item.id}** на **{slug}** отправлена!\n"
            "Владелец видит её в `/requests` и может выдать тебе ключ. После одобрения открой **Получить ключ**.")


def owner_requests(db: Session) -> str:
    rows = db.scalars(select(AccessRequest).where(AccessRequest.status == "pending")
                      .order_by(AccessRequest.id.asc()).limit(20)).all()
    if not rows:
        return "Новых заявок нет."
    body = "\n".join(f"`#{x.id}` • <@{x.user_id}> • `{x.script_slug}` • server `{x.guild_id}`" for x in rows)
    return body + "\n\n`/approve id [days]` — выдать ключ, `/deny id` — отклонить."


def license_listing(db: Session) -> str:
    result = db.scalars(select(License).order_by(License.id.desc()).limit(15)).all()
    if not result:
        return "Лицензий пока нет."
    return "\n".join(f"`#{v.id}` **{v.script_slug}** · {'REVOKED' if v.revoked else 'EXPIRED' if not valid_license(v) else 'ACTIVE'} · {('<@' + v.user_id + '>') if v.user_id else 'unclaimed'}" for v in result)


def script_listing(db: Session) -> str:
    scripts = db.scalars(select(ScriptAsset).order_by(ScriptAsset.slug.asc()).limit(40)).all()
    if not scripts:
        return "Скриптов пока нет. Владелец может добавить их через `/upload`."
    return "\n".join(f"`{s.slug}` • v{s.version}" for s in scripts)


def statistics(db: Session) -> str:
    return (f"Скриптов: **{db.scalar(select(func.count()).select_from(ScriptAsset)) or 0}**\n"
            f"Всего лицензий: **{db.scalar(select(func.count()).select_from(License)) or 0}**\n"
            f"Заблокированных: **{db.scalar(select(func.count()).select_from(UserFlag).where(UserFlag.flag == 'blacklist')) or 0}**\n"
            f"Логов: **{db.scalar(select(func.count()).select_from(AuditLog)) or 0}**")


HELP_TEXT = ("**Покупатель:** нажми кнопки в публичной панели. Либо используй `/access`, `/redeem`, `/key`, `/loader`, `/resetdevice`.\n\n"
             "**Владелец:** `/publishpanel` в канале для покупателей, `/panel`, `/requests`, `/approve id [days]`, `/deny id`, "
             "`/upload script file`, `/createkey script [days]`, `/grant user script [days]`, "
             "`/whitelist action user`, `/blacklist action user`, `/revoke id`, `/forcereset user script`, `/licenses`, `/stats`, `/audit`.\n\n"
             "Все действия с ключами и loader отвечают приватно. Заявки требуют одобрения владельца.")


def modal_text_value(items: list, name: str) -> str:
    # Совместимость со старыми Action Row и новыми Label компонентами Discord.
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
        return message("Неизвестное действие.")
    with SessionLocal() as db:
        if not allowed(db, user):
            return message("Доступ запрещён. Обратись к владельцу.")
        if action == "request":
            return message(create_access_request(db, guild_id, user, slug))
        lic = get_user_license(db, user, slug)
        if lic is None:
            return message("У тебя нет действующей лицензии на этот скрипт. Нажми **Запросить доступ**.")
        if action == "reset":
            if lic.device_digest is None:
                return message("HWID пока не привязан. Сброс не нужен: устройство закрепится при первом запуске loader.")
            return reset_confirmation(slug)
        if action == "confirmreset":
            if lic.device_digest is None:
                return message("HWID уже сброшен или пока не привязан.")
            if lic.reset_at and now() - lic.reset_at < timedelta(hours=24):
                remain = timedelta(hours=24) - (now() - lic.reset_at)
                hours, seconds = divmod(int(remain.total_seconds()), 3600)
                return message(f"⏳ Лимит сброса использован. Повтори через **{hours} ч {seconds // 60} мин**.")
            lic.device_digest = None
            lic.reset_at = now()
            record(db, user, "resetdevice", f"license#{lic.id}")
            db.commit()
            return message("✅ HWID сброшен. Следующий успешный запуск привяжет новое устройство. Следующий сброс — через 24 часа.")
        key = decrypt(lic.key_encrypted, "license-key")
    if action == "key":
        return message(f"🔑 **Твой ключ для {slug}**\n```{key}```\n"
                       "Ответ видишь только ты. Не пересылай ключ другим.")
    lua = (LUA_LOADER_TEMPLATE.replace("__API_URL__", json.dumps(api_url))
           .replace("__SCRIPT_NAME__", json.dumps(slug))
           .replace("__LICENSE_KEY__", json.dumps(key)))
    return message(f"📦 **Loader для {slug}** прикреплён к сообщению.\n"
                   "Файл содержит твой лицензионный ключ — не передавай его другим.",
                   file=(f"nezzx_{slug}_loader.lua", lua.encode("utf-8")))


async def process_command(payload: dict, api_url: str) -> dict:
    user = user_id_from_interaction(payload)
    guild_id = str(payload.get("guild_id", ""))
    if not guild_id:
        return message("Используй команды на Discord-сервере, не в личных сообщениях.")
    data = payload.get("data") or {}
    name = data.get("name", "")
    cid = data.get("custom_id", "")
    opts = options(payload)
    owner = user in OWNER_IDS
    if cid.startswith("owner:") and not owner:
        return message("Нет доступа к панели владельца.")
    if name in {"panel", "publishpanel", "requests", "approve", "deny", "upload", "createkey", "grant", "whitelist", "blacklist", "revoke", "licenses", "stats", "audit", "forcereset"} and not owner:
        return message("⛔ Эта команда только для владельца.")

    # Owner-controlled button pages. No unsafe GET mutation.
    if cid in {"owner:scripts", "owner:licenses", "owner:stats", "owner:requests", "owner:help", "buyer:scripts", "buyer:help"}:
        with SessionLocal() as db:
            mapping = {
                "owner:scripts": ("Scripts", script_listing(db)),
                "owner:licenses": ("Licenses", license_listing(db)),
                "owner:stats": ("Statistics", statistics(db)),
                "owner:requests": ("Заявки покупателей", owner_requests(db)),
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
            return message("Действие отменено.")
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Доступ запрещён. Обратись к владельцу.")
            return customer_status(db, user)

    if cid in {"buyer:get_key", "buyer:get_loader", "buyer:reset_hwid", "buyer:request_access"} or cid.startswith("buyer:page:"):
        if cid.startswith("buyer:page:"):
            parts = cid.split(":")
            if len(parts) != 4 or parts[2] not in {"key", "loader", "reset", "request"}:
                return message("Некорректное действие.")
            action, page = parts[2], min(10000, max(0, int(parts[3])))
        else:
            action = {"buyer:get_key": "key", "buyer:get_loader": "loader",
                      "buyer:reset_hwid": "reset", "buyer:request_access": "request"}[cid]
            page = 0
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Доступ запрещён. Обратись к владельцу.")
            screen = select_screen(db, user, action, page)
        single = screen.get("content", "")
        if single.startswith("__INTERNAL_SINGLE__:"):
            _, action, slug = single.split(":")
            return await selected_action(user, guild_id, action, slug, api_url)
        return screen

    if cid.startswith("buyer:select:"):
        parts = cid.split(":")
        if len(parts) != 4 or parts[2] not in {"key", "loader", "reset", "request"}:
            return message("Некорректный выбор.")
        values = data.get("values") or []
        if len(values) != 1 or not isinstance(values[0], str):
            return message("Выбери один скрипт.")
        try:
            slug = normalize_slug(values[0])
        except ValueError:
            return message("Неправильное имя скрипта.")
        return await selected_action(user, guild_id, parts[2], slug, api_url)

    if cid.startswith("buyer:confirmreset:"):
        slug = normalize_slug(cid.split(":", 2)[2])
        return await selected_action(user, guild_id, "confirmreset", slug, api_url)

    if name == "requests":
        with SessionLocal() as db:
            return message(embed_obj=embed("Заявки покупателей", owner_requests(db)))

    if name in {"approve", "deny"}:
        request_id = int(opts.get("id", 0))
        days = int(opts.get("days", 30))
        if days < 0 or days > 3650:
            return message("Срок: от 0 до 3650 дней (0 — бессрочно).")
        with SessionLocal() as db:
            item = db.scalar(select(AccessRequest).where(AccessRequest.id == request_id).with_for_update())
            if item is None or item.status != "pending":
                return message("Заявка не найдена или уже обработана.")
            if name == "deny":
                item.status = "rejected"
                item.resolved_by, item.resolved_at = user, now()
                record(db, user, "deny_access", f"request#{item.id}")
                db.commit()
                return message(f"⛔ Заявка **#{request_id}** отклонена.")
            if not allowed(db, item.user_id):
                return message("Пользователь заблокирован или отсутствует в whitelist.")
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
        return message(f"✅ Одобрена заявка **#{request_id}**: <@{target_id}> • **{slug}**.\n"
                       "Пользователь может открыть **Получить ключ** и **Получить loader** в публичной панели."
                       + ("\n⚠️ Роль BUYER не выдана — проверь права бота." if not role_ok else "\n🟡 Роль BUYER выдана."))

    if name == "help":
        return message(embed_obj=embed("Help", HELP_TEXT))
    if name == "access":
        await ensure_buyer_role(guild_id)
        return panel(False)
    if name == "panel":
        await ensure_buyer_role(guild_id)
        return panel(True)

    if name == "upload":
        slug = normalize_slug(str(opts.get("script", "")))
        attachment_id = str(opts.get("file", ""))
        attachment = (((payload.get("data") or {}).get("resolved") or {}).get("attachments") or {}).get(attachment_id)
        if not attachment:
            return message("Вложение не найдено в данных Discord.")
        filename = attachment.get("filename", "").lower()
        if not (filename.endswith(".lua") or filename.endswith(".txt")):
            return message("Принимаются только файлы .lua и .txt.")
        if int(attachment.get("size", MAX_SCRIPT_BYTES + 1)) > MAX_SCRIPT_BYTES:
            return message(f"Слишком большой файл. Максимум {MAX_SCRIPT_BYTES // 1024} KiB.")
        url = str(attachment.get("url", ""))
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in {"cdn.discordapp.com", "media.discordapp.net"}:
            return message("Неизвестный адрес вложения; отклонено.")
        async with httpx.AsyncClient(timeout=16, follow_redirects=False) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_SCRIPT_BYTES:
                        return message("Пустой или слишком большой файл.")
                    chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw:
            return message("Пустой файл.")
        try:
            source = raw.decode("utf-8-sig")
        except UnicodeError:
            return message("Файл должен быть в кодировке UTF-8.")
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
        return message(embed_obj=embed("✓ Script secured", f"**{slug}** обновлён до версии **v{version}**.\nLua сохранён зашифрованным в PostgreSQL. Уже выданные лицензии получат новую версию при следующем запуске."))

    if name in {"scripts", "licenses", "stats", "audit"}:
        with SessionLocal() as db:
            if name == "audit":
                recent = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(15)).all()
                body = "\n".join(f"`{v.created_at.strftime('%m-%d %H:%M')}` {v.action} / {v.actor}: {v.detail}" for v in recent) or "Журнал пуст."
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
            role_note = "\nBUYER role: added." if ok else "\n⚠️ Не удалось выдать BUYER: проверь права и положение роли бота."
        return message(f"🔑 **License #{lic_id}** для `{slug}`\n```{key}```\n{'User: <@' + target + '>' if target else 'Unclaimed key'}\nExpires: {'never' if not days else str(days) + ' days'}{role_note}\n**Никому не показывай этот приватный ответ.**")

    if name == "redeem" or cid == "modal:redeem":
        key = str(opts.get("key", "")) if name == "redeem" else modal_text_value((payload.get("data") or {}).get("components") or [], "key")
        if len(key) > 256:
            return message("Неверный формат ключа.")
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Доступ запрещён. Обратись к владельцу.")
            lic = db.scalar(select(License).where(License.digest == secret_digest(key)))
            if lic is None or not valid_license(lic):
                return message("Неверный, отозванный или просроченный ключ.")
            if lic.user_id not in (None, user):
                return message("Этот ключ уже закреплён за другим Discord-пользователем.")
            if lic.user_id is None:
                # Race-safe claim even under concurrent submissions.
                changed = db.execute(update(License).where(License.id == lic.id, License.user_id.is_(None)).values(user_id=user)).rowcount
                db.commit()
                if not changed:
                    lic = db.get(License, lic.id)
                    if lic.user_id != user:
                        return message("Ключ уже занят другим пользователем.")
            record(db, user, "redeem", f"license#{lic.id} {lic.script_slug}")
            db.commit()
            slug = lic.script_slug
        role_ok = await assign_buyer(user, guild_id)
        return message(f"✅ Ключ активирован. Скрипт: **{slug}**.\nИспользуй `/key {slug}` и `/loader {slug}`." + ("\n⚠️ Роль BUYER не назначена: попроси владельца проверить права бота." if not role_ok else "\n🟡 Роль BUYER выдана."))

    if name in {"key", "loader", "resetdevice"}:
        slug = normalize_slug(str(opts.get("script", "")))
        with SessionLocal() as db:
            if not allowed(db, user):
                return message("Доступ запрещён. Обратись к владельцу.")
            lic = get_user_license(db, user, slug)
            if lic is None:
                return message("Нет действующей лицензии. Введи ключ через `/redeem` или `/access`.")
            if name == "resetdevice":
                if lic.device_digest is None:
                    return message("Для этой лицензии устройство ещё не привязано.")
                if lic.reset_at and now() - lic.reset_at < timedelta(hours=24):
                    remain = timedelta(hours=24) - (now() - lic.reset_at)
                    hours, seconds = divmod(int(remain.total_seconds()), 3600)
                    return message(f"Сброс уже использован. Повтори через {hours} ч {seconds // 60} мин.")
                lic.device_digest = None
                lic.reset_at = now()
                record(db, user, "resetdevice", f"license#{lic.id}")
                db.commit()
                return message("✅ Привязка сброшена. Следующий успешный запуск закрепит новое устройство. Следующий сброс — через 24 часа.")
            key = decrypt(lic.key_encrypted, "license-key")
        if name == "key":
            return message(f"🔑 Твой ключ для **{slug}**:\n```{key}```\n**Не публикуй этот ключ.**")
        template = LUA_LOADER_TEMPLATE
        lua = template.replace("__API_URL__", json.dumps(api_url)).replace("__SCRIPT_NAME__", json.dumps(slug)).replace("__LICENSE_KEY__", json.dumps(key))
        return message(f"✅ Loader для **{slug}**. Файл содержит твой личный ключ — не передавай другим.", file=(f"nezzx_{slug}_loader.lua", lua.encode("utf-8")))

    if name in {"whitelist", "blacklist"}:
        action = str(opts.get("action", ""))
        target = str(opts.get("user", ""))
        if target in OWNER_IDS and name == "blacklist":
            return message("Владельца нельзя внести в blacklist.")
        with SessionLocal() as db:
            existing = db.scalar(select(UserFlag).where(UserFlag.user_id == target, UserFlag.flag == name))
            if action == "add" and existing is None:
                db.add(UserFlag(user_id=target, flag=name))
            elif action == "remove" and existing is not None:
                db.delete(existing)
            record(db, user, f"{name}:{action}", target)
            db.commit()
        return message(f"✅ **{name}**: `{action}` для <@{target}>.")

    if name == "forcereset":
        target = str(opts.get("user", ""))
        slug = normalize_slug(str(opts.get("script", "")))
        with SessionLocal() as db:
            lic = get_user_license(db, target, slug)
            if lic is None:
                return message("У пользователя нет действующей лицензии для этого скрипта.")
            lic.device_digest = None
            lic.reset_at = None
            record(db, user, "forcereset", f"license#{lic.id} user={target}")
            db.commit()
        return message(f"✅ Привязка <@{target}> для `{slug}` принудительно сброшена.")

    if name == "revoke":
        lic_id = int(opts.get("id", 0))
        with SessionLocal() as db:
            lic = db.get(License, lic_id)
            if lic is None:
                return message("Лицензия не найдена.")
            lic.revoked = True
            record(db, user, "revoke", f"license#{lic.id}")
            db.commit()
        return message(f"✅ Лицензия **#{lic_id}** отозвана. Следующие загрузки будут запрещены.")

    return message("Неизвестная команда. Используй `/help`.")


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
-- NEZZX AUTH | Lua loader
-- The Discord /loader command generates this file with actual URL, script and key.
local API_URL = __API_URL__
local SCRIPT_NAME = __SCRIPT_NAME__
local LICENSE_KEY = __LICENSE_KEY__

local HttpService = game:GetService("HttpService")
local requestFn = request or http_request or (syn and syn.request) or (http and http.request)
assert(type(requestFn) == "function", "Your Lua environment does not expose HTTP requests")

-- A persistent installation identifier, not a cryptographic hardware fingerprint.
local function deviceId()
    if type(gethwid) == "function" then
        local ok, value = pcall(gethwid)
        if ok and type(value) == "string" and #value >= 8 then
            return "hwid:" .. value
        end
    end
    if type(isfile) ~= "function" or type(readfile) ~= "function" or type(writefile) ~= "function" then
        error("Persistent file API (isfile/readfile/writefile) or gethwid is required")
    end
    local filename = "nezzx_auth_device_id.txt"
    local ok, exists = pcall(isfile, filename)
    if ok and exists then
        local readOK, value = pcall(readfile, filename)
        if readOK and type(value) == "string" and #value >= 16 then
            return "install:" .. value
        end
    end
    local value = HttpService:GenerateGUID(false)
    local saved = pcall(writefile, filename, value)
    assert(saved, "Cannot save device ID. Check the Lua environment's file permissions")
    return "install:" .. value
end

local body = HttpService:JSONEncode({
    key = LICENSE_KEY,
    device_id = deviceId(),
    script = SCRIPT_NAME
})
local ok, response = pcall(requestFn, {
    Url = API_URL .. "/api/v1/load",
    Method = "POST",
    Headers = { ["Content-Type"] = "application/json" },
    Body = body
})
assert(ok and type(response) == "table", "Authorization service is temporarily unavailable")

local status = tonumber(response.StatusCode or response.Status or 0)
local dataOK, data = pcall(HttpService.JSONDecode, HttpService, response.Body or "")
assert(dataOK and type(data) == "table", "Invalid authorization response")
if status ~= 200 or not data.ok then
    error("NEZZX AUTH: " .. tostring(data.error or "Authorization denied"))
end

local fn, compileError = loadstring(data.code)
assert(fn, "Lua compile error: " .. tostring(compileError))
return fn()
'''

def startup_discord_setup() -> None:
    """Global slash command registration. Guild ID is no longer needed."""
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    # Restrict slash commands to Discord guilds (no direct messages).
    payload = [dict(command, contexts=[0], integration_types=[0]) for command in COMMANDS]
    with httpx.Client(timeout=30) as client:
        cmds = client.put(f"https://discord.com/api/v10/applications/{APP_ID}/commands",
                          headers=headers, json=payload)
        if not cmds.is_success:
            log.warning("Command registration failed: %s %s", cmds.status_code, cmds.text[:250])
        else:
            log.info("Registered %s global Discord commands.", len(COMMANDS))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    boot_database()
    # Public verification key and app ID are loaded before requests are served.
    await asyncio.to_thread(load_discord_identity)
    try:
        await asyncio.to_thread(startup_discord_setup)
    except Exception as exc:
        log.warning("Discord command registration failed; check bot permissions: %s", type(exc).__name__)
    yield


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


async def edit_deferred(payload: dict, result: dict) -> None:
    token = payload["token"]
    url = f"https://discord.com/api/v10/webhooks/{APP_ID}/{token}/messages/@original"
    attached = result.pop("_file", None)
    async with httpx.AsyncClient(timeout=18) as client:
        if attached:
            filename, content = attached
            result["attachments"] = [{"id": 0, "filename": filename}]
            response = await client.patch(url, data={"payload_json": json.dumps(result)}, files={"files[0]": (filename, content, "text/plain")})
        else:
            response = await client.patch(url, json=result)
    if response.status_code >= 400:
        log.warning("Discord webhook edit failed: %s %s", response.status_code, response.text[:160])


async def handle_deferred(payload: dict, api_url: str) -> None:
    try:
        result = await process_command(payload, api_url)
    except Exception as exc:
        # Never include exception details (keys, paths, DB data) in user-visible errors.
        log.exception("Interaction handler failed: %s", type(exc).__name__)
        result = message("⚠️ Операция не завершена. Проверь параметры и журнал сервиса.")
    try:
        await edit_deferred(payload, result)
    except Exception as exc:
        log.warning("Unable to answer interaction: %s", type(exc).__name__)


@app.post("/interactions")
async def interactions(request: Request):
    signature = request.headers.get("X-Signature-Ed25519", "")
    timestamp = request.headers.get("X-Signature-Timestamp", "")
    raw = await request.body()
    try:
        # Reject stale replayed signed interaction messages.
        if abs(time.time() - int(timestamp)) > 300:
            raise ValueError("stale timestamp")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_KEY)).verify(bytes.fromhex(signature), timestamp.encode() + raw)
    except (InvalidSignature, ValueError, TypeError):
        raise HTTPException(401, detail="Invalid Discord signature")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, detail="Invalid JSON")
    if payload.get("type") == 1:
        return JSONResponse({"type": 1})
    if payload.get("type") == 3 and (payload.get("data") or {}).get("custom_id") == "buyer:redeem":
        return JSONResponse({"type": 9, "data": {"custom_id": "modal:redeem", "title": "Activate your license", "components": [{"type": 18, "label": "License key", "component": {"type": 4, "custom_id": "key", "style": 1, "placeholder": "NZX-...", "required": True, "max_length": 200}}]}})
    if payload.get("type") not in (2, 3, 5):
        return JSONResponse({"type": 4, "data": {"content": "Unsupported interaction", "flags": 64}})
    public_base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not public_base:
        hostname = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "").strip()
        if hostname:
            public_base = "https://" + hostname
        else:
            # In local development only; Render provides RENDER_EXTERNAL_HOSTNAME.
            public_base = str(request.base_url).rstrip("/")
    asyncio.create_task(handle_deferred(payload, public_base))
    return JSONResponse({"type": 5, "data": {"flags": 64}})


class LoadRequest(BaseModel):
    key: str = Field(min_length=15, max_length=256)
    device_id: str = Field(min_length=8, max_length=256)
    script: str = Field(min_length=2, max_length=48)


def denied(reason: str, status_code: int = 403) -> JSONResponse:
    return JSONResponse({"ok": False, "error": reason}, status_code=status_code, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


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
        if lic.device_digest is None:
            updated = db.execute(update(License).where(License.id == lic.id, License.device_digest.is_(None)).values(device_digest=device_digest)).rowcount
            db.commit()
            if not updated:
                db.refresh(lic)
                if lic.device_digest != device_digest:
                    return denied("Device mismatch. Use /resetdevice in Discord")
        elif not hmac.compare_digest(lic.device_digest, device_digest):
            record(db, lic.user_id, "device_mismatch", f"license#{lic.id}")
            db.commit()
            return denied("Device mismatch. Use /resetdevice in Discord")
        lic.last_loaded_at = now()
        record(db, lic.user_id, "load", f"license#{lic.id} {slug}@{script.version}")
        db.commit()
        source = decrypt(script.encrypted_blob, f"script:{slug}:{script.version}")
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
