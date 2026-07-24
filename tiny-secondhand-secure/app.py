#!/usr/bin/env python3
"""Tiny Second-hand Shopping Platform - standard-library secure coding project.

Runs with Python 3.10+ and no third-party packages.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import parse_qs, quote, urlencode, urlparse
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TINYMARKET_DB", BASE_DIR / "tiny_market.db"))
SESSION_TTL = 8 * 60 * 60
MAX_BODY = 64 * 1024
PBKDF2_ITERATIONS = 310_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("tiny-market")


@dataclass
class Response:
    body: bytes
    status: int = 200
    headers: list[tuple[str, str]] | None = None

    @classmethod
    def html(cls, text: str, status: int = 200, headers=None) -> "Response":
        return cls(text.encode("utf-8"), status, headers or [])

    @classmethod
    def text(cls, text: str, status: int = 200, headers=None) -> "Response":
        return cls(text.encode("utf-8"), status, headers or [])

    @classmethod
    def redirect(cls, location: str) -> "Response":
        return cls(b"", 303, [("Location", location)])


class RateLimiter:
    """Simple process-local fixed-window limiter for a small demo deployment."""

    def __init__(self):
        self.hits: dict[tuple[str, str], list[float]] = {}

    def allow(self, ip: str, action: str, limit: int, window: int) -> bool:
        now = time.time()
        key = (ip, action)
        recent = [t for t in self.hits.get(key, []) if now - t < window]
        if len(recent) >= limit:
            self.hits[key] = recent
            return False
        recent.append(now)
        self.hits[key] = recent
        return True


limiter = RateLimiter()


def now_ts() -> int:
    return int(time.time())


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db() -> None:
    schema = (BASE_DIR / "schema.sql").read_text(encoding="utf-8")
    with get_db() as conn:
        conn.executescript(schema)


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def password_verify(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def password_error(password: str) -> str | None:
    if len(password) < 10:
        return "비밀번호는 10자 이상이어야 합니다."
    if len(password) > 128:
        return "비밀번호는 128자를 넘을 수 없습니다."
    if not re.search(r"[A-Z]", password):
        return "비밀번호에 영문 대문자를 포함하세요."
    if not re.search(r"[a-z]", password):
        return "비밀번호에 영문 소문자를 포함하세요."
    if not re.search(r"\d", password):
        return "비밀번호에 숫자를 포함하세요."
    return None


def e(value) -> str:
    return html.escape(str(value), quote=True)


def parse_form(environ) -> dict[str, str]:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length > MAX_BODY:
        raise ValueError("요청 본문이 너무 큽니다.")
    raw = environ["wsgi.input"].read(length).decode("utf-8", errors="strict")
    parsed = parse_qs(raw, keep_blank_values=True, strict_parsing=False)
    return {k: v[-1] if v else "" for k, v in parsed.items()}


def parse_cookie(environ) -> dict[str, str]:
    cookie = SimpleCookie()
    try:
        cookie.load(environ.get("HTTP_COOKIE", ""))
    except Exception:
        return {}
    return {k: morsel.value for k, morsel in cookie.items()}


def make_session(user_id: int | None = None) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions(token, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (token, user_id, csrf, now_ts() + SESSION_TTL, iso_now()),
        )
    return token, csrf


def delete_session(token: str | None) -> None:
    if not token:
        return
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def load_session(environ) -> tuple[sqlite3.Row | None, bool]:
    cookies = parse_cookie(environ)
    token = cookies.get("tm_session")
    if token:
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token = ? AND expires_at > ?", (token, now_ts())
            ).fetchone()
            if row:
                return row, False
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    new_token, _ = make_session()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE token = ?", (new_token,)).fetchone()
    return row, True


def current_user(session: sqlite3.Row | None) -> sqlite3.Row | None:
    if not session or session["user_id"] is None:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def session_cookie(token: str, expired: bool = False) -> tuple[str, str]:
    secure = os.environ.get("SECURE_COOKIE", "0") == "1"
    parts = [f"tm_session={'' if expired else token}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if secure:
        parts.append("Secure")
    if expired:
        parts.append("Max-Age=0")
    else:
        parts.append(f"Max-Age={SESSION_TTL}")
    return ("Set-Cookie", "; ".join(parts))


def csrf_input(session: sqlite3.Row) -> str:
    return f'<input type="hidden" name="csrf_token" value="{e(session["csrf_token"])}">'


def require_csrf(form: dict[str, str], session: sqlite3.Row) -> bool:
    return hmac.compare_digest(form.get("csrf_token", ""), session["csrf_token"])


def flash_redirect(session: sqlite3.Row, location: str, message: str, kind: str = "info") -> Response:
    with get_db() as conn:
        conn.execute("UPDATE sessions SET flash = ?, flash_kind = ? WHERE token = ?", (message, kind, session["token"]))
    return Response.redirect(location)


def pop_flash(session: sqlite3.Row) -> tuple[str | None, str | None]:
    message, kind = session["flash"], session["flash_kind"]
    if message:
        with get_db() as conn:
            conn.execute("UPDATE sessions SET flash = NULL, flash_kind = NULL WHERE token = ?", (session["token"],))
    return message, kind


def base_page(title: str, content: str, session: sqlite3.Row, user: sqlite3.Row | None) -> str:
    flash, flash_kind = pop_flash(session)
    auth_nav = (
        f'<a href="/messages">메시지</a><a href="/transfer">포인트 송금</a>'
        f'<span class="user-chip">{e(user["display_name"])} · {user["balance"]:,}P</span>'
        + ('<a href="/admin">관리자</a>' if user["is_admin"] else '')
        + f'<form class="inline" method="post" action="/logout">{csrf_input(session)}<button class="link-button">로그아웃</button></form>'
        if user
        else '<a href="/login">로그인</a><a href="/register">회원가입</a>'
    )
    flash_html = f'<div class="flash {e(flash_kind or "info")}">{e(flash)}</div>' if flash else ""
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} - Tiny Market</title><link rel="stylesheet" href="/static/style.css"><script src="/static/app.js" defer></script></head>
<body><header><div class="wrap header-inner"><a class="brand" href="/">Tiny Market</a><nav><a href="/">상품</a>{'<a href="/products/new">상품 등록</a>' if user else ''}{auth_nav}</nav></div></header>
<main class="wrap">{flash_html}{content}</main><footer><div class="wrap">교육용 보안 중고거래 플랫폼 · 실제 금전 거래 금지</div></footer></body></html>"""


def error_page(status: int, message: str, session, user) -> Response:
    content = f'<section class="panel"><h1>{status}</h1><p>{e(message)}</p><p><a class="button" href="/">홈으로</a></p></section>'
    return Response.html(base_page("오류", content, session, user), status)


def validate_image_url(value: str) -> bool:
    if not value:
        return True
    if len(value) > 500:
        return False
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def form_row(label: str, name: str, value: str = "", typ: str = "text", attrs: str = "") -> str:
    return f'<label>{e(label)}<input type="{e(typ)}" name="{e(name)}" value="{e(value)}" {attrs}></label>'


def route_home(environ, session, user, **kwargs) -> Response:
    query = parse_qs(environ.get("QUERY_STRING", ""))
    q = (query.get("q", [""])[0] or "").strip()[:50]
    with get_db() as conn:
        if q:
            pattern = f"%{like_escape(q)}%"
            products = conn.execute(
                """SELECT p.*, u.display_name seller_name FROM products p JOIN users u ON u.id=p.seller_id
                   WHERE p.hidden=0 AND u.active=1 AND (p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\')
                   ORDER BY p.id DESC""",
                (pattern, pattern),
            ).fetchall()
        else:
            products = conn.execute(
                """SELECT p.*, u.display_name seller_name FROM products p JOIN users u ON u.id=p.seller_id
                   WHERE p.hidden=0 AND u.active=1 ORDER BY p.id DESC"""
            ).fetchall()
    cards = []
    for p in products:
        img = f'<img src="{e(p["image_url"])}" alt="상품 이미지">' if p["image_url"] else '<div class="placeholder">NO IMAGE</div>'
        sold = '<span class="badge sold">판매완료</span>' if p["sold"] else '<span class="badge">판매중</span>'
        cards.append(f'''<article class="card"><a href="/products/{p["id"]}">{img}<div class="card-body"><div>{sold}</div><h2>{e(p["title"])}</h2><p class="price">{p["price"]:,}P</p><p class="muted">판매자 {e(p["seller_name"])}</p></div></a></article>''')
    content = f'''<section class="hero"><h1>작고 안전한 중고거래 실습 플랫폼</h1><p>회원가입, 상품, 메시지, 신고, 포인트 송금, 검색, 관리자 기능을 구현했습니다.</p></section>
<form class="search" method="get" action="/"><input name="q" maxlength="50" value="{e(q)}" placeholder="상품 검색"><button>검색</button></form>
<section class="grid">{''.join(cards) if cards else '<p class="empty">등록된 상품이 없습니다.</p>'}</section>'''
    return Response.html(base_page("상품 목록", content, session, user))


def route_register(environ, session, user, **kwargs) -> Response:
    if user:
        return Response.redirect("/")
    if environ["REQUEST_METHOD"] == "POST":
        ip = environ.get("REMOTE_ADDR", "unknown")
        if not limiter.allow(ip, "register", 5, 600):
            return error_page(429, "회원가입 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", session, user)
        form = parse_form(environ)
        if not require_csrf(form, session):
            return error_page(400, "CSRF 검증에 실패했습니다.", session, user)
        username = form.get("username", "").strip()
        display_name = form.get("display_name", "").strip()
        password = form.get("password", "")
        error = None
        if not USERNAME_RE.fullmatch(username):
            error = "아이디는 영문, 숫자, 밑줄 3~20자로 입력하세요."
        elif not 2 <= len(display_name) <= 30:
            error = "표시 이름은 2~30자로 입력하세요."
        else:
            error = password_error(password)
        if error:
            return flash_redirect(session, "/register", error, "error")
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users(username, display_name, password_hash, balance, active, is_admin, created_at) VALUES (?, ?, ?, 100000, 1, 0, ?)",
                    (username, display_name, password_hash(password), iso_now()),
                )
        except sqlite3.IntegrityError:
            return flash_redirect(session, "/register", "이미 사용 중인 아이디입니다.", "error")
        return flash_redirect(session, "/login", "회원가입이 완료되었습니다.", "success")
    content = f'''<section class="panel narrow"><h1>회원가입</h1><form method="post">{csrf_input(session)}
{form_row('아이디', 'username', attrs='required minlength="3" maxlength="20" pattern="[A-Za-z0-9_]+"')}
{form_row('표시 이름', 'display_name', attrs='required minlength="2" maxlength="30"')}
{form_row('비밀번호', 'password', typ='password', attrs='required minlength="10" maxlength="128"')}
<p class="help">10자 이상, 영문 대문자·소문자·숫자를 포함하세요.</p><button class="button">가입하기</button></form></section>'''
    return Response.html(base_page("회원가입", content, session, user))


def route_login(environ, session, user, **kwargs) -> Response:
    if user:
        return Response.redirect("/")
    if environ["REQUEST_METHOD"] == "POST":
        ip = environ.get("REMOTE_ADDR", "unknown")
        if not limiter.allow(ip, "login", 10, 300):
            return error_page(429, "로그인 요청이 너무 많습니다. 잠시 후 다시 시도하세요.", session, user)
        form = parse_form(environ)
        if not require_csrf(form, session):
            return error_page(400, "CSRF 검증에 실패했습니다.", session, user)
        username = form.get("username", "").strip()
        password = form.get("password", "")
        with get_db() as conn:
            found = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # Same generic error prevents user enumeration.
        if not found or not found["active"] or not password_verify(password, found["password_hash"]):
            time.sleep(0.12)
            return flash_redirect(session, "/login", "아이디 또는 비밀번호가 올바르지 않습니다.", "error")
        old_token = session["token"]
        delete_session(old_token)
        new_token, _ = make_session(found["id"])
        resp = Response.redirect("/")
        resp.headers.append(session_cookie(new_token))
        return resp
    content = f'''<section class="panel narrow"><h1>로그인</h1><form method="post">{csrf_input(session)}
{form_row('아이디', 'username', attrs='required maxlength="20"')}{form_row('비밀번호', 'password', typ='password', attrs='required maxlength="128"')}
<button class="button">로그인</button></form></section>'''
    return Response.html(base_page("로그인", content, session, user))


def route_logout(environ, session, user, **kwargs) -> Response:
    if environ["REQUEST_METHOD"] != "POST":
        return error_page(405, "허용되지 않은 요청입니다.", session, user)
    form = parse_form(environ)
    if not require_csrf(form, session):
        return error_page(400, "CSRF 검증에 실패했습니다.", session, user)
    delete_session(session["token"])
    resp = Response.redirect("/")
    resp.headers.append(session_cookie("", expired=True))
    return resp


def require_login(session, user) -> Response | None:
    if not user:
        return flash_redirect(session, "/login", "로그인이 필요합니다.", "error")
    if not user["active"]:
        delete_session(session["token"])
        return Response.redirect("/login")
    return None


def route_product_new(environ, session, user, **kwargs) -> Response:
    denied = require_login(session, user)
    if denied:
        return denied
    if environ["REQUEST_METHOD"] == "POST":
        form = parse_form(environ)
        if not require_csrf(form, session):
            return error_page(400, "CSRF 검증에 실패했습니다.", session, user)
        title = form.get("title", "").strip()
        description = form.get("description", "").strip()
        image_url = form.get("image_url", "").strip()
        try:
            price = int(form.get("price", ""))
        except ValueError:
            price = -1
        if not 2 <= len(title) <= 80:
            return flash_redirect(session, "/products/new", "상품명은 2~80자로 입력하세요.", "error")
        if not 5 <= len(description) <= 2000:
            return flash_redirect(session, "/products/new", "설명은 5~2000자로 입력하세요.", "error")
        if not 0 <= price <= 100_000_000:
            return flash_redirect(session, "/products/new", "가격 범위가 올바르지 않습니다.", "error")
        if not validate_image_url(image_url):
            return flash_redirect(session, "/products/new", "이미지 URL은 http 또는 https 주소만 허용합니다.", "error")
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO products(seller_id,title,description,price,image_url,sold,hidden,created_at) VALUES(?,?,?,?,?,0,0,?)",
                (user["id"], title, description, price, image_url or None, iso_now()),
            )
            product_id = cur.lastrowid
        return flash_redirect(session, f"/products/{product_id}", "상품이 등록되었습니다.", "success")
    content = f'''<section class="panel"><h1>상품 등록</h1><form method="post">{csrf_input(session)}
{form_row('상품명', 'title', attrs='required minlength="2" maxlength="80"')}
<label>상품 설명<textarea name="description" required minlength="5" maxlength="2000"></textarea></label>
{form_row('가격(포인트)', 'price', typ='number', attrs='required min="0" max="100000000"')}
{form_row('이미지 URL(선택)', 'image_url', typ='url', attrs='maxlength="500" placeholder="https://..."')}
<button class="button">등록하기</button></form></section>'''
    return Response.html(base_page("상품 등록", content, session, user))


def get_product(product_id: int, include_hidden: bool = False):
    with get_db() as conn:
        sql = """SELECT p.*, u.display_name seller_name, u.active seller_active
                 FROM products p JOIN users u ON u.id=p.seller_id WHERE p.id=?"""
        p = conn.execute(sql, (product_id,)).fetchone()
    if p and (include_hidden or not p["hidden"]):
        return p
    return None


def route_product_detail(environ, session, user, product_id: int, **kwargs) -> Response:
    product = get_product(product_id, bool(user and user["is_admin"]))
    if not product:
        return error_page(404, "상품을 찾을 수 없습니다.", session, user)
    img = f'<img class="detail-img" src="{e(product["image_url"])}" alt="상품 이미지">' if product["image_url"] else '<div class="detail-img placeholder">NO IMAGE</div>'
    actions = ""
    if user:
        if user["id"] == product["seller_id"] or user["is_admin"]:
            actions += f'''<form class="inline" method="post" action="/products/{product_id}/toggle-sold">{csrf_input(session)}<button class="button secondary">판매 상태 변경</button></form>
<form class="inline" method="post" action="/products/{product_id}/delete" onsubmit="return confirm('삭제할까요?')">{csrf_input(session)}<button class="button danger">삭제</button></form>'''
        if user["id"] != product["seller_id"]:
            params = urlencode({"to": product["seller_id"], "product": product_id})
            actions += f'<a class="button" href="/messages/new?{params}">판매자에게 메시지</a>'
            actions += f'''<form class="inline" method="post" action="/reports/product/{product_id}">{csrf_input(session)}<input type="hidden" name="reason" value="의심스러운 상품"><button class="button secondary">상품 신고</button></form>
<form class="inline" method="post" action="/reports/user/{product["seller_id"]}">{csrf_input(session)}<input type="hidden" name="reason" value="의심스러운 사용자"><button class="button secondary">판매자 신고</button></form>'''
    content = f'''<section class="detail panel"><div>{img}</div><div><div class="badge">{'판매완료' if product["sold"] else '판매중'}</div>
<h1>{e(product["title"])}</h1><p class="price">{product["price"]:,}P</p><p class="muted">판매자 {e(product["seller_name"])}</p>
<div class="description">{e(product["description"]).replace(chr(10), '<br>')}</div><div class="actions">{actions}</div></div></section>'''
    return Response.html(base_page(product["title"], content, session, user))


def post_guard(environ, session, user) -> tuple[dict[str, str] | None, Response | None]:
    denied = require_login(session, user)
    if denied:
        return None, denied
    if environ["REQUEST_METHOD"] != "POST":
        return None, error_page(405, "허용되지 않은 요청입니다.", session, user)
    form = parse_form(environ)
    if not require_csrf(form, session):
        return None, error_page(400, "CSRF 검증에 실패했습니다.", session, user)
    return form, None


def route_toggle_sold(environ, session, user, product_id: int, **kwargs) -> Response:
    form, denied = post_guard(environ, session, user)
    if denied:
        return denied
    with get_db() as conn:
        p = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not p:
            return error_page(404, "상품을 찾을 수 없습니다.", session, user)
        if p["seller_id"] != user["id"] and not user["is_admin"]:
            return error_page(403, "다른 사용자의 상품을 변경할 수 없습니다.", session, user)
        conn.execute("UPDATE products SET sold = CASE sold WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (product_id,))
    return flash_redirect(session, f"/products/{product_id}", "판매 상태를 변경했습니다.", "success")


def route_delete_product(environ, session, user, product_id: int, **kwargs) -> Response:
    form, denied = post_guard(environ, session, user)
    if denied:
        return denied
    with get_db() as conn:
        p = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not p:
            return error_page(404, "상품을 찾을 수 없습니다.", session, user)
        if p["seller_id"] != user["id"] and not user["is_admin"]:
            return error_page(403, "다른 사용자의 상품을 삭제할 수 없습니다.", session, user)
        conn.execute("DELETE FROM products WHERE id=?", (product_id,))
    return flash_redirect(session, "/", "상품을 삭제했습니다.", "success")


def route_message_new(environ, session, user, **kwargs) -> Response:
    denied = require_login(session, user)
    if denied:
        return denied
    query = parse_qs(environ.get("QUERY_STRING", ""))
    try:
        recipient_id = int(query.get("to", ["0"])[0])
    except ValueError:
        recipient_id = 0
    try:
        product_id = int(query.get("product", ["0"])[0]) or None
    except ValueError:
        product_id = None
    with get_db() as conn:
        recipient = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (recipient_id,)).fetchone()
    if not recipient or recipient["id"] == user["id"]:
        return error_page(400, "메시지 수신자가 올바르지 않습니다.", session, user)
    if environ["REQUEST_METHOD"] == "POST":
        ip = environ.get("REMOTE_ADDR", "unknown")
        if not limiter.allow(ip, "message", 30, 300):
            return error_page(429, "메시지 전송 횟수가 너무 많습니다.", session, user)
        form = parse_form(environ)
        if not require_csrf(form, session):
            return error_page(400, "CSRF 검증에 실패했습니다.", session, user)
        body = form.get("body", "").strip()
        if not 1 <= len(body) <= 500:
            return flash_redirect(session, f"/messages/new?{urlencode({'to': recipient_id, 'product': product_id or ''})}", "메시지는 1~500자로 입력하세요.", "error")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO messages(sender_id,recipient_id,product_id,body,created_at) VALUES(?,?,?,?,?)",
                (user["id"], recipient_id, product_id, body, iso_now()),
            )
        return flash_redirect(session, "/messages", "메시지를 보냈습니다.", "success")
    content = f'''<section class="panel narrow"><h1>{e(recipient["display_name"])}님에게 메시지</h1><form method="post">{csrf_input(session)}
<label>내용<textarea name="body" required maxlength="500"></textarea></label><button class="button">보내기</button></form></section>'''
    return Response.html(base_page("메시지 보내기", content, session, user))


def route_messages(environ, session, user, **kwargs) -> Response:
    denied = require_login(session, user)
    if denied:
        return denied
    with get_db() as conn:
        rows = conn.execute(
            """SELECT m.*, s.display_name sender_name, r.display_name recipient_name, p.title product_title
               FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id
               LEFT JOIN products p ON p.id=m.product_id
               WHERE m.sender_id=? OR m.recipient_id=? ORDER BY m.id DESC LIMIT 100""",
            (user["id"], user["id"]),
        ).fetchall()
    items = []
    for m in rows:
        direction = "받음" if m["recipient_id"] == user["id"] else "보냄"
        partner = m["sender_name"] if direction == "받음" else m["recipient_name"]
        partner_id = m["sender_id"] if direction == "받음" else m["recipient_id"]
        reply_url = "/messages/new?" + urlencode({"to": partner_id, "product": m["product_id"] or ""})
        items.append(f'''<article class="message"><div><strong>{e(direction)}</strong> · {e(partner)} {('· ' + e(m['product_title'])) if m['product_title'] else ''}</div><p>{e(m["body"])}</p><small>{e(m["created_at"])}</small><div class="actions"><a class="button secondary" href="{e(reply_url)}">답장</a></div></article>''')
    content = f'<section class="panel"><h1>메시지함</h1>{"".join(items) if items else "<p>메시지가 없습니다.</p>"}</section>'
    return Response.html(base_page("메시지", content, session, user))


def route_report(environ, session, user, target_type: str, target_id: int, **kwargs) -> Response:
    form, denied = post_guard(environ, session, user)
    if denied:
        return denied
    ip = environ.get("REMOTE_ADDR", "unknown")
    if not limiter.allow(ip, "report", 20, 600):
        return error_page(429, "신고 요청이 너무 많습니다.", session, user)
    reason = form.get("reason", "").strip()
    if not 3 <= len(reason) <= 200:
        return error_page(400, "신고 사유가 올바르지 않습니다.", session, user)
    if target_type not in {"product", "user"}:
        return error_page(400, "잘못된 신고 대상입니다.", session, user)
    with get_db() as conn:
        if target_type == "product":
            target = conn.execute("SELECT seller_id FROM products WHERE id=?", (target_id,)).fetchone()
            redirect_to = f"/products/{target_id}"
            if target and target["seller_id"] == user["id"]:
                return error_page(400, "자신의 상품은 신고할 수 없습니다.", session, user)
        else:
            target = conn.execute("SELECT id FROM users WHERE id=?", (target_id,)).fetchone()
            redirect_to = "/"
            if target_id == user["id"]:
                return error_page(400, "자신은 신고할 수 없습니다.", session, user)
        if not target:
            return error_page(404, "신고 대상을 찾을 수 없습니다.", session, user)
        try:
            conn.execute(
                "INSERT INTO reports(reporter_id,target_type,target_id,reason,status,created_at) VALUES(?,?,?,?, 'open', ?)",
                (user["id"], target_type, target_id, reason, iso_now()),
            )
        except sqlite3.IntegrityError:
            conn.rollback()
            duplicate = True
        else:
            duplicate = False
    if duplicate:
        return flash_redirect(session, redirect_to, "이미 신고한 대상입니다.", "error")
    return flash_redirect(session, redirect_to, "신고가 접수되었습니다. 관리자가 검토합니다.", "success")


def route_transfer(environ, session, user, **kwargs) -> Response:
    denied = require_login(session, user)
    if denied:
        return denied
    if environ["REQUEST_METHOD"] == "POST":
        ip = environ.get("REMOTE_ADDR", "unknown")
        if not limiter.allow(ip, "transfer", 20, 300):
            return error_page(429, "송금 요청이 너무 많습니다.", session, user)
        form = parse_form(environ)
        if not require_csrf(form, session):
            return error_page(400, "CSRF 검증에 실패했습니다.", session, user)
        recipient_name = form.get("recipient", "").strip()
        try:
            amount = int(form.get("amount", ""))
        except ValueError:
            amount = 0
        if not 1 <= amount <= 1_000_000:
            return flash_redirect(session, "/transfer", "송금액은 1~1,000,000 포인트여야 합니다.", "error")
        conn = get_db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            sender = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
            recipient = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (recipient_name,)).fetchone()
            if not recipient:
                conn.rollback()
                return flash_redirect(session, "/transfer", "수신자를 찾을 수 없습니다.", "error")
            if recipient["id"] == sender["id"]:
                conn.rollback()
                return flash_redirect(session, "/transfer", "자기 자신에게 송금할 수 없습니다.", "error")
            if sender["balance"] < amount:
                conn.rollback()
                return flash_redirect(session, "/transfer", "잔액이 부족합니다.", "error")
            conn.execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, sender["id"]))
            conn.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, recipient["id"]))
            conn.execute(
                "INSERT INTO transfers(sender_id,recipient_id,amount,created_at) VALUES(?,?,?,?)",
                (sender["id"], recipient["id"], amount, iso_now()),
            )
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            logger.exception("transfer failed")
            return error_page(500, "송금 처리 중 오류가 발생했습니다.", session, user)
        finally:
            conn.close()
        return flash_redirect(session, "/transfer", f"{recipient_name}님에게 {amount:,}P를 보냈습니다.", "success")
    with get_db() as conn:
        transfers = conn.execute(
            """SELECT t.*, s.username sender_name, r.username recipient_name FROM transfers t
               JOIN users s ON s.id=t.sender_id JOIN users r ON r.id=t.recipient_id
               WHERE t.sender_id=? OR t.recipient_id=? ORDER BY t.id DESC LIMIT 20""",
            (user["id"], user["id"]),
        ).fetchall()
    history = "".join(
        f'<li>{e(t["sender_name"])} → {e(t["recipient_name"])} : {t["amount"]:,}P</li>' for t in transfers
    ) or "<li>내역이 없습니다.</li>"
    content = f'''<section class="two-col"><div class="panel"><h1>포인트 송금</h1><p class="notice">교육용 가상 포인트입니다. 실제 결제·현금 송금이 아닙니다.</p><form method="post">{csrf_input(session)}
{form_row('받는 사람 아이디', 'recipient', attrs='required maxlength="20"')}{form_row('금액', 'amount', typ='number', attrs='required min="1" max="1000000"')}
<button class="button">송금하기</button></form></div><div class="panel"><h2>최근 내역</h2><ul>{history}</ul></div></section>'''
    return Response.html(base_page("포인트 송금", content, session, user))


def require_admin(session, user) -> Response | None:
    denied = require_login(session, user)
    if denied:
        return denied
    if not user["is_admin"]:
        return error_page(403, "관리자 권한이 필요합니다.", session, user)
    return None


def route_admin(environ, session, user, **kwargs) -> Response:
    denied = require_admin(session, user)
    if denied:
        return denied
    with get_db() as conn:
        users = conn.execute("SELECT id,username,display_name,active,is_admin,balance FROM users ORDER BY id").fetchall()
        products = conn.execute("SELECT id,title,hidden,sold FROM products ORDER BY id DESC LIMIT 100").fetchall()
        reports = conn.execute(
            "SELECT r.*, u.username reporter FROM reports r JOIN users u ON u.id=r.reporter_id ORDER BY r.id DESC LIMIT 100"
        ).fetchall()
        messages = conn.execute(
            "SELECT m.id, s.username sender, r.username recipient, m.body, m.created_at FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id ORDER BY m.id DESC LIMIT 50"
        ).fetchall()
        transfers = conn.execute(
            "SELECT t.id, s.username sender, r.username recipient, t.amount, t.created_at FROM transfers t JOIN users s ON s.id=t.sender_id JOIN users r ON r.id=t.recipient_id ORDER BY t.id DESC LIMIT 50"
        ).fetchall()
    user_rows = "".join(
        f'''<tr><td>{u["id"]}</td><td>{e(u["username"])}</td><td>{e(u["display_name"])}</td><td>{'활성' if u['active'] else '정지'}</td><td>{u['balance']:,}</td><td>{'' if u['is_admin'] else f'<form method="post" action="/admin/user/{u["id"]}/toggle">{csrf_input(session)}<button>상태 변경</button></form>'}</td></tr>'''
        for u in users
    )
    product_rows = "".join(
        f'''<tr><td>{p["id"]}</td><td>{e(p["title"])}</td><td>{'숨김' if p['hidden'] else '공개'}</td><td><form method="post" action="/admin/product/{p["id"]}/toggle">{csrf_input(session)}<button>공개 상태 변경</button></form></td></tr>'''
        for p in products
    )
    report_rows = "".join(
        f'<tr><td>{r["id"]}</td><td>{e(r["reporter"])}</td><td>{e(r["target_type"])}/{r["target_id"]}</td><td>{e(r["reason"])}</td><td>{e(r["status"])}</td></tr>'
        for r in reports
    )
    message_rows = "".join(
        f'<tr><td>{m["id"]}</td><td>{e(m["sender"])}</td><td>{e(m["recipient"])}</td><td>{e(m["body"])}</td><td>{e(m["created_at"])}</td></tr>'
        for m in messages
    )
    transfer_rows = "".join(
        f'<tr><td>{t["id"]}</td><td>{e(t["sender"])}</td><td>{e(t["recipient"])}</td><td>{t["amount"]:,}P</td><td>{e(t["created_at"])}</td></tr>'
        for t in transfers
    )
    content = f'''<section class="panel"><h1>관리자 페이지</h1><h2>사용자</h2><div class="table-wrap"><table><tr><th>ID</th><th>아이디</th><th>이름</th><th>상태</th><th>잔액</th><th>관리</th></tr>{user_rows}</table></div>
<h2>상품</h2><div class="table-wrap"><table><tr><th>ID</th><th>상품명</th><th>상태</th><th>관리</th></tr>{product_rows}</table></div>
<h2>신고</h2><div class="table-wrap"><table><tr><th>ID</th><th>신고자</th><th>대상</th><th>사유</th><th>상태</th></tr>{report_rows}</table></div>
<h2>최근 메시지 감사 내역</h2><div class="table-wrap"><table><tr><th>ID</th><th>발신자</th><th>수신자</th><th>내용</th><th>시각</th></tr>{message_rows}</table></div>
<h2>최근 송금 감사 내역</h2><div class="table-wrap"><table><tr><th>ID</th><th>송신자</th><th>수신자</th><th>금액</th><th>시각</th></tr>{transfer_rows}</table></div></section>'''
    return Response.html(base_page("관리자", content, session, user))


def route_admin_user_toggle(environ, session, user, target_id: int, **kwargs) -> Response:
    denied = require_admin(session, user)
    if denied:
        return denied
    form, post_denied = post_guard(environ, session, user)
    if post_denied:
        return post_denied
    if target_id == user["id"]:
        return flash_redirect(session, "/admin", "현재 관리자 계정은 정지할 수 없습니다.", "error")
    with get_db() as conn:
        conn.execute("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=? AND is_admin=0", (target_id,))
        conn.execute("UPDATE reports SET status='resolved' WHERE target_type='user' AND target_id=?", (target_id,))
    return flash_redirect(session, "/admin", "사용자 상태를 변경했습니다.", "success")


def route_admin_product_toggle(environ, session, user, product_id: int, **kwargs) -> Response:
    denied = require_admin(session, user)
    if denied:
        return denied
    form, post_denied = post_guard(environ, session, user)
    if post_denied:
        return post_denied
    with get_db() as conn:
        conn.execute("UPDATE products SET hidden=CASE hidden WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (product_id,))
        conn.execute("UPDATE reports SET status='resolved' WHERE target_type='product' AND target_id=?", (product_id,))
    return flash_redirect(session, "/admin", "상품 공개 상태를 변경했습니다.", "success")



APP_JS = r"""
function resetSubmittedForms() {
  document.querySelectorAll('form[data-submitted="1"]').forEach(function (form) {
    form.removeAttribute("data-submitted");

    form.querySelectorAll(
      'button[type="submit"], button:not([type]), input[type="submit"]'
    ).forEach(function (button) {
      button.disabled = false;

      if (button.dataset.originalText) {
        button.textContent = button.dataset.originalText;
        delete button.dataset.originalText;
      }
    });
  });
}

window.addEventListener("pageshow", resetSubmittedForms);

document.addEventListener("submit", function (event) {
  const form = event.target;

  if (!(form instanceof HTMLFormElement)) return;

  if (form.dataset.submitted === "1") {
    event.preventDefault();
    return;
  }

  form.dataset.submitted = "1";

  form.querySelectorAll(
    'button[type="submit"], button:not([type]), input[type="submit"]'
  ).forEach(function (button) {
    button.disabled = true;

    if (button.tagName === "BUTTON") {
      button.dataset.originalText = button.textContent;
      button.textContent = "처리 중...";
    }
  });
});
"""

STYLE = r"""
:root{--bg:#f6f7f9;--ink:#20252b;--muted:#68707a;--brand:#2f7d5a;--line:#dfe4e8;--danger:#a53535}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans KR",sans-serif;line-height:1.55}.wrap{max-width:1080px;margin:auto;padding:0 20px}header{background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:3}.header-inner{min-height:64px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{font-weight:800;font-size:1.25rem;color:var(--brand);text-decoration:none}nav{display:flex;align-items:center;gap:14px;flex-wrap:wrap}nav a,.link-button{color:var(--ink);text-decoration:none;background:none;border:0;font:inherit;padding:0;cursor:pointer}.user-chip{font-size:.88rem;background:#edf5f0;padding:5px 9px;border-radius:999px}.inline{display:inline}.hero{padding:50px 0 22px}.hero h1{font-size:2rem;margin:0 0 8px}.hero p{color:var(--muted)}.search{display:flex;gap:8px;margin:0 0 24px}.search input{flex:1}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:18px;padding-bottom:45px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 5px 18px rgba(0,0,0,.04)}.card a{text-decoration:none;color:inherit}.card img,.placeholder{width:100%;height:180px;object-fit:cover;background:#e9edf0;display:flex;align-items:center;justify-content:center;color:#8a929a}.card-body{padding:15px}.card h2{font-size:1.08rem;margin:7px 0}.price{font-weight:800;font-size:1.2rem}.muted,.help,small{color:var(--muted)}.badge{display:inline-block;background:#e9f4ed;color:#256a4a;border-radius:999px;padding:3px 8px;font-size:.78rem}.badge.sold{background:#eee;color:#666}.panel{background:#fff;border:1px solid var(--line);border-radius:14px;padding:24px;margin:32px 0}.narrow{max-width:560px;margin-left:auto;margin-right:auto}label{display:block;font-weight:650;margin:14px 0 6px}input,textarea,button{font:inherit}input,textarea{width:100%;border:1px solid #c9d0d6;border-radius:9px;padding:11px 12px;background:#fff}textarea{min-height:140px;resize:vertical}.button,button{display:inline-block;border:0;border-radius:9px;padding:10px 14px;background:var(--brand);color:#fff;text-decoration:none;cursor:pointer}.button.secondary{background:#536270}.button.danger{background:var(--danger)}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:22px}.detail{display:grid;grid-template-columns:minmax(240px,420px) 1fr;gap:28px}.detail-img{width:100%;height:360px;object-fit:cover;border-radius:10px}.description{padding:16px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.flash{padding:12px 14px;border-radius:9px;margin-top:20px;background:#e7eef8}.flash.success{background:#e8f5ec}.flash.error{background:#fae9e9}.notice{background:#fff8dc;border:1px solid #e8d68f;padding:10px;border-radius:9px}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:18px}.message{border-bottom:1px solid var(--line);padding:14px 0}.message p{white-space:pre-wrap}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin-bottom:28px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:9px;vertical-align:top}footer{margin-top:50px;padding:30px 0;color:var(--muted);border-top:1px solid var(--line)}.empty{grid-column:1/-1}.help{font-size:.9rem}@media(max-width:760px){.header-inner{align-items:flex-start;padding-top:14px;padding-bottom:14px}.detail,.two-col{grid-template-columns:1fr}.detail-img{height:280px}.hero{padding-top:30px}nav{gap:9px;font-size:.9rem}}
"""


def route_script(environ, session, user, **kwargs) -> Response:
    return Response.text(
        APP_JS,
        200,
        [
            ("Content-Type", "application/javascript; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ],
    )


def route_style(environ, session, user, **kwargs) -> Response:
    return Response.text(STYLE, 200, [("Content-Type", "text/css; charset=utf-8"), ("Cache-Control", "public, max-age=3600")])


ROUTES: list[tuple[str, re.Pattern, set[str], Callable]] = [
    ("home", re.compile(r"^/$"), {"GET"}, route_home),
    ("register", re.compile(r"^/register$"), {"GET", "POST"}, route_register),
    ("login", re.compile(r"^/login$"), {"GET", "POST"}, route_login),
    ("logout", re.compile(r"^/logout$"), {"POST"}, route_logout),
    ("product_new", re.compile(r"^/products/new$"), {"GET", "POST"}, route_product_new),
    ("product_detail", re.compile(r"^/products/(?P<product_id>\d+)$"), {"GET"}, route_product_detail),
    ("toggle_sold", re.compile(r"^/products/(?P<product_id>\d+)/toggle-sold$"), {"POST"}, route_toggle_sold),
    ("delete_product", re.compile(r"^/products/(?P<product_id>\d+)/delete$"), {"POST"}, route_delete_product),
    ("messages", re.compile(r"^/messages$"), {"GET"}, route_messages),
    ("message_new", re.compile(r"^/messages/new$"), {"GET", "POST"}, route_message_new),
    ("report", re.compile(r"^/reports/(?P<target_type>product|user)/(?P<target_id>\d+)$"), {"POST"}, route_report),
    ("transfer", re.compile(r"^/transfer$"), {"GET", "POST"}, route_transfer),
    ("admin", re.compile(r"^/admin$"), {"GET"}, route_admin),
    ("admin_user", re.compile(r"^/admin/user/(?P<target_id>\d+)/toggle$"), {"POST"}, route_admin_user_toggle),
    ("admin_product", re.compile(r"^/admin/product/(?P<product_id>\d+)/toggle$"), {"POST"}, route_admin_product_toggle),
    ("script", re.compile(r"^/static/app\.js$"), {"GET"}, route_script),
    ("style", re.compile(r"^/static/style\.css$"), {"GET"}, route_style),
]


def security_headers(content_type: str = "text/html; charset=utf-8") -> list[tuple[str, str]]:
    headers = [
        ("Content-Type", content_type),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "same-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' https: data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    ]
    if os.environ.get("ENABLE_HSTS", "0") == "1":
        headers.append(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
    return headers


def application(environ, start_response):
    init_db()
    session, is_new = load_session(environ)
    user = current_user(session)
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    response = None
    try:
        for _, pattern, methods, handler in ROUTES:
            match = pattern.fullmatch(path)
            if match:
                if method not in methods:
                    response = error_page(405, "허용되지 않은 HTTP 메서드입니다.", session, user)
                else:
                    kwargs = {k: int(v) if k.endswith("_id") else v for k, v in match.groupdict().items()}
                    response = handler(environ, session, user, **kwargs)
                break
        if response is None:
            response = error_page(404, "페이지를 찾을 수 없습니다.", session, user)
    except UnicodeDecodeError:
        response = error_page(400, "UTF-8 형식의 요청만 허용합니다.", session, user)
    except ValueError as exc:
        response = error_page(400, str(exc), session, user)
    except Exception:
        logger.exception("Unhandled application error")
        response = error_page(500, "내부 오류가 발생했습니다.", session, user)

    status = f"{response.status} {HTTPStatus(response.status).phrase}"
    headers = list(response.headers or [])
    content_type = next((v for k, v in headers if k.lower() == "content-type"), "text/html; charset=utf-8")
    headers.extend(security_headers(content_type))
    if content_type.startswith("text/html"):
        headers.append(("Cache-Control", "no-store"))
    if is_new and not any(k.lower() == "set-cookie" for k, _ in headers):
        headers.append(session_cookie(session["token"]))
    headers.append(("Content-Length", str(len(response.body))))
    start_response(status, headers)
    return [response.body]


def create_admin(username: str, password: str, display_name: str = "관리자") -> None:
    init_db()
    if not USERNAME_RE.fullmatch(username):
        raise SystemExit("관리자 아이디는 영문, 숫자, 밑줄 3~20자여야 합니다.")
    err = password_error(password)
    if err:
        raise SystemExit(err)
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users(username,display_name,password_hash,balance,active,is_admin,created_at) VALUES(?,?,?,100000,1,1,?)",
                (username, display_name, password_hash(password), iso_now()),
            )
        except sqlite3.IntegrityError:
            conn.execute(
                "UPDATE users SET password_hash=?, is_admin=1, active=1 WHERE username=?",
                (password_hash(password), username),
            )
    print(f"관리자 계정 '{username}'을 생성/갱신했습니다.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tiny Market secure coding project")
    sub = parser.add_subparsers(dest="command")
    run_p = sub.add_parser("run")
    run_p.add_argument("--host", default="127.0.0.1")
    run_p.add_argument("--port", type=int, default=8000)
    admin_p = sub.add_parser("create-admin")
    admin_p.add_argument("username")
    admin_p.add_argument("password")
    admin_p.add_argument("--display-name", default="관리자")
    sub.add_parser("init-db")
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.username, args.password, args.display_name)
    elif args.command == "init-db":
        init_db(); print(f"DB 초기화 완료: {DB_PATH}")
    else:
        init_db()
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8000)
        print(f"Tiny Market 실행: http://{host}:{port}")
        print("종료: Ctrl+C")
        with make_server(host, port, application) as server:
            server.serve_forever()


if __name__ == "__main__":
    main()
