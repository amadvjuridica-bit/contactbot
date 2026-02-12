import os
import io
import csv
import re
import json
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, date, time
from typing import Optional, Tuple, List, Dict, Any

import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# ============================================================
# CONFIG / PADRÕES VISUAIS (cinza/azul)
# ============================================================
st.set_page_config(page_title="ContactBot", layout="wide")
load_dotenv()

PRIMARY_BLUE = "#1E4E8C"
SECONDARY_BLUE = "#2B6CB0"
SOFT_GRAY_BG = "#F6F7F9"
SOFT_GRAY_BORDER = "#E6E8EC"
TEXT_GRAY = "#2B2F38"
MUTED_GRAY = "#5B6472"

def inject_css():
    st.markdown(
        f"""
        <style>
            html, body, [class*="css"] {{
                color: {TEXT_GRAY};
            }}
            .block-container {{
                padding-top: 1.1rem;
                padding-bottom: 2rem;
            }}
            button[data-baseweb="tab"] {{
                font-weight: 750;
            }}
            .stButton button {{
                background: {PRIMARY_BLUE};
                color: white;
                border-radius: 12px;
                border: 1px solid {PRIMARY_BLUE};
                padding: 0.62rem 1rem;
                font-weight: 850;
            }}
            .stButton button:hover {{
                background: {SECONDARY_BLUE};
                border-color: {SECONDARY_BLUE};
                color: white;
            }}
            .stDownloadButton button {{
                border-radius: 12px;
                font-weight: 850;
            }}
            [data-baseweb="input"] > div, [data-baseweb="textarea"] > div, [data-baseweb="select"] > div {{
                border-radius: 12px !important;
                border-color: {SOFT_GRAY_BORDER} !important;
            }}
            [data-testid="stMetric"] {{
                background: white;
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 14px;
                padding: 14px 14px;
            }}
            .stDataFrame {{
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 14px;
                overflow: hidden;
            }}
            .cb-card {{
                background: white;
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 16px;
                padding: 16px 18px;
                margin-bottom: 10px;
            }}
            .cb-title {{
                font-size: 26px;
                font-weight: 950;
                margin-bottom: 0.2rem;
                letter-spacing: -0.2px;
            }}
            .cb-sub {{
                color: {MUTED_GRAY};
                font-size: 13px;
                margin-top: 0rem;
            }}
            .cb-pill {{
                display: inline-block;
                padding: 6px 10px;
                border-radius: 999px;
                border: 1px solid {SOFT_GRAY_BORDER};
                background: {SOFT_GRAY_BG};
                font-size: 12px;
                font-weight: 850;
                color: #3B4250;
            }}
            .cb-muted {{
                color: #6B7280;
                font-size: 13px;
            }}
            .cb-section-title {{
                font-size: 18px;
                font-weight: 900;
                margin-top: 0.2rem;
                margin-bottom: 0.2rem;
            }}
            .cb-help {{
                color: {MUTED_GRAY};
                font-size: 13px;
                margin-bottom: 0.2rem;
            }}
            .cb-divider {{
                height: 1px;
                background: {SOFT_GRAY_BORDER};
                margin: 14px 0;
            }}
            .cb-action {{
                background: {SOFT_GRAY_BG};
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 14px;
                padding: 12px 14px;
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )

inject_css()

# ============================================================
# SECRETS
# ============================================================
def get_secret(name: str, default: str = "") -> str:
    v = (os.getenv(name, "") or "").strip()
    if v:
        return v
    try:
        v2 = (st.secrets.get(name, "") or "").strip()
        return v2 if v2 else default
    except Exception:
        return default

SUPABASE_URL = get_secret("SUPABASE_URL")
SUPABASE_ANON_KEY = get_secret("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = get_secret("SUPABASE_SERVICE_ROLE_KEY")

UPLOADS_BUCKET = "contactbot-uploads"
CLIENT_BASES_BUCKET = "contactbot-client-bases"  # novo bucket (recomendado)

# ADMIN (apenas seu usuário)
ADMIN_EMAIL = "amadvjuridica@gmail.com"

# SMTP default (porta confirmada)
DEFAULT_SMTP_PORT = 465

# ============================================================
# FAIXAS PADRÃO (fallback)
# ============================================================
DEFAULT_TIERS = {
    "pos": [
        (1, 10999, 0.27),
        (11000, 30999, 0.25),
        (31000, 50999, 0.22),
        (51000, 100999, 0.20),
        (101000, 10**12, 0.18),
    ],
    "pre": [
        (1000, 10999, 0.34),
        (11000, 30999, 0.30),
        (31000, 50999, 0.28),
        (51000, 100999, 0.26),
        (101000, 10**12, 0.24),
    ],
}

BILLABLE_STATUSES = {"sent", "delivered", "read"}
NON_BILLABLE_STATUSES = {"undelivered"}

# ============================================================
# FORMATAÇÃO (pt-BR)
# ============================================================
def fmt_int(n: Optional[int]) -> str:
    if n is None:
        return "-"
    try:
        return f"{int(n):,}".replace(",", ".")
    except Exception:
        return str(n)

def fmt_money(v: Optional[float]) -> str:
    if v is None:
        return "-"
    try:
        s = f"{float(v):,.2f}"
        return "R$ " + s.replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return str(v)

def fmt_pct(x: float) -> str:
    try:
        return f"{x:.1f}%".replace(".", ",")
    except Exception:
        return "-"

def _mask(s: str, show: int = 6) -> str:
    if not s:
        return ""
    if len(s) <= show:
        return s
    return s[:show] + "..." + f"({len(s)} chars)"

def ensure_env_or_stop():
    missing = []
    if not SUPABASE_URL:
        missing.append("SUPABASE_URL")
    if not SUPABASE_ANON_KEY:
        missing.append("SUPABASE_ANON_KEY")
    if not SUPABASE_SERVICE_ROLE_KEY:
        missing.append("SUPABASE_SERVICE_ROLE_KEY")

    if missing:
        st.error(f"Faltando config: {', '.join(missing)}")
        st.info("Local: crie um arquivo .env na mesma pasta do app.py e reinicie o Streamlit.")
        st.info("Streamlit Cloud: Manage app → Settings → Secrets (TOML).")
        st.stop()

ensure_env_or_stop()

@st.cache_resource(show_spinner=False)
def get_clients() -> tuple[Client, Client]:
    supa_public = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    supa_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return supa_public, supa_admin

supabase_public, supabase_admin = get_clients()

# ============================================================
# SESSÃO (página única)
# ============================================================
def session_is_logged_in() -> bool:
    return bool(st.session_state.get("access_token")) and bool(st.session_state.get("user"))

def session_set_from_auth_response(resp):
    session = getattr(resp, "session", None) or (resp.get("session") if isinstance(resp, dict) else None)
    user = getattr(resp, "user", None) or (resp.get("user") if isinstance(resp, dict) else None)
    if not session or not user:
        return False

    access_token = getattr(session, "access_token", None) or (session.get("access_token") if isinstance(session, dict) else None)
    refresh_token = getattr(session, "refresh_token", None) or (session.get("refresh_token") if isinstance(session, dict) else None)

    user_email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    user_id = getattr(user, "id", None) or (user.get("id") if isinstance(user, dict) else None)

    st.session_state["access_token"] = access_token
    st.session_state["refresh_token"] = refresh_token
    st.session_state["user"] = {"email": user_email, "id": user_id}
    return True

def do_logout():
    try:
        supabase_public.auth.sign_out()
    except Exception:
        pass
    for k in ["access_token", "refresh_token", "user"]:
        st.session_state.pop(k, None)
    st.rerun()

def is_admin_user() -> bool:
    user = st.session_state.get("user", {}) or {}
    email = (user.get("email") or "").strip().lower()
    return email == ADMIN_EMAIL.lower()

# ============================================================
# AUTH / ADMIN (mantido)
# ============================================================
def admin_find_user_by_email(email: str):
    email = (email or "").strip().lower()
    if not email:
        return None
    page = 1
    per_page = 200
    for _ in range(20):
        resp = supabase_admin.auth.admin.list_users(page=page, per_page=per_page)
        users = getattr(resp, "users", None)
        if users is None and isinstance(resp, dict):
            users = resp.get("users", [])
        if not users:
            return None
        for u in users:
            if (u.get("email") or "").strip().lower() == email:
                return u
        page += 1
    return None

def admin_create_user(email: str, password: str):
    return supabase_admin.auth.admin.create_user({"email": email.strip(), "password": password.strip(), "email_confirm": True})

def admin_set_password(email: str, new_password: str, *, create_if_missing: bool = True):
    """Define senha de um usuário no Supabase Auth.
    Se o usuário não existir e create_if_missing=True, cria o usuário (email confirmado) e define a senha.
    Retorna (user_dict, action) onde action ∈ {'updated','created'}.
    """
    email = (email or "").strip().lower()
    pwd = (new_password or "").strip()
    if not email:
        raise ValueError("Informe o e-mail do usuário.")
    if not pwd:
        raise ValueError("Informe a nova senha.")
    u = admin_find_user_by_email(email)
    if not u:
        if not create_if_missing:
            raise ValueError("Não achei esse e-mail no Supabase Auth > Users.")
        created = admin_create_user(email, pwd, True)
        u = created.user if hasattr(created, "user") else (created.get("user") if isinstance(created, dict) else None)
        if not u:
            u = admin_find_user_by_email(email)
        if not u:
            raise ValueError("Falha ao criar o usuário no Supabase Auth.")
        return u, "created"
    uid = u.get("id")
    supabase_admin.auth.admin.update_user_by_id(uid, {"password": pwd})
    return u, "updated"

def do_login(email: str, password: str):
    return supabase_public.auth.sign_in_with_password({"email": email.strip(), "password": password.strip()})

# ============================================================
# UTILS
# ============================================================
def slugify(text: str) -> str:
    text = (text or "").strip().upper()
    text = re.sub(r"[^\w\s]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "_", text)
    return text

def remessa_key_from(numero: int, data_remessa: date, cliente_slug: str) -> str:
    return f"CB-{data_remessa.strftime('%Y%m%d')}-{int(numero):03d}-{cliente_slug}"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_storage_path(cliente_slug: str, remessa_key: str, file_tipo: str, original_name: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{cliente_slug}/{remessa_key}/{file_tipo}/{ts}__{original_name}"

def make_client_base_storage_path(cliente_slug: str, schedule_date: date, original_name: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    day = schedule_date.strftime("%Y%m%d")
    return f"{cliente_slug}/bases/{day}/{ts}__{original_name}"

def parse_csv_preview(data: bytes, max_rows: int = 30):
    text = data.decode("utf-8", errors="replace")
    f = io.StringIO(text)
    reader = csv.DictReader(f)
    headers = reader.fieldnames or []
    rows = []
    for i, row in enumerate(reader):
        rows.append(row)
        if i + 1 >= max_rows:
            break
    return headers, rows

def detect_delimiter(sample_text: str) -> str:
    if sample_text.count(";") > sample_text.count(","):
        return ";"
    return ","

def _safe_dt_local_to_utc_iso(d: date, t: time) -> str:
    # Sem depender de timezone do browser: assume "America/Sao_Paulo" no operacional.
    # Se você quiser, dá para ajustar com pytz, mas aqui fica estável e simples.
    # Armazena como ISO sem timezone (ou como UTC assumido).
    dt = datetime(d.year, d.month, d.day, t.hour, t.minute, 0)
    # guarda como ISO com timezone UTC (assumindo já local convertido manualmente não é necessário)
    # Para auditoria, guardamos também o "local" num campo.
    return dt.replace(tzinfo=timezone.utc).isoformat()

# ============================================================
# DB HELPERS
# ============================================================
def _resp_data(resp):
    return getattr(resp, "data", None) or (resp.get("data", []) if isinstance(resp, dict) else [])

def db_list_clientes():
    return supabase_admin.table("clientes").select("*").order("razao_social").execute()

def db_insert_cliente(cnpj, razao, contato_nome, contato_email, contato_whatsapp, plano_tipo):
    slug = slugify(razao)
    contato_email_clean = (contato_email or "").strip() or None

    payload = {
        "cnpj": (cnpj or "").strip(),
        "razao_social": (razao or "").strip(),
        "slug": slug,
        "contato_nome": (contato_nome or "").strip() or None,
        "contato_email": contato_email_clean,
        "contato_whatsapp": (contato_whatsapp or "").strip() or None,
        "plano_tipo": plano_tipo,
        "ativo": True,
        "email_principal": contato_email_clean or "financeiro@exemplo.com",
    }
    return supabase_admin.table("clientes").insert(payload).execute()

def db_update_cliente(cliente_id, payload: dict):
    return supabase_admin.table("clientes").update(payload).eq("id", cliente_id).execute()

def remessa_get_key(r: dict) -> str:
    return (r.get("remessa_key") or r.get("titulo") or "")

def remessa_get_numero(r: dict) -> int:
    return int(r.get("numero_remessa") or r.get("numero") or 0)

def db_list_remessas(cliente_id=None, limit=200):
    q = supabase_admin.table("remessas").select("*").order("data", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    return q.execute()

def db_insert_remessa(cliente_id, numero_remessa, data_remessa, remessa_key, observacao=None):
    payload = {
        "cliente_id": cliente_id,
        "data": str(data_remessa),
        "status": "aguardando_upload",
        "versao": 1,
        "numero": int(numero_remessa),
        "titulo": remessa_key,
    }
    if observacao and (observacao or "").strip():
        payload["observacao"] = (observacao or "").strip()
    return supabase_admin.table("remessas").insert(payload).execute()

def db_update_remessa_status(remessa_id: str, status: str):
    return supabase_admin.table("remessas").update({"status": status}).eq("id", remessa_id).execute()

def db_insert_upload_record(user_id, user_email, file_name, bucket, path, size_bytes, sha256, remessa_id, file_tipo):
    return supabase_admin.table("uploads").insert({
        "user_id": user_id,
        "user_email": user_email,
        "file_name": file_name,
        "storage_bucket": bucket,
        "storage_path": path,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "remessa_id": remessa_id,
        "file_tipo": file_tipo
    }).execute()

def db_list_uploads(remessa_id=None, limit=200):
    q = supabase_admin.table("uploads").select("*").order("created_at", desc=True).limit(limit)
    if remessa_id:
        q = q.eq("remessa_id", remessa_id)
    return q.execute()

# ---- Email config/logs
def db_get_email_config():
    return supabase_admin.table("email_config").select("*").order("created_at", desc=True).limit(1).execute()

def db_upsert_email_config(payload: dict):
    existing = _resp_data(db_get_email_config())
    if existing:
        row_id = existing[0]["id"]
        return supabase_admin.table("email_config").update(payload).eq("id", row_id).execute()
    return supabase_admin.table("email_config").insert(payload).execute()

def db_insert_email_log(payload: dict):
    return supabase_admin.table("email_logs").insert(payload).execute()

def db_list_email_logs(cliente_id: Optional[str] = None, remessa_id: Optional[str] = None, status: Optional[str] = None, limit: int = 200):
    q = supabase_admin.table("email_logs").select("*").order("created_at", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    if remessa_id:
        q = q.eq("remessa_id", remessa_id)
    if status and status != "Todos":
        q = q.eq("status", status)
    return q.execute()

# ---- Mercado Pago config
def db_get_mercadopago_config():
    return supabase_admin.table("mercadopago_config").select("*").order("created_at", desc=True).limit(1).execute()

def db_upsert_mercadopago_config(payload: dict):
    existing = _resp_data(db_get_mercadopago_config())
    if existing:
        row_id = existing[0]["id"]
        return supabase_admin.table("mercadopago_config").update(payload).eq("id", row_id).execute()
    return supabase_admin.table("mercadopago_config").insert(payload).execute()

# ---- Pricing tiers
def db_list_pricing_tiers(plan_tipo: str):
    return supabase_admin.table("pricing_tiers").select("*").eq("plano_tipo", plan_tipo).order("min_qty").execute()

def db_update_pricing_tier(row_id: int, payload: dict):
    return supabase_admin.table("pricing_tiers").update(payload).eq("id", row_id).execute()

def db_insert_pricing_tiers(rows: list[dict]):
    return supabase_admin.table("pricing_tiers").insert(rows).execute()

def load_tiers_from_db_or_default(plan_tipo: str):
    try:
        resp = db_list_pricing_tiers(plan_tipo)
        rows = _resp_data(resp) or []
        rows = [r for r in rows if r.get("ativo", True)]
        if not rows:
            return DEFAULT_TIERS[plan_tipo]
        out = []
        for r in rows:
            mn = int(r.get("min_qty") or 0)
            mx = int(r.get("max_qty") or 10**12)
            pr = float(r.get("unit_price") or 0.0)
            out.append((mn, mx, pr))
        out.sort(key=lambda x: x[0])
        return out
    except Exception:
        return DEFAULT_TIERS[plan_tipo]

def tier_price(plan_tipo: str, qty_billable: int) -> float:
    tiers = load_tiers_from_db_or_default(plan_tipo)
    for a, b, p in tiers:
        if a <= qty_billable <= b:
            return p
    return tiers[-1][2]

def next_tier(plan_tipo: str, qty_billable: int):
    tiers = load_tiers_from_db_or_default(plan_tipo)
    for a, b, p in tiers:
        if qty_billable < a:
            return (a, b, p)
    return None

def current_tier(plan_tipo: str, qty_billable: int):
    tiers = load_tiers_from_db_or_default(plan_tipo)
    for a, b, p in tiers:
        if a <= qty_billable <= b:
            return (a, b, p)
    return tiers[-1]

# ---- client_users (controle de acesso por cliente)
def db_list_client_users(cliente_id: Optional[str] = None, limit: int = 200):
    q = supabase_admin.table("client_users").select("*").order("created_at", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    return q.execute()

def db_upsert_client_user(cliente_id: str, user_email: str, user_id: Optional[str], role: str, ativo: bool):
    email_norm = (user_email or "").strip().lower()
    existing = _resp_data(
        supabase_admin.table("client_users").select("*").ilike("user_email", email_norm).limit(1).execute()
    )
    payload = {
        "cliente_id": cliente_id,
        "user_email": email_norm,
        "user_id": user_id,
        "role": role,
        "ativo": bool(ativo),
    }
    if existing:
        row_id = existing[0]["id"]
        return supabase_admin.table("client_users").update(payload).eq("id", row_id).execute()
    return supabase_admin.table("client_users").insert(payload).execute()

def db_get_access_cliente_ids_for_user(user_email: str) -> List[str]:
    email_norm = (user_email or "").strip().lower()
    try:
        rows = _resp_data(
            supabase_admin.table("client_users")
            .select("cliente_id, ativo")
            .ilike("user_email", email_norm)
            .execute()
        ) or []
        rows = [r for r in rows if bool(r.get("ativo", True))]
        return [r["cliente_id"] for r in rows if r.get("cliente_id")]
    except Exception:
        return []

# ---- bases (novas tabelas)
def db_try_select(table: str, limit: int = 1):
    return supabase_admin.table(table).select("*").limit(limit).execute()

def db_get_base_agendamento(cliente_id: str, day: date):
    # retorna agendamento do dia (se existir)
    return supabase_admin.table("bases_agendamentos").select("*").eq("cliente_id", cliente_id).eq("schedule_date", str(day)).limit(1).execute()

def db_insert_base_agendamento(cliente_id: str, schedule_date: date, schedule_time: str, schedule_dt_utc: str,
                               created_by_email: str, created_by_user_id: str, notes: Optional[str] = None):
    payload = {
        "cliente_id": cliente_id,
        "schedule_date": str(schedule_date),
        "schedule_time": schedule_time,
        "schedule_dt_utc": schedule_dt_utc,
        "status": "aguardando_execucao",
        "created_by_email": created_by_email,
        "created_by_user_id": created_by_user_id,
        "notes": (notes or "").strip() or None,
    }
    return supabase_admin.table("bases_agendamentos").insert(payload).execute()

def db_insert_base_arquivo(agendamento_id: str, cliente_id: str, original_name: str, file_ext: str,
                           bucket: str, storage_path: str, size_bytes: int, sha256: str,
                           uploaded_by_email: str, uploaded_by_user_id: str):
    payload = {
        "agendamento_id": agendamento_id,
        "cliente_id": cliente_id,
        "original_name": original_name,
        "file_ext": file_ext,
        "storage_bucket": bucket,
        "storage_path": storage_path,
        "size_bytes": int(size_bytes),
        "sha256": sha256,
        "uploaded_by_email": uploaded_by_email,
        "uploaded_by_user_id": uploaded_by_user_id,
    }
    return supabase_admin.table("bases_arquivos").insert(payload).execute()

def db_list_base_agendamentos(cliente_id: Optional[str] = None, limit: int = 200):
    q = supabase_admin.table("bases_agendamentos").select("*").order("schedule_date", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    return q.execute()

def db_list_base_arquivos(agendamento_id: str, limit: int = 200):
    return supabase_admin.table("bases_arquivos").select("*").eq("agendamento_id", agendamento_id).order("created_at", desc=True).limit(limit).execute()

# ============================================================
# STORAGE HELPERS
# ============================================================
def storage_upload_bytes(bucket: str, path: str, data: bytes, content_type: str):
    return supabase_admin.storage.from_(bucket).upload(
        path,
        data,
        file_options={"content-type": content_type, "upsert": False},
    )

def storage_upload_csv(bucket: str, path: str, data: bytes):
    return storage_upload_bytes(bucket, path, data, "text/csv")

def storage_signed_url(bucket: str, path: str, expires_in: int = 3600) -> str:
    resp = supabase_admin.storage.from_(bucket).create_signed_url(path, expires_in)
    if isinstance(resp, dict) and "signedURL" in resp:
        return resp["signedURL"]
    if isinstance(resp, dict) and "data" in resp and isinstance(resp["data"], dict):
        return resp["data"].get("signedUrl") or resp["data"].get("signedURL") or ""
    return ""

def fetch_bytes_from_signed_url(url: str) -> bytes:
    import requests
    r = requests.get(url, timeout=180)
    r.raise_for_status()
    return r.content

# ============================================================
# CSV -> MÉTRICAS (ignora linhas vazias)
# ============================================================
def infer_status_column(headers: list[str]) -> str | None:
    candidates = ["message_status", "status", "situacao", "estado", "resultado", "delivery_status"]
    lowered = {h.lower(): h for h in headers}
    for c in candidates:
        if c in lowered:
            return lowered[c]
    for h in headers:
        if "status" in h.lower():
            return h
    return None

def compute_envios_metrics(csv_bytes: bytes):
    text = csv_bytes.decode("utf-8", errors="replace")
    sample = text[:5000]
    delim = detect_delimiter(sample)

    f = io.StringIO(text)
    reader = csv.DictReader(f, delimiter=delim)
    headers = reader.fieldnames or []
    status_col = infer_status_column(headers)

    counts = {
        "total_rows": 0,
        "billable": 0,
        "undelivered": 0,
        "by_status": {},
        "status_col": status_col or "",
        "delimiter": delim,
    }

    for row in reader:
        if not row or all(((v or "").strip() == "") for v in row.values()):
            continue

        counts["total_rows"] += 1

        status = ""
        if status_col:
            status = (row.get(status_col) or "").strip().lower()

        if status:
            counts["by_status"][status] = counts["by_status"].get(status, 0) + 1
            if status in NON_BILLABLE_STATUSES:
                counts["undelivered"] += 1
            elif status in BILLABLE_STATUSES:
                counts["billable"] += 1

    return counts

# ============================================================
# STATUS DA REMESSA (baseado nos uploads)
# ============================================================
def remessa_status_from_uploads(uploads_rows: list[dict]) -> str:
    tipos = {u.get("file_tipo") for u in uploads_rows}
    has_envios = "envios" in tipos
    has_botoes = "botoes" in tipos
    if has_envios and has_botoes:
        return "completa"
    if has_envios or has_botoes:
        return "parcial"
    return "aguardando_upload"

# ============================================================
# EMAIL (SMTP SSL 465)
# ============================================================
def smtp_send_email_ssl(host: str, port: int, user: str, password: str, from_name: str, from_email: str,
                        to_email: str, subject: str, body: str, attachments: List[Tuple[str, bytes, str]]):
    msg = EmailMessage()
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    for filename, data, mime in attachments:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    with smtplib.SMTP_SSL(host, port) as server:
        server.login(user, password)
        server.send_message(msg)

def email_cfg_or_none():
    try:
        rows = _resp_data(db_get_email_config()) or []
        if not rows:
            return None
        cfg = rows[0]
        if not bool(cfg.get("is_active", False)):
            return None
        # precisa ter host/user/pass
        if not (cfg.get("smtp_host") and cfg.get("smtp_user") and cfg.get("smtp_pass")):
            return None
        return cfg
    except Exception:
        return None

def send_notification_email(to_email: str, subject: str, body: str):
    cfg = email_cfg_or_none()
    if not cfg:
        return False, "SMTP não configurado/ativo."
    try:
        smtp_send_email_ssl(
            host=(cfg.get("smtp_host") or "").strip(),
            port=int(cfg.get("smtp_port") or DEFAULT_SMTP_PORT),
            user=(cfg.get("smtp_user") or "").strip(),
            password=(cfg.get("smtp_pass") or "").strip(),
            from_name=(cfg.get("from_name") or "ContactBot").strip(),
            from_email=(cfg.get("from_email") or cfg.get("smtp_user") or "").strip(),
            to_email=to_email.strip(),
            subject=subject,
            body=body,
            attachments=[],
        )
        return True, "Enviado."
    except Exception as e:
        return False, str(e)

# ============================================================
# UI HELPERS
# ============================================================
def card(title: str, subtitle: str = ""):
    st.markdown(
        f"""
        <div class="cb-card">
            <div class="cb-section-title">{title}</div>
            <div class="cb-help">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

def status_percent_block(by_status: Dict[str, int], total_rows: int):
    """Barras de % por status (limpo, profissional)."""
    if not by_status or total_rows <= 0:
        st.info("Sem distribuição de status disponível.")
        return

    order = ["delivered", "read", "sent", "undelivered"]
    keys = [k for k in order if k in by_status] + [k for k in by_status.keys() if k not in order]

    for k in keys:
        v = int(by_status.get(k, 0))
        pct = (v / total_rows) * 100.0 if total_rows else 0.0
        c1, c2, c3 = st.columns([2.0, 6.0, 1.2])
        with c1:
            st.write(f"**{k}**")
        with c2:
            st.progress(min(max(pct / 100.0, 0.0), 1.0))
        with c3:
            st.write(f"{fmt_pct(pct)}  ({fmt_int(v)})")

def confirm_block(title: str, help_text: str, button_label: str, key: str) -> bool:
    st.markdown(f"<div class='cb-action'><b>{title}</b><div class='cb-help'>{help_text}</div></div>", unsafe_allow_html=True)
    return st.button(button_label, width='stretch', key=key)

# ============================================================
# HEADER
# ============================================================
st.markdown(
    """
    <div class="cb-card">
        <div class="cb-title">ContactBot</div>
        <div class="cb-sub">Painel operacional (admin) e painel do cliente — com relatórios, remuneração, bases e auditoria.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.expander("Diagnóstico rápido (config)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))
    st.write("UPLOADS_BUCKET:", UPLOADS_BUCKET)
    st.write("CLIENT_BASES_BUCKET:", CLIENT_BASES_BUCKET)

# ============================================================
# PAINEL (LOGADO)
# ============================================================
if session_is_logged_in():
    user = st.session_state.get("user", {}) or {}
    user_email = (user.get("email") or "").strip()
    user_id = (user.get("id") or "").strip()

    # Controle de acesso (não-admin só vê clientes vinculados)
    allowed_cliente_ids = None
    if not is_admin_user():
        allowed_cliente_ids = db_get_access_cliente_ids_for_user(user_email)
        if not allowed_cliente_ids:
            st.error("Seu usuário ainda não foi vinculado a nenhum cliente. Solicite liberação ao administrador.")
            st.stop()

    # topo
    top_l, top_r = st.columns([4, 1])
    with top_l:
        st.subheader("✅ Painel")
        st.caption(f"Usuário: {user_email} | ID: {user_id}")
    with top_r:
        if st.button("Sair", width='stretch'):
            do_logout()

    st.divider()

    # helper: lista clientes filtrando acesso
    def get_visible_clientes() -> List[dict]:
        clientes_resp = db_list_clientes()
        clientes = _resp_data(clientes_resp) or []
        if is_admin_user():
            return clientes
        return [c for c in clientes if c.get("id") in set(allowed_cliente_ids or [])]

    # ============================================================
    # MENU: cliente vê painel simplificado; admin vê completo
    # Tudo com "confirmar" antes de executar consultas pesadas
    # ============================================================
    if is_admin_user():
        tabs = st.tabs(["Dashboard", "Uploads (CSV)", "Campanhas (Remessas)", "Relatórios", "Remuneração", "Bases (Agendamentos)", "Configurações (Admin)"])
    else:
        tabs = st.tabs(["Visão geral", "Relatórios", "Remuneração", "Bases para envio"])

    # ============================================================
    # CLIENTE — Visão geral
    # ============================================================
    if not is_admin_user():
        with tabs[0]:
            card("Visão geral", "Selecione filtros e clique em Confirmar para carregar. Nada executa automaticamente.")

            clientes = get_visible_clientes()
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="cli_client")
            cliente = map_label_to_cliente[cliente_label]
            plano_tipo = cliente.get("plano_tipo", "pos")

            today = date.today()
            c1, c2 = st.columns(2)
            with c1:
                year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="cli_year")
            with c2:
                month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="cli_month")

            go = confirm_block(
                "Confirmar filtros",
                "Clique para carregar o resumo do mês e as campanhas. (Evita travar e deixa auditável.)",
                "Confirmar e carregar",
                "cli_overview_go"
            )

            if not go:
                st.info("Selecione cliente/mês/ano e clique em **Confirmar e carregar**.")
            else:
                
                rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=800)) or []
                
                def in_month(r):
                    try:
                        d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                        return d.year == int(year) and d.month == int(month)
                    except Exception:
                        return False
                
                rems_month = [r for r in rems if in_month(r)]
                
                total_billable_month = 0
                total_value_month = 0.0
                rows_month = []
                
                for r in rems_month:
                    ups = _resp_data(db_list_uploads(remessa_id=r["id"], limit=200)) or []
                    envios_files = [u for u in ups if u.get("file_tipo") == "envios"]
                    if not envios_files:
                        continue
                    envios_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                    env_u = envios_files[0]
                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    if not url:
                        continue
                    csv_bytes = fetch_bytes_from_signed_url(url)
                    metrics = compute_envios_metrics(csv_bytes)
                
                    qty_billable = int(metrics["billable"])
                    unit = tier_price(plano_tipo, qty_billable)
                    tot = qty_billable * unit
                
                    total_billable_month += qty_billable
                    total_value_month += tot
                
                    rows_month.append({
                        "remessa": remessa_get_key(r),
                        "data": r.get("data"),
                        "cobráveis": qty_billable,
                        "unit": unit,
                        "total": tot
                    })
                
                cA, cB, cC, cD = st.columns(4)
                cA.metric("Remessas no mês", fmt_int(len(rems_month)))
                cB.metric("Cobráveis (mês)", fmt_int(total_billable_month))
                cC.metric("Acumulado (mês)", fmt_money(total_value_month))
                a, b, p = current_tier(plano_tipo, total_billable_month if total_billable_month > 0 else (1 if plano_tipo == "pos" else 1000))
                cD.metric("Faixa (referência mês)", f"{fmt_money(p)}")
                
                nxt = next_tier(plano_tipo, total_billable_month)
                if nxt:
                    na, nb, np = nxt
                    falta = max(na - total_billable_month, 0)
                    st.info(f"Para atingir a próxima faixa do mês ({fmt_money(np)}), faltam **{fmt_int(falta)}** cobráveis.")
                else:
                    st.info("Você já está na última faixa de preço.")
                
                st.divider()
                st.write("#### Resumo por campanha (mês)")
                if not rows_month:
                    st.info("Sem remessas com CSV de envios neste mês.")
                else:
                    st.dataframe([{
                        "remessa": x["remessa"],
                        "data": x["data"],
                        "cobráveis": fmt_int(x["cobráveis"]),
                        "unitário": fmt_money(x["unit"]),
                        "total": fmt_money(x["total"]),
                    } for x in rows_month], width='stretch')
                
        # ============================================================
        # CLIENTE — Relatórios
        # ============================================================
        with tabs[1]:
            card("Relatórios", "Selecione o mês e a remessa e clique em Confirmar. Download e sintético por status.")

            clientes = get_visible_clientes()
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="cli_rep_client")
            cliente = map_label_to_cliente[cliente_label]

            today = date.today()
            c1, c2 = st.columns(2)
            with c1:
                year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="cli_rep_year")
            with c2:
                month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="cli_rep_month")

            go = confirm_block(
                "Confirmar filtros",
                "Clique para listar as remessas do mês e abrir a seleção.",
                "Confirmar e carregar",
                "cli_reports_go"
            )
            if not go:
                st.info("Selecione e clique em **Confirmar e carregar**.")
            else:
                
                rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=800)) or []
                
                def in_month(r):
                    try:
                        d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                        return d.year == int(year) and d.month == int(month)
                    except Exception:
                        return False
                
                rems_month = [r for r in rems if in_month(r)]
                if not rems_month:
                    st.info("Nenhuma remessa encontrada para este mês.")
                    st.stop()
                
                map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems_month}
                rem_label = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="cli_rep_rem")
                rem = map_label_to_rem[rem_label]
                
                go2 = confirm_block(
                    "Confirmar remessa",
                    "Clique para carregar downloads e o sintético por status desta remessa.",
                    "Carregar remessa",
                    "cli_reports_go2"
                )
                if not go2:
                    st.info("Selecione a remessa e clique em **Carregar remessa**.")
                    st.stop()
                
                ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
                env_u = next((u for u in ups if u.get("file_tipo") == "envios"), None)
                bot_u = next((u for u in ups if u.get("file_tipo") == "botoes"), None)
                
                st.write("#### Arquivos disponíveis para download")
                d1, d2 = st.columns(2)
                with d1:
                    if env_u:
                        url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                        if url:
                            data = fetch_bytes_from_signed_url(url)
                            st.download_button(
                                "Baixar Envios (CSV)",
                                data=data,
                                file_name=env_u.get("file_name") or "envios.csv",
                                mime="text/csv",
                                width='stretch'
                            )
                        else:
                            st.warning("Não foi possível gerar link para Envios.")
                    else:
                        st.info("Envios não disponível nesta remessa.")
                with d2:
                    if bot_u:
                        url = storage_signed_url(UPLOADS_BUCKET, bot_u.get("storage_path"), expires_in=3600)
                        if url:
                            data = fetch_bytes_from_signed_url(url)
                            st.download_button(
                                "Baixar Botões (CSV)",
                                data=data,
                                file_name=bot_u.get("file_name") or "botoes.csv",
                                mime="text/csv",
                                width='stretch'
                            )
                        else:
                            st.warning("Não foi possível gerar link para Botões.")
                    else:
                        st.info("Botões não disponível nesta remessa.")
                
                st.divider()
                st.write("#### Sintético + distribuição por status (envios)")
                if not env_u:
                    st.warning("Sem CSV de envios nesta remessa.")
                else:
                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    csv_bytes = fetch_bytes_from_signed_url(url)
                    metrics = compute_envios_metrics(csv_bytes)
                
                    total_rows = int(metrics["total_rows"])
                    billable = int(metrics["billable"])
                    undelivered = int(metrics["undelivered"])
                    by_status = metrics["by_status"]
                
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Total linhas", fmt_int(total_rows))
                    m2.metric("Cobráveis", fmt_int(billable))
                    m3.metric("Undelivered", fmt_int(undelivered))
                
                    st.caption(f"Coluna de status: {metrics['status_col']} | Delimitador: {metrics['delimiter']}")
                    st.write("**Percentual por status (sobre o total de linhas):**")
                    status_percent_block(by_status, total_rows)
                
        # ============================================================
        # CLIENTE — Remuneração
        # ============================================================
        with tabs[2]:
            card("Remuneração", "Selecione mês e campanha e clique em Confirmar. Painel claro e auditável.")

            clientes = get_visible_clientes()
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="cli_pay_client")
            cliente = map_label_to_cliente[cliente_label]
            plano_tipo = cliente.get("plano_tipo", "pos")

            today = date.today()
            c1, c2 = st.columns(2)
            with c1:
                year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="cli_pay_year")
            with c2:
                month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="cli_pay_month")

            go = confirm_block(
                "Confirmar filtros",
                "Clique para listar campanhas do mês e liberar seleção.",
                "Confirmar e carregar",
                "cli_pay_go"
            )
            if not go:
                st.info("Selecione e clique em **Confirmar e carregar**.")
            else:
                
                rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=800)) or []
                
                def in_month(r):
                    try:
                        d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                        return d.year == int(year) and d.month == int(month)
                    except Exception:
                        return False
                
                rems_month = [r for r in rems if in_month(r)]
                if not rems_month:
                    st.info("Nenhuma remessa neste mês.")
                    st.stop()
                
                map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems_month}
                rem_label = st.selectbox("Campanha (remessa)", list(map_label_to_rem.keys()), key="cli_pay_rem")
                rem = map_label_to_rem[rem_label]
                
                go2 = confirm_block(
                    "Confirmar campanha",
                    "Clique para calcular os valores desta campanha e o consolidado do mês.",
                    "Calcular remuneração",
                    "cli_pay_go2"
                )
                if not go2:
                    st.info("Selecione a campanha e clique em **Calcular remuneração**.")
                    st.stop()
                
                ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
                env_u = next((u for u in ups if u.get("file_tipo") == "envios"), None)
                
                st.write("#### Por campanha (detalhado)")
                if not env_u:
                    st.warning("Sem CSV de envios para esta campanha.")
                else:
                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    csv_bytes = fetch_bytes_from_signed_url(url)
                    metrics = compute_envios_metrics(csv_bytes)
                
                    qty_total = int(metrics["total_rows"])
                    qty_billable = int(metrics["billable"])
                    qty_undel = int(metrics["undelivered"])
                    unit = tier_price(plano_tipo, qty_billable)
                    total = qty_billable * unit
                
                    k1, k2, k3, k4 = st.columns(4)
                    k1.metric("Total linhas", fmt_int(qty_total))
                    k2.metric("Cobráveis", fmt_int(qty_billable))
                    k3.metric("Undelivered", fmt_int(qty_undel))
                    k4.metric("Unitário", fmt_money(unit))
                
                    st.success(f"Total da campanha (estimado): **{fmt_money(total)}**")
                
                    nxt = next_tier(plano_tipo, qty_billable)
                    if nxt:
                        a, b, p = nxt
                        falta = max(a - qty_billable, 0)
                        st.info(f"Para atingir a próxima faixa desta campanha ({fmt_money(p)}), faltam **{fmt_int(falta)}** cobráveis.")
                    else:
                        st.info("Campanha já está na última faixa de preço.")
                
                st.divider()
                st.write("#### Mensal (acumulado)")
                rows_out = []
                total_month = 0.0
                total_billable_month = 0
                
                for r in rems_month:
                    ups = _resp_data(db_list_uploads(remessa_id=r["id"], limit=200)) or []
                    env_files = [u for u in ups if u.get("file_tipo") == "envios"]
                    if not env_files:
                        continue
                    env_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                    env_u2 = env_files[0]
                    url2 = storage_signed_url(UPLOADS_BUCKET, env_u2.get("storage_path"), expires_in=3600)
                    if not url2:
                        continue
                
                    csv_bytes2 = fetch_bytes_from_signed_url(url2)
                    metrics2 = compute_envios_metrics(csv_bytes2)
                    qty_billable2 = int(metrics2["billable"])
                    unit2 = tier_price(plano_tipo, qty_billable2)
                    tot2 = qty_billable2 * unit2
                
                    total_month += tot2
                    total_billable_month += qty_billable2
                    rows_out.append({
                        "remessa": remessa_get_key(r),
                        "data": r.get("data"),
                        "cobráveis": qty_billable2,
                        "unit": unit2,
                        "total": tot2
                    })
                
                cM1, cM2, cM3 = st.columns(3)
                cM1.metric("Cobráveis no mês", fmt_int(total_billable_month))
                cM2.metric("Acumulado no mês", fmt_money(total_month))
                a, b, p = current_tier(plano_tipo, total_billable_month if total_billable_month > 0 else (1 if plano_tipo == "pos" else 1000))
                cM3.metric("Faixa (mês)", fmt_money(p))
                
                nxtm = next_tier(plano_tipo, total_billable_month)
                if nxtm:
                    na, nb, np = nxtm
                    falta = max(na - total_billable_month, 0)
                    st.info(f"Para atingir a próxima faixa do mês ({fmt_money(np)}), faltam **{fmt_int(falta)}** cobráveis.")
                else:
                    st.info("Você já está na última faixa de preço do mês.")
                
                st.dataframe([{
                    "remessa": x["remessa"],
                    "data": x["data"],
                    "cobráveis": fmt_int(x["cobráveis"]),
                    "unitário": fmt_money(x["unit"]),
                    "total": fmt_money(x["total"])
                } for x in rows_out], width='stretch')
                
        # ============================================================
        # CLIENTE — Bases para envio (NOVO)
        # ============================================================
        with tabs[3]:
            card(
                "Bases para envio",
                "Envie sua base (CSV ou XLSX) e agende data/horário. Apenas 1 agendamento por dia. Você pode enviar vários arquivos, mas o disparo será único."
            )

            # checa se tabelas existem (não quebra)
            need_tables = False
            try:
                db_try_select("bases_agendamentos", 1)
                db_try_select("bases_arquivos", 1)
            except Exception:
                need_tables = True

            if need_tables:
                st.error("As tabelas de bases ainda não existem no Supabase. Peça ao admin para criar (Configurações → Bases).")
                st.stop()

            clientes = get_visible_clientes()
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="cli_base_client")
            cliente = map_label_to_cliente[cliente_label]

            colA, colB = st.columns(2)
            with colA:
                schedule_date = st.date_input("Data do envio", value=date.today(), key="cli_base_date")
            with colB:
                schedule_time = st.time_input("Horário do envio", value=time(9, 0), key="cli_base_time")

            st.caption("Regra: **1 agendamento por dia**. Se já existir agendamento no dia, o horário fica travado (você poderá enviar mais arquivos para o mesmo disparo).")

            # validar agendamento existente
            existing = None
            try:
                existing_resp = db_get_base_agendamento(cliente["id"], schedule_date)
                existing = (_resp_data(existing_resp) or [None])[0]
            except Exception:
                existing = None

            if existing:
                st.info(f"Já existe um agendamento para {schedule_date.strftime('%d/%m/%Y')} às **{existing.get('schedule_time')}**. Você pode enviar mais arquivos para esse mesmo disparo.")
                # travar horário para manter o mesmo
                try:
                    schedule_time_str = existing.get("schedule_time") or f"{schedule_time.hour:02d}:{schedule_time.minute:02d}"
                except Exception:
                    schedule_time_str = f"{schedule_time.hour:02d}:{schedule_time.minute:02d}"
            else:
                schedule_time_str = f"{schedule_time.hour:02d}:{schedule_time.minute:02d}"

            notes = st.text_input("Observação (opcional)", value="", key="cli_base_notes")
            files = st.file_uploader("Envie arquivos (CSV ou XLSX). Pode selecionar vários.", type=["csv", "xlsx", "xls"], accept_multiple_files=True, key="cli_base_files")

            go = confirm_block(
                "Confirmar envio",
                "Clique para registrar o agendamento do dia e salvar os arquivos. Você e o admin receberão e-mail de confirmação.",
                "Enviar base e agendar",
                "cli_base_submit"
            )

            if not go:
                st.info("Selecione data/horário e arquivos e clique em **Enviar base e agendar**.")
            else:
                
                if not files:
                    st.warning("Envie pelo menos 1 arquivo (CSV/XLSX).")
                    st.stop()
                
                # 1) cria agendamento se não existir
                try:
                    if existing:
                        agendamento_id = existing["id"]
                        # garante horário igual
                        schedule_time_str = existing.get("schedule_time") or schedule_time_str
                        schedule_dt_utc = existing.get("schedule_dt_utc") or _safe_dt_local_to_utc_iso(schedule_date, schedule_time)
                    else:
                        schedule_dt_utc = _safe_dt_local_to_utc_iso(schedule_date, schedule_time)
                        ins = db_insert_base_agendamento(
                            cliente_id=cliente["id"],
                            schedule_date=schedule_date,
                            schedule_time=schedule_time_str,
                            schedule_dt_utc=schedule_dt_utc,
                            created_by_email=user_email,
                            created_by_user_id=user_id,
                            notes=notes
                        )
                        agendamento_id = (_resp_data(ins) or [None])[0]["id"]
                
                    # 2) salva arquivos
                    saved = []
                    for f in files:
                        raw = f.getvalue()
                        name = f.name
                        ext = name.split(".")[-1].lower() if "." in name else ""
                        size_bytes = len(raw)
                        digest = sha256_hex(raw)
                
                        # storage
                        path = make_client_base_storage_path(cliente["slug"], schedule_date, name)
                        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if ext in ("xlsx", "xls") else "text/csv"
                        storage_upload_bytes(CLIENT_BASES_BUCKET, path, raw, content_type)
                
                        # db record
                        db_insert_base_arquivo(
                            agendamento_id=agendamento_id,
                            cliente_id=cliente["id"],
                            original_name=name,
                            file_ext=ext,
                            bucket=CLIENT_BASES_BUCKET,
                            storage_path=path,
                            size_bytes=size_bytes,
                            sha256=digest,
                            uploaded_by_email=user_email,
                            uploaded_by_user_id=user_id
                        )
                        saved.append(name)
                
                    # 3) envia e-mails (cliente + admin)                    # Notificação (no upload da base): **somente Admin**.
                    # O cliente será notificado quando o status do agendamento for marcado como **Concluído** no painel admin.
                    admin_ok = False

                    subject_admin = f"Nova base disponível — {cliente.get('razao_social','Cliente')} — {schedule_date.strftime('%d/%m/%Y')} {schedule_time_str}"
                    body_admin = f"""Admin,

O cliente enviou uma base e ela está disponível no painel.

Cliente: {cliente.get('razao_social','')}
Agendamento: {schedule_date.strftime('%d/%m/%Y')} às {schedule_time_str}
Arquivos: {', '.join(saved)}
Usuário: {user_email}
Observação: {notes or '-'}

ContactBot
"""

                    ok2, _ = send_notification_email(ADMIN_EMAIL, subject_admin, body_admin)
                    admin_ok = ok2

                    st.success("✅ Base registrada e arquivos salvos.")
                    st.caption(f"E-mail admin: {'enviado' if admin_ok else 'pendente (SMTP não ativo)'}")
                
                except Exception as e:
                    st.error(f"Falha ao registrar base: {e}")
                
                st.divider()
                st.write("#### Histórico de agendamentos (seu cliente)")
                try:
                    ags = _resp_data(db_list_base_agendamentos(cliente_id=cliente["id"], limit=50)) or []
                    if not ags:
                        st.info("Nenhum agendamento ainda.")
                    else:
                        st.dataframe([{
                            "data": a.get("schedule_date"),
                            "horário": a.get("schedule_time"),
                            "status": a.get("status"),
                            "criado_por": a.get("created_by_email"),
                            "obs": a.get("notes") or "",
                        } for a in ags], width='stretch')
                except Exception as e:
                    st.warning(f"Não foi possível carregar histórico: {e}")
                
        st.stop()

    # ============================================================
    # ADMIN — Dashboard
    # ============================================================
    with tabs[0]:
        card("Dashboard (Admin)", "Operação e visão geral. Tudo executa somente ao clicar em Confirmar.")
        st.info("Fluxo: **Campanhas** → **Uploads** → conferir em **Relatórios/Remuneração**. Bases do cliente ficam em **Bases (Agendamentos)**.")

    # ============================================================
    # ADMIN — Uploads (CSV)
    # ============================================================
    with tabs[1]:
        card("Uploads (CSV)", "Anexe os arquivos de retorno à remessa correta. Só salva quando você clicar em Salvar.")
        clientes = get_visible_clientes()
        if not clientes:
            st.warning("Nenhum cliente cadastrado.")
            st.stop()

        map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
        cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="up_cli_adm")
        cliente = map_label_to_cliente[cliente_label]

        go = confirm_block("Confirmar cliente", "Clique para listar remessas do cliente selecionado.", "Confirmar", "adm_up_go")
        if not go:
            st.info("Selecione o cliente e clique em **Confirmar**.")
        else:
            
            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=300)) or []
            if not rems:
                st.warning("Crie uma remessa primeiro (aba Campanhas/Remessas).")
                st.stop()
            
            map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems}
            rem_label = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="up_rem_adm")
            rem = map_label_to_rem[rem_label]
            
            file_tipo = st.selectbox("Tipo do arquivo", ["envios", "botoes", "base"], index=0, key="up_tipo_adm")
            uploaded = st.file_uploader("Envie um CSV", type=["csv"], key="up_file_adm")
            
            if uploaded:
                data = uploaded.getvalue()
                file_name = uploaded.name
                size_bytes = len(data)
                digest = sha256_hex(data)
            
                st.caption(f"Arquivo: **{file_name}** | {fmt_int(size_bytes)} bytes | SHA256 `{digest[:16]}...`")
            
                try:
                    headers, rows = parse_csv_preview(data, max_rows=20)
                    st.write("Colunas detectadas:", headers or "(sem cabeçalho)")
                    if rows:
                        st.dataframe(rows, width='stretch')
                except Exception as e:
                    st.warning(f"Preview falhou: {e}")
            
                if st.button("Salvar arquivo", type="primary", width='stretch', key="up_save_adm"):
                    try:
                        rem_key = remessa_get_key(rem) or f"REM-{rem.get('id')}"
                        path = make_storage_path(cliente["slug"], rem_key, file_tipo, file_name)
                        storage_upload_csv(UPLOADS_BUCKET, path, data)
            
                        db_insert_upload_record(
                            user_id=user_id,
                            user_email=user_email,
                            file_name=file_name,
                            bucket=UPLOADS_BUCKET,
                            path=path,
                            size_bytes=size_bytes,
                            sha256=digest,
                            remessa_id=rem["id"],
                            file_tipo=file_tipo
                        )
            
                        ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
                        status = remessa_status_from_uploads(ups)
                        db_update_remessa_status(rem["id"], status)
            
                        st.success(f"✅ Upload salvo. Status da remessa: **{status}**")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Falha ao salvar: {e}")
            
            st.divider()
            st.write("#### Uploads desta remessa")
            ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
            if not ups:
                st.info("Nenhum upload nesta remessa ainda.")
            else:
                st.dataframe([{
                    "data": u.get("created_at"),
                    "tipo": u.get("file_tipo"),
                    "arquivo": u.get("file_name"),
                    "tamanho": fmt_int(u.get("size_bytes")),
                    "storage_path": u.get("storage_path"),
                } for u in ups], width='stretch')
            
    # ============================================================
    # ADMIN — Campanhas (Remessas)
    # ============================================================
    with tabs[2]:
        card("Campanhas (Remessas)", "Crie e acompanhe remessas. Só executa quando clicar em botões de ação.")
        clientes = get_visible_clientes()
        if not clientes:
            st.warning("Cadastre clientes primeiro.")
            st.stop()

        map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
        cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="rem_cli_adm")
        cliente = map_label_to_cliente[cliente_label]

        c1, c2 = st.columns(2)
        with c1:
            numero = st.number_input("Número da remessa", min_value=1, step=1, value=50, key="rem_num_adm")
        with c2:
            data_rem = st.date_input("Data da remessa", value=date.today(), key="rem_data_adm")

        preview_key = remessa_key_from(numero, data_rem, cliente["slug"])
        st.success(f"Identificador: **{preview_key}**")

        observacao = st.text_input("Observação (opcional)", key="rem_obs_adm")

        if st.button("Criar remessa", type="primary", width='stretch', key="rem_create_adm"):
            try:
                db_insert_remessa(cliente["id"], numero, data_rem, preview_key, observacao)
                st.success("✅ Remessa criada.")
                st.rerun()
            except Exception as e:
                st.error(f"Erro ao criar remessa: {e}")

        st.divider()
        go = confirm_block("Confirmar listagem", "Clique para carregar as últimas remessas do cliente.", "Carregar remessas", "adm_rem_list_go")
        if not go:
            st.info("Clique em **Carregar remessas** para visualizar.")
        else:
            
            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=300)) or []
            if not rems:
                st.info("Nenhuma remessa ainda.")
            else:
                st.dataframe([{
                    "id": r.get("id"),
                    "data": r.get("data"),
                    "número": remessa_get_numero(r),
                    "remessa": remessa_get_key(r),
                    "status": r.get("status"),
                } for r in rems], width='stretch')
            
    # ============================================================
    # ADMIN — Relatórios
    # ============================================================
    with tabs[3]:
        card("Relatórios (Admin)", "Selecione filtros e clique em Confirmar. Download e sintético por status.")
        clientes = get_visible_clientes()
        if not clientes:
            st.warning("Nenhum cliente cadastrado.")
            st.stop()

        map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
        cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="adm_rep_client")
        cliente = map_label_to_cliente[cliente_label]

        today = date.today()
        c1, c2 = st.columns(2)
        with c1:
            year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="adm_rep_year")
        with c2:
            month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="adm_rep_month")

        go = confirm_block("Confirmar filtros", "Clique para listar remessas do mês.", "Confirmar e carregar", "adm_rep_go")
        if not go:
            st.info("Selecione e clique em **Confirmar e carregar**.")
        else:
            
            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=800)) or []
            
            def in_month(r):
                try:
                    d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                    return d.year == int(year) and d.month == int(month)
                except Exception:
                    return False
            
            rems_month = [r for r in rems if in_month(r)]
            if not rems_month:
                st.info("Nenhuma remessa encontrada para este mês.")
                st.stop()
            
            map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems_month}
            rem_label = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="adm_rep_rem")
            rem = map_label_to_rem[rem_label]
            
            go2 = confirm_block("Confirmar remessa", "Clique para carregar downloads e sintético desta remessa.", "Carregar remessa", "adm_rep_go2")
            if not go2:
                st.info("Selecione a remessa e clique em **Carregar remessa**.")
                st.stop()
            
            ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
            env_u = next((u for u in ups if u.get("file_tipo") == "envios"), None)
            bot_u = next((u for u in ups if u.get("file_tipo") == "botoes"), None)
            
            st.write("#### Downloads")
            d1, d2 = st.columns(2)
            with d1:
                if env_u:
                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    data = fetch_bytes_from_signed_url(url) if url else None
                    if data:
                        st.download_button("Baixar Envios (CSV)", data=data, file_name=env_u.get("file_name") or "envios.csv", mime="text/csv", width='stretch')
                    else:
                        st.warning("Sem link de envios.")
                else:
                    st.info("Envios não disponível.")
            with d2:
                if bot_u:
                    url = storage_signed_url(UPLOADS_BUCKET, bot_u.get("storage_path"), expires_in=3600)
                    data = fetch_bytes_from_signed_url(url) if url else None
                    if data:
                        st.download_button("Baixar Botões (CSV)", data=data, file_name=bot_u.get("file_name") or "botoes.csv", mime="text/csv", width='stretch')
                    else:
                        st.warning("Sem link de botões.")
                else:
                    st.info("Botões não disponível.")
            
            st.divider()
            st.write("#### Sintético + % por status (envios)")
            if not env_u:
                st.warning("Sem CSV de envios.")
            else:
                url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                csv_bytes = fetch_bytes_from_signed_url(url)
                metrics = compute_envios_metrics(csv_bytes)
            
                total_rows = int(metrics["total_rows"])
                billable = int(metrics["billable"])
                undelivered = int(metrics["undelivered"])
                by_status = metrics["by_status"]
            
                m1, m2, m3 = st.columns(3)
                m1.metric("Total linhas", fmt_int(total_rows))
                m2.metric("Cobráveis", fmt_int(billable))
                m3.metric("Undelivered", fmt_int(undelivered))
            
                st.caption(f"Coluna de status: {metrics['status_col']} | Delimitador: {metrics['delimiter']}")
                status_percent_block(by_status, total_rows)
            
    # ============================================================
    # ADMIN — Remuneração
    # ============================================================
    with tabs[4]:
        card("Remuneração (Admin)", "Detalhe por campanha e consolidado mensal. Tudo só calcula quando você confirmar.")
        clientes = get_visible_clientes()
        if not clientes:
            st.warning("Nenhum cliente cadastrado.")
            st.stop()

        map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
        cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="adm_pay_client")
        cliente = map_label_to_cliente[cliente_label]
        plano_tipo = cliente.get("plano_tipo", "pos")

        today = date.today()
        c1, c2 = st.columns(2)
        with c1:
            year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="adm_pay_year")
        with c2:
            month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="adm_pay_month")

        go = confirm_block("Confirmar filtros", "Clique para listar campanhas do mês.", "Confirmar e carregar", "adm_pay_go")
        if not go:
            st.info("Selecione e clique em **Confirmar e carregar**.")
        else:
            
            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=800)) or []
            
            def in_month(r):
                try:
                    d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                    return d.year == int(year) and d.month == int(month)
                except Exception:
                    return False
            
            rems_month = [r for r in rems if in_month(r)]
            st.caption(f"Plano do cliente: **{plano_tipo.upper()}**")
            
            if not rems_month:
                st.info("Nenhuma remessa neste mês.")
                st.stop()
            
            map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems_month}
            rem_label = st.selectbox("Campanha (remessa)", list(map_label_to_rem.keys()), key="adm_pay_rem")
            rem = map_label_to_rem[rem_label]
            
            go2 = confirm_block("Confirmar campanha", "Clique para calcular campanha e consolidado mensal.", "Calcular remuneração", "adm_pay_go2")
            if not go2:
                st.info("Selecione a campanha e clique em **Calcular remuneração**.")
                st.stop()
            
            ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
            env_u = next((u for u in ups if u.get("file_tipo") == "envios"), None)
            
            st.write("#### Por campanha (detalhado)")
            if not env_u:
                st.warning("Sem CSV de envios para esta campanha.")
            else:
                url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                csv_bytes = fetch_bytes_from_signed_url(url)
                metrics = compute_envios_metrics(csv_bytes)
            
                qty_total = int(metrics["total_rows"])
                qty_billable = int(metrics["billable"])
                qty_undel = int(metrics["undelivered"])
                unit = tier_price(plano_tipo, qty_billable)
                total = qty_billable * unit
            
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("Total linhas", fmt_int(qty_total))
                k2.metric("Cobráveis", fmt_int(qty_billable))
                k3.metric("Undelivered", fmt_int(qty_undel))
                k4.metric("Unitário", fmt_money(unit))
            
                st.success(f"Total da campanha (estimado): **{fmt_money(total)}**")
            
                nxt = next_tier(plano_tipo, qty_billable)
                if nxt:
                    a, b, p = nxt
                    falta = max(a - qty_billable, 0)
                    st.info(f"Para atingir a próxima faixa desta campanha ({fmt_money(p)}), faltam **{fmt_int(falta)}** cobráveis.")
                else:
                    st.info("Campanha já está na última faixa de preço.")
            
            st.divider()
            st.write("#### Consolidado mensal")
            rows_out = []
            total_month = 0.0
            total_billable_month = 0
            
            for r in rems_month:
                ups = _resp_data(db_list_uploads(remessa_id=r["id"], limit=200)) or []
                env_files = [u for u in ups if u.get("file_tipo") == "envios"]
                if not env_files:
                    continue
                env_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                env_u2 = env_files[0]
                url2 = storage_signed_url(UPLOADS_BUCKET, env_u2.get("storage_path"), expires_in=3600)
                if not url2:
                    continue
            
                csv_bytes2 = fetch_bytes_from_signed_url(url2)
                metrics2 = compute_envios_metrics(csv_bytes2)
                qty_billable2 = int(metrics2["billable"])
                unit2 = tier_price(plano_tipo, qty_billable2)
                tot2 = qty_billable2 * unit2
            
                total_month += tot2
                total_billable_month += qty_billable2
                rows_out.append({
                    "remessa": remessa_get_key(r),
                    "data": r.get("data"),
                    "cobráveis": qty_billable2,
                    "unit": unit2,
                    "total": tot2
                })
            
            cM1, cM2, cM3 = st.columns(3)
            cM1.metric("Cobráveis no mês", fmt_int(total_billable_month))
            cM2.metric("Acumulado no mês", fmt_money(total_month))
            a, b, p = current_tier(plano_tipo, total_billable_month if total_billable_month > 0 else (1 if plano_tipo == "pos" else 1000))
            cM3.metric("Faixa (mês)", fmt_money(p))
            
            nxtm = next_tier(plano_tipo, total_billable_month)
            if nxtm:
                na, nb, np = nxtm
                falta = max(na - total_billable_month, 0)
                st.info(f"Para atingir a próxima faixa do mês ({fmt_money(np)}), faltam **{fmt_int(falta)}** cobráveis.")
            else:
                st.info("Você já está na última faixa de preço do mês.")
            
            st.dataframe([{
                "remessa": x["remessa"],
                "data": x["data"],
                "cobráveis": fmt_int(x["cobráveis"]),
                "unitário": fmt_money(x["unit"]),
                "total": fmt_money(x["total"])
            } for x in rows_out], width='stretch')
            
    # ============================================================
    # ADMIN — Bases (Agendamentos)
    # ============================================================
    with tabs[5]:
        card("Bases (Agendamentos)", "Veja bases enviadas pelo cliente, com data/horário e arquivos. Tudo com confirmar para não travar.")

        # checagem de tabelas
        try:
            db_try_select("bases_agendamentos", 1)
            db_try_select("bases_arquivos", 1)
            ok_tables = True
        except Exception:
            ok_tables = False

        if not ok_tables:
            st.error("As tabelas de bases ainda não existem no Supabase.")
            st.write("Crie com o SQL abaixo (rode no Supabase SQL Editor):")
            st.code(
                """
-- 1) Agendamentos (1 por dia por cliente)
create table if not exists public.bases_agendamentos (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  cliente_id uuid not null references public.clientes(id) on delete cascade,
  schedule_date date not null,
  schedule_time text not null,
  schedule_dt_utc timestamptz not null,
  status text not null default 'aguardando_execucao',
  created_by_email text,
  created_by_user_id uuid,
  notes text
);

create unique index if not exists bases_agendamentos_unique_day
on public.bases_agendamentos (cliente_id, schedule_date);

-- 2) Arquivos da base (vários por agendamento)
create table if not exists public.bases_arquivos (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  agendamento_id uuid not null references public.bases_agendamentos(id) on delete cascade,
  cliente_id uuid not null references public.clientes(id) on delete cascade,
  original_name text not null,
  file_ext text,
  storage_bucket text not null,
  storage_path text not null,
  size_bytes bigint,
  sha256 text,
  uploaded_by_email text,
  uploaded_by_user_id uuid
);
                """.strip(),
                language="sql"
            )
            st.stop()

        clientes = get_visible_clientes()
        if not clientes:
            st.warning("Nenhum cliente cadastrado.")
            st.stop()

        map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
        cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="adm_base_client")
        cliente = map_label_to_cliente[cliente_label]

        go = confirm_block("Confirmar", "Clique para carregar agendamentos do cliente.", "Carregar agendamentos", "adm_base_go")
        if not go:
            st.info("Selecione e clique em **Carregar agendamentos**.")
        else:
            
            ags = _resp_data(db_list_base_agendamentos(cliente_id=cliente["id"], limit=200)) or []
            if not ags:
                st.info("Nenhum agendamento encontrado para este cliente.")
                st.stop()
            
            # escolher um agendamento
            def ag_label(a: dict) -> str:
                return f"{a.get('schedule_date')} {a.get('schedule_time')} — {a.get('status')}"
            
            ag_map = {ag_label(a): a for a in ags}
            ag_sel = st.selectbox("Agendamento", list(ag_map.keys()), key="adm_base_ag_sel")
            ag = ag_map[ag_sel]
            
            go2 = confirm_block("Confirmar agendamento", "Clique para carregar os arquivos deste agendamento.", "Carregar arquivos", "adm_base_go2")
            if not go2:
                st.info("Clique em **Carregar arquivos**.")
                st.stop()
            
            files = _resp_data(db_list_base_arquivos(agendamento_id=ag["id"], limit=300)) or []
            st.write("#### Detalhes")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Data", str(ag.get("schedule_date")))
            c2.metric("Horário", str(ag.get("schedule_time")))
            c3.metric("Status", str(ag.get("status")))
            c4.metric("Arquivos", fmt_int(len(files)))
            
            if not files:
                st.info("Nenhum arquivo neste agendamento.")
            else:
                st.write("#### Arquivos")
                st.dataframe([{
                    "quando": f.get("created_at"),
                    "arquivo": f.get("original_name"),
                    "ext": f.get("file_ext") or "",
                    "tamanho": fmt_int(f.get("size_bytes")),
                    "sha256": (f.get("sha256") or "")[:12] + "...",
                    "storage": f.get("storage_path"),
                } for f in files], width='stretch')
            
                st.write("#### Download (links assinados)")
                for f in files[:50]:
                    url = storage_signed_url(f.get("storage_bucket"), f.get("storage_path"), expires_in=3600)
                    if url:
                        st.markdown(f"- **{f.get('original_name')}** — link assinado gerado (válido por 1h).")
                        st.code(url, language="text")
            
    # ============================================================
    # ADMIN — Configurações
    # ============================================================
    with tabs[6]:
        card("Configurações (Admin)", "Clientes, faixas, e-mail, PIX, entrega e usuários dos clientes.")
        sec = st.tabs(["Clientes", "Valores (Remuneração)", "E-mail (SMTP)", "PIX (Mercado Pago)", "Entrega por e-mail", "Usuários (Clientes)"])

        # ---- Clientes
        with sec[0]:
            st.write("### Clientes")
            clientes = _resp_data(db_list_clientes()) or []

            with st.expander("➕ Cadastrar novo cliente", expanded=True):
                cnpj = st.text_input("CNPJ", value="", key="adm_cnpj")
                razao = st.text_input("Razão social", value="", key="adm_razao")
                contato_nome = st.text_input("Contato (nome)", value="", key="adm_contato_nome")
                contato_email = st.text_input("Contato (e-mail)", value="", key="adm_contato_email")
                contato_whatsapp = st.text_input("Contato (WhatsApp)", value="", key="adm_contato_whats")

                plano_label = st.selectbox("Plano", ["Pós-pago", "Pré-pago"], index=0, key="adm_plano")
                plano_tipo = "pos" if plano_label == "Pós-pago" else "pre"

                if st.button("Salvar cliente", type="primary", width='stretch', key="adm_save_cliente"):
                    try:
                        if not (cnpj or "").strip():
                            st.warning("Informe o CNPJ.")
                            st.stop()
                        if not (razao or "").strip():
                            st.warning("Informe a Razão Social.")
                            st.stop()
                        if not (contato_email or "").strip():
                            st.warning("Informe o e-mail do contato.")
                            st.stop()
                        db_insert_cliente(cnpj, razao, contato_nome, contato_email, contato_whatsapp, plano_tipo)
                        st.success("✅ Cliente cadastrado.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erro ao cadastrar cliente: {e}")

            st.divider()
            if not clientes:
                st.info("Nenhum cliente cadastrado ainda.")
            else:
                st.dataframe([{
                    "id": c.get("id"),
                    "cnpj": c.get("cnpj"),
                    "razao_social": c.get("razao_social"),
                    "slug": c.get("slug"),
                    "plano_tipo": c.get("plano_tipo"),
                    "contato_email": c.get("contato_email") or c.get("email_principal"),
                    "ativo": c.get("ativo"),
                } for c in clientes], width='stretch')

        # ---- Valores remuneração
        with sec[1]:
            st.write("### Valores (Remuneração) — por faixa")
            st.caption("Edite SOMENTE o valor unitário (R$). Quantidades ficam fixas.")

            def render_tiers(plan_tipo: str, title: str):
                st.subheader(title)
                try:
                    rows = _resp_data(db_list_pricing_tiers(plan_tipo)) or []
                    rows = sorted(rows, key=lambda x: int(x.get("min_qty") or 0))
                except Exception as e:
                    st.error(f"Erro ao acessar pricing_tiers ({plan_tipo}): {e}")
                    return

                if not rows:
                    st.warning("Sem faixas no banco.")
                    if st.button(f"Criar faixas padrão ({plan_tipo.upper()})", key=f"seed_{plan_tipo}", width='stretch'):
                        seed = []
                        for mn, mx, pr in DEFAULT_TIERS[plan_tipo]:
                            seed.append({"plano_tipo": plan_tipo, "min_qty": int(mn), "max_qty": int(mx), "unit_price": float(pr), "ativo": True})
                        db_insert_pricing_tiers(seed)
                        st.success("✅ Faixas criadas.")
                        st.rerun()
                    return

                for r in rows:
                    mn = int(r.get("min_qty") or 0)
                    mx = int(r.get("max_qty") or 10**12)
                    pr = float(r.get("unit_price") or 0.0)
                    ativo = bool(r.get("ativo", True))

                    label = f"DE {fmt_int(mn)} A {fmt_int(mx)}" if mx < 10**11 else f"ACIMA DE {fmt_int(mn)}"
                    with st.expander(f"{label}  →  {fmt_money(pr)}", expanded=False):
                        c1, c2, c3, c4 = st.columns([1, 1, 1.4, 1])
                        with c1:
                            st.number_input("Min", value=mn, disabled=True, key=f"{plan_tipo}_mn_{r['id']}")
                        with c2:
                            st.number_input("Max", value=mx, disabled=True, key=f"{plan_tipo}_mx_{r['id']}")
                        with c3:
                            new_price = st.number_input("Valor unitário (R$)", value=pr, step=0.01, key=f"{plan_tipo}_pr_{r['id']}")
                        with c4:
                            new_ativo = st.checkbox("Ativo", value=ativo, key=f"{plan_tipo}_at_{r['id']}")

                        if st.button("Salvar", key=f"{plan_tipo}_save_{r['id']}", width='stretch'):
                            db_update_pricing_tier(r["id"], {"unit_price": float(new_price), "ativo": bool(new_ativo)})
                            st.success("✅ Salvo.")
                            st.rerun()

            render_tiers("pos", "PÓS-PAGO")
            st.divider()
            render_tiers("pre", "PRÉ-PAGO")

        # ---- E-mail config
        with sec[2]:
            st.write("### E-mail (SMTP)")
            st.caption("Porta **465 (SSL)**. Preencha e salve. Isso habilita notificações ao cliente e ao admin.")

            existing = _resp_data(db_get_email_config())
            row = existing[0] if existing else {}

            is_active = st.checkbox("Ativar envio por e-mail", value=bool(row.get("is_active", False)), key="em_active")
            smtp_host = st.text_input("SMTP Host", value=row.get("smtp_host") or "", key="em_host")
            smtp_port = st.number_input("SMTP Port", value=int(row.get("smtp_port") or DEFAULT_SMTP_PORT), step=1, key="em_port")
            smtp_user = st.text_input("SMTP User", value=row.get("smtp_user") or "", key="em_user")
            smtp_pass = st.text_input("SMTP Pass", value=row.get("smtp_pass") or "", type="password", key="em_pass")

            from_name = st.text_input("From Name", value=row.get("from_name") or "ContactBot", key="em_from_name")
            from_email = st.text_input("From E-mail", value=row.get("from_email") or smtp_user or "", key="em_from_email")

            template_assunto = st.text_input("Template de assunto", value=row.get("template_assunto") or "Relatório ContactBot — {cliente} — {mes}/{ano}", key="em_subj")
            template_corpo = st.text_area("Template de mensagem", value=row.get("template_corpo") or "Olá, segue o relatório.\n\nAtt,\nContactBot", height=160, key="em_body")

            if st.button("Salvar configurações de e-mail", width='stretch', key="em_save"):
                db_upsert_email_config({
                    "is_active": bool(is_active),
                    "smtp_host": (smtp_host or "").strip() or None,
                    "smtp_port": int(smtp_port),
                    "smtp_user": (smtp_user or "").strip() or None,
                    "smtp_pass": (smtp_pass or "").strip() or None,
                    "from_name": (from_name or "").strip() or None,
                    "from_email": (from_email or "").strip() or None,
                    "template_assunto": (template_assunto or "").strip() or None,
                    "template_corpo": (template_corpo or "").strip() or None,
                })
                st.success("✅ Configurações salvas.")
                st.rerun()

        # ---- Mercado Pago
        with sec[3]:
            st.write("### PIX (Mercado Pago)")
            existing = _resp_data(db_get_mercadopago_config())
            row = existing[0] if existing else {}

            mp_active = st.checkbox("Ativar integração Mercado Pago", value=bool(row.get("is_active", False)), key="mp_active")
            access_token = st.text_input("Access Token", value=row.get("access_token") or "", type="password", key="mp_token")
            public_key = st.text_input("Public Key", value=row.get("public_key") or "", key="mp_pub")
            webhook_secret = st.text_input("Webhook Secret", value=row.get("webhook_secret") or "", type="password", key="mp_webhook")

            if st.button("Salvar configurações Mercado Pago", width='stretch', key="mp_save"):
                db_upsert_mercadopago_config({
                    "is_active": bool(mp_active),
                    "access_token": (access_token or "").strip() or None,
                    "public_key": (public_key or "").strip() or None,
                    "webhook_secret": (webhook_secret or "").strip() or None,
                })
                st.success("✅ Configurações salvas.")
                st.rerun()

        # ---- Entrega por e-mail + Auditoria
        with sec[4]:
            st.write("### Entrega por e-mail (anexos) + Auditoria")
            clientes = _resp_data(db_list_clientes()) or []
            if not clientes:
                st.warning("Cadastre um cliente primeiro.")
                st.stop()

            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="mail_cli")
            cliente = map_label_to_cliente[cliente_label]

            go = confirm_block("Confirmar cliente", "Clique para listar remessas e liberar o envio.", "Confirmar", "mail_go")
            if not go:
                st.info("Clique em **Confirmar**.")
            else:
                
                rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=400)) or []
                if not rems:
                    st.warning("Crie uma remessa primeiro.")
                    st.stop()
                
                map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems}
                rem_label = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="mail_rem")
                rem = map_label_to_rem[rem_label]
                
                go2 = confirm_block("Confirmar remessa", "Clique para carregar anexos e liberar o envio.", "Carregar remessa", "mail_go2")
                if not go2:
                    st.info("Clique em **Carregar remessa**.")
                    st.stop()
                
                ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200)) or []
                env_u = next((u for u in ups if u.get("file_tipo") == "envios"), None)
                bot_u = next((u for u in ups if u.get("file_tipo") == "botoes"), None)
                
                cA, cB, cC = st.columns([1, 1, 2])
                with cA:
                    st.markdown(f"<span class='cb-pill'>Envios: {'OK' if env_u else 'Pendente'}</span>", unsafe_allow_html=True)
                with cB:
                    st.markdown(f"<span class='cb-pill'>Botões: {'OK' if bot_u else 'Pendente'}</span>", unsafe_allow_html=True)
                with cC:
                    st.markdown(f"<span class='cb-muted'>Destino padrão: <b>{cliente.get('contato_email') or cliente.get('email_principal') or '-'}</b></span>", unsafe_allow_html=True)
                
                email_cfg_rows = _resp_data(db_get_email_config())
                if not email_cfg_rows or not bool(email_cfg_rows[0].get("is_active", False)):
                    st.warning("Configure e ative o SMTP em **E-mail (SMTP)**.")
                    st.stop()
                
                cfg = email_cfg_rows[0]
                to_default = (cliente.get("contato_email") or cliente.get("email_principal") or "").strip()
                to_email = st.text_input("E-mail de destino", value=to_default, key="mail_to")
                
                d = datetime.strptime(rem.get("data"), "%Y-%m-%d").date() if rem.get("data") else date.today()
                subj_tpl = cfg.get("template_assunto") or "Relatório ContactBot — {cliente} — {mes}/{ano}"
                body_tpl = cfg.get("template_corpo") or "Olá, segue o relatório.\n\nAtt,\nContactBot"
                
                assunto_prev = subj_tpl.format(cliente=cliente.get("razao_social", ""), mes=d.month, ano=d.year, remessa=remessa_get_key(rem))
                corpo_prev = body_tpl.format(cliente=cliente.get("razao_social", ""), mes=d.month, ano=d.year, remessa=remessa_get_key(rem))
                
                st.text_input("Assunto (prévia)", value=assunto_prev, key="mail_subj")
                st.text_area("Mensagem (prévia)", value=corpo_prev, height=120, key="mail_body")
                
                can_send = bool(env_u or bot_u) and bool(to_email.strip())
                
                if st.button("Enviar relatório desta remessa", type="primary", width='stretch', disabled=not can_send, key="mail_send"):
                    started = datetime.now(timezone.utc).isoformat()
                    attachments: List[Tuple[str, bytes, str]] = []
                    attach_meta = []
                
                    try:
                        for u, label in [(env_u, "envios"), (bot_u, "botoes")]:
                            if not u:
                                continue
                            url = storage_signed_url(UPLOADS_BUCKET, u.get("storage_path"), expires_in=3600)
                            if not url:
                                raise RuntimeError(f"Sem link assinado para {label}.")
                            data = fetch_bytes_from_signed_url(url)
                            filename = u.get("file_name") or f"{label}.csv"
                            attachments.append((filename, data, "text/csv"))
                            attach_meta.append({
                                "tipo": label,
                                "file_name": filename,
                                "bytes": len(data),
                                "sha256": u.get("sha256"),
                                "storage_path": u.get("storage_path"),
                            })
                
                        smtp_send_email_ssl(
                            host=(cfg.get("smtp_host") or "").strip(),
                            port=int(cfg.get("smtp_port") or DEFAULT_SMTP_PORT),
                            user=(cfg.get("smtp_user") or "").strip(),
                            password=(cfg.get("smtp_pass") or "").strip(),
                            from_name=(cfg.get("from_name") or "ContactBot").strip(),
                            from_email=(cfg.get("from_email") or cfg.get("smtp_user") or "").strip(),
                            to_email=to_email.strip(),
                            subject=assunto_prev,
                            body=corpo_prev,
                            attachments=attachments,
                        )
                
                        db_insert_email_log({
                            "status": "sent",
                            "cliente_id": cliente["id"],
                            "remessa_id": rem["id"],
                            "to_email": to_email.strip(),
                            "subject": assunto_prev,
                            "body_preview": (corpo_prev or "")[:4000],
                            "attachments_json": json.dumps(attach_meta, ensure_ascii=False),
                            "user_email": user_email,
                            "started_at": started,
                            "finished_at": datetime.now(timezone.utc).isoformat(),
                        })
                
                        st.success("✅ E-mail enviado e auditado.")
                        st.rerun()
                
                    except Exception as e:
                        try:
                            db_insert_email_log({
                                "status": "error",
                                "cliente_id": cliente["id"],
                                "remessa_id": rem["id"],
                                "to_email": to_email.strip(),
                                "subject": assunto_prev,
                                "body_preview": (corpo_prev or "")[:4000],
                                "attachments_json": json.dumps(attach_meta, ensure_ascii=False),
                                "user_email": user_email,
                                "started_at": started,
                                "finished_at": datetime.now(timezone.utc).isoformat(),
                                "error_message": str(e)[:4000],
                            })
                        except Exception:
                            pass
                        st.error(f"Falha no envio: {e}")
                
                st.divider()
                st.write("#### Auditoria (histórico)")
                
                logs = _resp_data(db_list_email_logs(cliente_id=cliente["id"], remessa_id=rem["id"], status=None, limit=300)) or []
                existing_statuses = sorted(list({(l.get("status") or "").strip() for l in logs if (l.get("status") or "").strip()}))
                options = ["Todos"] + (existing_statuses if existing_statuses else ["sent", "error"])
                
                f1, f2 = st.columns([1, 1])
                with f1:
                    status_filter = st.selectbox("Status", options, index=0, key="mail_log_status")
                with f2:
                    limit = st.number_input("Quantidade", min_value=50, max_value=500, value=200, step=50, key="mail_log_limit")
                
                logs2 = _resp_data(db_list_email_logs(cliente_id=cliente["id"], remessa_id=rem["id"], status=status_filter, limit=int(limit))) or []
                if not logs2:
                    st.info("Nenhum registro encontrado para este filtro.")
                else:
                    out = []
                    for l in logs2:
                        try:
                            attaches = json.loads(l.get("attachments_json") or "[]")
                            attach_txt = ", ".join([f"{a.get('tipo')}({fmt_int(a.get('bytes'))}b)" for a in attaches]) if attaches else "-"
                        except Exception:
                            attach_txt = "-"
                        out.append({
                            "quando": l.get("created_at") or l.get("finished_at") or "",
                            "status": l.get("status"),
                            "destino": l.get("to_email"),
                            "assunto": l.get("subject"),
                            "anexos": attach_txt,
                            "usuário": l.get("user_email") or "",
                            "erro": (l.get("error_message") or "")[:180] if l.get("status") == "error" else "",
                        })
                    st.dataframe(out, width='stretch')
                
        # ---- Usuários (Clientes)
        with sec[5]:
            st.write("### Usuários (Clientes)")
            st.caption("Você cria e define senha (sem convite). Depois vincula ao cliente (acesso restrito e seguro).")

            clientes = _resp_data(db_list_clientes()) or []
            if not clientes:
                st.warning("Cadastre um cliente primeiro.")
                st.stop()

            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="u_cli")
            cliente = map_label_to_cliente[cliente_label]

            with st.expander("➕ Criar usuário do cliente / Definir senha", expanded=True):
                u_email = st.text_input("E-mail do usuário", value="", key="u_email")
                u_pass1 = st.text_input("Senha", value="", type="password", key="u_pass1")
                u_pass2 = st.text_input("Confirmar senha", value="", type="password", key="u_pass2")
                u_role = st.selectbox("Perfil", ["client", "admin"], index=0, key="u_role")
                u_active = st.checkbox("Ativo", value=True, key="u_active")

                colb1, colb2 = st.columns(2)
                with colb1:
                    if st.button("Criar usuário + Vincular", width='stretch', key="u_create_link"):
                        try:
                            if not u_email.strip():
                                st.warning("Informe o e-mail.")
                                st.stop()
                            if not u_pass1.strip() or not u_pass2.strip():
                                st.warning("Informe a senha e confirme.")
                                st.stop()
                            if u_pass1 != u_pass2:
                                st.warning("As senhas não batem.")
                                st.stop()

                            admin_create_user(u_email, u_pass1)
                            u_found = admin_find_user_by_email(u_email)
                            uid = (u_found or {}).get("id") if u_found else None

                            db_upsert_client_user(cliente_id=cliente["id"], user_email=u_email, user_id=uid, role=u_role, ativo=u_active)

                            st.success("✅ Usuário criado e vinculado ao cliente.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao criar/vincular: {e}")

                with colb2:
                    if st.button("Apenas resetar senha", width='stretch', key="u_reset"):
                        try:
                            if not u_email.strip():
                                st.warning("Informe o e-mail.")
                                st.stop()
                            if not u_pass1.strip() or not u_pass2.strip():
                                st.warning("Informe a senha e confirme.")
                                st.stop()
                            if u_pass1 != u_pass2:
                                st.warning("As senhas não batem.")
                                st.stop()

                            user_obj, action = admin_set_password(u_email, u_pass1, create_if_missing=False)
                            try:
                                uid = (user_obj or {}).get("id")
                                if uid:
                                    db_upsert_client_user(cliente_id, u_email, uid, u_role, bool(u_active))
                            except Exception:
                                pass

                            st.success("✅ Usuário criado no Auth e senha definida." if action == "created" else "✅ Senha atualizada.")
                        except Exception as e:
                            st.error(f"Erro ao resetar senha: {e}")

            st.divider()
            st.write("#### Acessos vinculados ao cliente")
            try:
                rows = _resp_data(db_list_client_users(cliente_id=cliente["id"], limit=200)) or []
                if not rows:
                    st.info("Nenhum usuário vinculado ainda.")
                else:
                    st.dataframe([{
                        "created_at": r.get("created_at"),
                        "user_email": r.get("user_email"),
                        "role": r.get("role"),
                        "ativo": r.get("ativo"),
                        "user_id": r.get("user_id"),
                    } for r in rows], width='stretch')
            except Exception:
                st.error("A tabela client_users não foi encontrada (rode o SQL do client_users).")

    st.stop()

# ============================================================
# LOGIN (não logado)
# ============================================================
st.subheader("🔐 Login")

col_left, col_right = st.columns([1.2, 1.0], gap="large")

with col_left:
    st.subheader("Entrar")
    login_email = st.text_input("E-mail", value="", placeholder="seuemail@dominio.com")
    login_pass = st.text_input("Senha", value="", type="password", placeholder="Digite sua senha")

    if st.button("Entrar", type="primary", width='stretch'):
        try:
            resp = do_login(login_email, login_pass)
            ok = session_set_from_auth_response(resp)
            if ok:
                st.success("✅ Login OK!")
                st.rerun()
            else:
                st.error("Login não retornou sessão.")
        except Exception as e:
            st.error(f"Login falhou: {e}")

with col_right:
    st.subheader("Acesso")
    st.caption("As credenciais de empresas são criadas pelo administrador (controlado e seguro).")
    st.info("Se você é cliente e ainda não tem acesso, solicite ao administrador.")

st.divider()
st.caption("Reset por e-mail permanece desativado neste app (decisão de segurança).")
