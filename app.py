import os
import io
import csv
import re
import hashlib
import time
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, date
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# =========================
# Config
# =========================
st.set_page_config(page_title="ContactBot", layout="wide")
load_dotenv()

# =========================
# UI (cinza/azul) — leve, profissional, sem quebrar nada
# =========================
st.markdown(
    """
    <style>
      :root { --cb-blue:#1e5aa8; --cb-blue2:#2b6cb0; --cb-gray:#f5f7fb; --cb-gray2:#eef2f7; --cb-text:#0f172a; }
      .block-container { padding-top: 2rem; }
      h1, h2, h3, h4, h5 { color: var(--cb-text); }
      div[data-testid="stMetricValue"] { color: var(--cb-text); }
      .stTabs [data-baseweb="tab"] { font-weight: 600; }
      .stTabs [aria-selected="true"] { color: var(--cb-blue) !important; }
      .stAlert { border-radius: 12px; }
      .stDataFrame { border-radius: 12px; overflow: hidden; }
      .stButton>button {
        border-radius: 10px;
        border: 1px solid rgba(30,90,168,0.25);
      }
      .stButton>button[kind="primary"] {
        background: linear-gradient(90deg, var(--cb-blue), var(--cb-blue2));
        border: 0 !important;
        color: white !important;
      }
      .stCaption { color: rgba(15, 23, 42, 0.65); }
    </style>
    """,
    unsafe_allow_html=True
)

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

# ADMIN (apenas seu usuário)
ADMIN_EMAIL = "amadvjuridica@gmail.com"

# =========================
# Faixas padrão (fallback)
# =========================
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
        st.error(f"Faltando configuração: {', '.join(missing)}")
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

# =========================
# Robustez: execute com retry (evita instabilidade httpx derrubar a tela)
# =========================
def _execute_with_retry(builder, tries: int = 4, base_sleep: float = 0.6):
    last = None
    for i in range(tries):
        try:
            return builder.execute()
        except Exception as e:
            last = e
            time.sleep(base_sleep * (2 ** i))
    raise last

# =========================
# Sessão (página única)
# =========================
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

# =========================
# Auth/Admin (mantido)
# =========================
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

def admin_set_password(email: str, new_password: str):
    u = admin_find_user_by_email(email)
    if not u:
        raise ValueError("Não encontrei esse e-mail no Supabase Auth > Users.")
    uid = u.get("id")
    return supabase_admin.auth.admin.update_user_by_id(uid, {"password": new_password.strip()})

def do_login(email: str, password: str):
    return supabase_public.auth.sign_in_with_password({"email": email.strip(), "password": password.strip()})

def do_signup(email: str, password: str):
    # self-signup (sem admin)
    return supabase_public.auth.sign_up({"email": email.strip(), "password": password.strip()})

# =========================
# Utils: slug e remessa_key
# =========================
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

def fmt_int_pt(n: Optional[int]) -> str:
    if n is None:
        return "-"
    try:
        return f"{int(n):,}".replace(",", ".")
    except Exception:
        return str(n)

def fmt_brl(v: Optional[float]) -> str:
    if v is None:
        return "-"
    try:
        s = f"{float(v):,.2f}"
        return "R$ " + s.replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return str(v)

# =========================
# DB helpers
# =========================
def _resp_data(resp):
    return getattr(resp, "data", None) or (resp.get("data", []) if isinstance(resp, dict) else [])

# ---- clientes
def db_list_clientes():
    return _execute_with_retry(supabase_admin.table("clientes").select("*").order("razao_social"))

def _cliente_email_destino(c: dict) -> str:
    return (
        (c.get("email_principal") or "").strip()
        or (c.get("contato_email") or "").strip()
        or (c.get("email") or "").strip()
        or (c.get("email_contato") or "").strip()
    )

def db_insert_cliente(cnpj, razao, contato_nome, contato_email, contato_whatsapp, plano_tipo):
    slug = slugify(razao)
    payload = {
        "cnpj": (cnpj or "").strip(),
        "razao_social": (razao or "").strip(),
        "slug": slug,
        "plano_tipo": plano_tipo,
        "ativo": True
    }

    email_principal = (contato_email or "").strip()
    if email_principal:
        payload["email_principal"] = email_principal

    if (contato_nome or "").strip():
        payload["contato_nome"] = (contato_nome or "").strip()
    if (contato_email or "").strip():
        payload["contato_email"] = (contato_email or "").strip()
    if (contato_whatsapp or "").strip():
        payload["contato_whatsapp"] = (contato_whatsapp or "").strip()

    return _execute_with_retry(supabase_admin.table("clientes").insert(payload))

def db_update_cliente(cliente_id, payload: dict):
    return _execute_with_retry(supabase_admin.table("clientes").update(payload).eq("id", cliente_id))

# ---- remessas
def db_list_remessas(cliente_id=None, limit=100):
    q = supabase_admin.table("remessas").select("*").order("data", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    return _execute_with_retry(q)

def db_insert_remessa(cliente_id, numero_remessa, data_remessa, remessa_key, observacao=None):
    payload = {
        "cliente_id": cliente_id,
        "data": str(data_remessa),
        "status": "aguardando_upload",
        "observacao": (observacao or "").strip() or None,
        "remessa_key": remessa_key,
    }
    try:
        payload_try = dict(payload)
        payload_try["numero"] = int(numero_remessa)
        return _execute_with_retry(supabase_admin.table("remessas").insert(payload_try))
    except Exception:
        payload_try = dict(payload)
        payload_try["numero_remessa"] = int(numero_remessa)
        return _execute_with_retry(supabase_admin.table("remessas").insert(payload_try))

def db_update_remessa_status(remessa_id: str, status: str):
    return _execute_with_retry(supabase_admin.table("remessas").update({"status": status}).eq("id", remessa_id))

# ---- uploads
def db_insert_upload_record(user_id, user_email, file_name, bucket, path, size_bytes, sha256, remessa_id, file_tipo):
    return _execute_with_retry(
        supabase_admin.table("uploads").insert({
            "user_id": user_id,
            "user_email": user_email,
            "file_name": file_name,
            "storage_bucket": bucket,
            "storage_path": path,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "remessa_id": remessa_id,
            "file_tipo": file_tipo
        })
    )

def db_list_uploads(remessa_id=None, limit=100):
    q = supabase_admin.table("uploads").select("*").order("created_at", desc=True).limit(limit)
    if remessa_id:
        q = q.eq("remessa_id", remessa_id)
    return _execute_with_retry(q)

# ---- Admin tables (config)
def db_get_email_config():
    return _execute_with_retry(supabase_admin.table("email_config").select("*").order("created_at", desc=True).limit(1))

def db_upsert_email_config(payload: dict):
    existing = _resp_data(db_get_email_config())
    if existing:
        row_id = existing[0]["id"]
        return _execute_with_retry(supabase_admin.table("email_config").update(payload).eq("id", row_id))
    return _execute_with_retry(supabase_admin.table("email_config").insert(payload))

def db_get_mercadopago_config():
    return _execute_with_retry(supabase_admin.table("mercadopago_config").select("*").order("created_at", desc=True).limit(1))

def db_upsert_mercadopago_config(payload: dict):
    existing = _resp_data(db_get_mercadopago_config())
    if existing:
        row_id = existing[0]["id"]
        return _execute_with_retry(supabase_admin.table("mercadopago_config").update(payload).eq("id", row_id))
    return _execute_with_retry(supabase_admin.table("mercadopago_config").insert(payload))

# ---- Pricing tiers (faixas)
def db_list_pricing_tiers(plan_tipo: str):
    return _execute_with_retry(supabase_admin.table("pricing_tiers").select("*").eq("plano_tipo", plan_tipo).order("min_qty"))

def db_update_pricing_tier(row_id: str, payload: dict):
    return _execute_with_retry(supabase_admin.table("pricing_tiers").update(payload).eq("id", row_id))

def db_insert_pricing_tiers(rows: list[dict]):
    return _execute_with_retry(supabase_admin.table("pricing_tiers").insert(rows))

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

# ---- Email logs (AUDITORIA)
def db_insert_email_log(payload: dict):
    # agora é "obrigatório" existir para auditoria 100%
    return _execute_with_retry(supabase_admin.table("email_logs").insert(payload))

def db_list_email_logs(cliente_id: Optional[str] = None, remessa_id: Optional[str] = None, status: Optional[str] = None, limit: int = 200):
    q = supabase_admin.table("email_logs").select("*").order("created_at", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    if remessa_id:
        q = q.eq("remessa_id", remessa_id)
    if status:
        q = q.eq("status", status)
    return _execute_with_retry(q)

# =========================
# Storage helpers
# =========================
def storage_upload_csv(bucket: str, path: str, data: bytes):
    return supabase_admin.storage.from_(bucket).upload(
        path,
        data,
        file_options={"content-type": "text/csv", "upsert": False},
    )

def storage_signed_url(bucket: str, path: str, expires_in: int = 3600) -> str:
    resp = supabase_admin.storage.from_(bucket).create_signed_url(path, expires_in)
    if isinstance(resp, dict) and "signedURL" in resp:
        return resp["signedURL"]
    if isinstance(resp, dict) and "data" in resp and isinstance(resp["data"], dict):
        return resp["data"].get("signedUrl") or resp["data"].get("signedURL") or ""
    return ""

def fetch_bytes_from_signed_url(url: str) -> bytes:
    import requests
    r = requests.get(url, timeout=90)
    r.raise_for_status()
    return r.content

# =========================
# Parse Envios CSV -> métricas (ignora linhas vazias)
# =========================
def infer_status_column(headers: list[str]) -> str | None:
    candidates = ["message_status", "status", "situacao", "estado", "resultado", "delivery_status", "messageStatus"]
    lowered = {h.lower(): h for h in headers}
    for c in candidates:
        if c.lower() in lowered:
            return lowered[c.lower()]
    for h in headers:
        if "status" in h.lower():
            return h
    return None

def _row_is_blank(row: dict) -> bool:
    if not row:
        return True
    for v in row.values():
        if v is None:
            continue
        if str(v).strip() != "":
            return False
    return True

def compute_envios_metrics(csv_bytes: bytes):
    text = csv_bytes.decode("utf-8", errors="replace")
    f = io.StringIO(text)
    reader = csv.DictReader(f, delimiter=";")
    headers = reader.fieldnames or []
    status_col = infer_status_column(headers)

    counts = {
        "total_rows": 0,
        "billable": 0,
        "undelivered": 0,
        "by_status": {},
        "status_col": status_col or "",
        "delimiter": ";",
    }

    for row in reader:
        if _row_is_blank(row):
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
            else:
                pass

    return counts

# =========================
# Status da remessa baseado em uploads
# =========================
def remessa_status_from_uploads(uploads_rows: list[dict]) -> str:
    tipos = {u.get("file_tipo") for u in uploads_rows}
    has_envios = "envios" in tipos
    has_botoes = "botoes" in tipos
    if has_envios and has_botoes:
        return "completa"
    if has_envios or has_botoes:
        return "parcial"
    return "aguardando_upload"

# =========================
# E-mail (SMTP) — 465 = SSL direto
# =========================
def smtp_send_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    from_name: str,
    from_email: str,
    to_email: str,
    subject: str,
    body_text: str,
    attachments: List[Tuple[str, bytes, str]],
    use_ssl_direct: bool = True,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_email}>".strip()
    msg["To"] = to_email
    msg.set_content(body_text or "")

    for filename, content, mime in attachments:
        maintype, subtype = "application", "octet-stream"
        if mime and "/" in mime:
            maintype, subtype = mime.split("/", 1)
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)

    if use_ssl_direct or int(smtp_port) == 465:
        with smtplib.SMTP_SSL(smtp_host, int(smtp_port), timeout=45) as server:
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=45) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)

def build_email_from_template(template: str, vars_map: dict) -> str:
    out = template or ""
    for k, v in vars_map.items():
        out = out.replace("{" + k + "}", str(v))
    return out

def get_latest_envios_upload(uploads: List[dict]) -> Optional[dict]:
    envs = [u for u in uploads if u.get("file_tipo") == "envios"]
    if not envs:
        return None
    envs.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return envs[0]

def get_latest_botoes_upload(uploads: List[dict]) -> Optional[dict]:
    bts = [u for u in uploads if u.get("file_tipo") == "botoes"]
    if not bts:
        return None
    bts.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return bts[0]

# =========================
# Controle de acesso simples (sem mexer no login)
# - Admin vê tudo
# - Cliente (não-admin) vê apenas o cliente cujo email_principal = email do usuário
# =========================
def filter_clientes_for_user(clientes: List[dict], user_email: str) -> List[dict]:
    if is_admin_user():
        return clientes
    ue = (user_email or "").strip().lower()
    out = []
    for c in clientes:
        em = _cliente_email_destino(c).strip().lower()
        if em and em == ue:
            out.append(c)
    return out

# =========================
# UI
# =========================
st.title("ContactBot")

with st.expander("Diagnóstico (configuração)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))
    st.write("UPLOADS_BUCKET:", UPLOADS_BUCKET)
    st.write("ADMIN_EMAIL:", ADMIN_EMAIL)

# =========================
# Painel (logado)
# =========================
if session_is_logged_in():
    user = st.session_state.get("user", {}) or {}
    user_email = user.get("email", "")
    user_id = user.get("id", "")

    top_l, top_r = st.columns([4, 1])
    with top_l:
        st.subheader("Painel")
        st.caption(f"Usuário: {user_email} • ID: {user_id}")
    with top_r:
        if st.button("Sair", use_container_width=True):
            do_logout()

    st.divider()

    base_tabs = ["Visão geral", "Uploads", "Remessas", "Relatórios", "Remuneração"]
    if is_admin_user():
        base_tabs.append("Admin")
    tabs = st.tabs(base_tabs)

    # -------------------------
    # Visão geral
    # -------------------------
    with tabs[0]:
        st.info("Visão geral será consolidada após automatizarmos relatórios e rotinas do pré-pago (saldo/recarga).")

    # -------------------------
    # Uploads
    # -------------------------
    with tabs[1]:
        st.write("### Uploads")
        st.caption("Envie os arquivos CSV de retorno (Envios e Botões) vinculando à remessa correta.")

        all_clientes = _resp_data(db_list_clientes())
        clientes = filter_clientes_for_user(all_clientes, user_email)

        if not clientes:
            if is_admin_user():
                st.warning("Nenhum cliente cadastrado. Vá em **Admin → Clientes** e cadastre o primeiro.")
            else:
                st.warning("Seu usuário ainda não está vinculado a nenhum cliente (e-mail não bate com o e-mail principal cadastrado).")
        else:
            map_label_to_cliente = {f'{c.get("razao_social","")} ({c.get("slug","")})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="up_cli")
            cliente = map_label_to_cliente[cliente_label]

            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=100))
            if not rems:
                st.warning("Crie uma remessa primeiro (aba Remessas).")
            else:
                def rem_label(r):
                    rk = r.get("remessa_key") or "-"
                    rid = r.get("id")
                    num = r.get("numero") or r.get("numero_remessa") or "-"
                    dt = r.get("data") or "-"
                    return f"{rk} (nº {num}, {dt}, id {rid})"

                map_label_to_rem = {rem_label(r): r for r in rems}
                rem_label_sel = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="up_rem")
                rem = map_label_to_rem[rem_label_sel]

                file_tipo = st.selectbox("Tipo do arquivo", ["envios", "botoes", "base"], index=0)
                uploaded = st.file_uploader("Selecione um CSV", type=["csv"])

                if uploaded:
                    data = uploaded.getvalue()
                    file_name = uploaded.name
                    size_bytes = len(data)
                    digest = sha256_hex(data)

                    st.caption(f"Arquivo: **{file_name}** • {fmt_int_pt(size_bytes)} bytes • SHA256 `{digest[:16]}...`")

                    try:
                        headers, rows = parse_csv_preview(data, max_rows=30)
                        st.write("Colunas detectadas:", headers or "(sem cabeçalho)")
                        if rows:
                            st.dataframe(rows, use_container_width=True)
                    except Exception as e:
                        st.warning(f"Preview falhou: {e}")

                    if st.button("Salvar arquivo (Storage + Registro)", type="primary", use_container_width=True):
                        try:
                            path = make_storage_path(cliente["slug"], rem.get("remessa_key") or "SEM_KEY", file_tipo, file_name)
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

                            ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200))
                            status = remessa_status_from_uploads(ups)
                            db_update_remessa_status(rem["id"], status)

                            st.success(f"Arquivo salvo com sucesso. Status da remessa: {status}")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Falha ao salvar: {e}")

                st.divider()
                st.write("#### Arquivos desta remessa")
                ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=200))

                if not ups:
                    st.info("Ainda não há arquivos registrados nesta remessa.")
                else:
                    st.dataframe([{
                        "data/hora": u.get("created_at"),
                        "tipo": u.get("file_tipo"),
                        "arquivo": u.get("file_name"),
                        "tamanho": fmt_int_pt(u.get("size_bytes") or 0),
                        "caminho": u.get("storage_path"),
                    } for u in ups], use_container_width=True)

    # -------------------------
    # Remessas
    # -------------------------
    with tabs[2]:
        st.write("### Remessas")

        all_clientes = _resp_data(db_list_clientes())
        clientes = filter_clientes_for_user(all_clientes, user_email)

        if not clientes:
            if is_admin_user():
                st.warning("Cadastre clientes primeiro em **Admin → Clientes**.")
            else:
                st.warning("Seu usuário ainda não está vinculado a um cliente (e-mail não bate com o e-mail principal cadastrado).")
        else:
            map_label_to_cliente = {f'{c.get("razao_social","")} ({c.get("slug","")})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="rem_cli")
            cliente = map_label_to_cliente[cliente_label]

            c1, c2 = st.columns(2)
            with c1:
                numero = st.number_input("Número da remessa", min_value=1, step=1, value=50, key="rem_num")
            with c2:
                data_rem = st.date_input("Data da remessa", value=date.today(), key="rem_data")

            preview_key = remessa_key_from(numero, data_rem, cliente["slug"])
            st.success(f"Identificador gerado: **{preview_key}**")

            observacao = st.text_input("Observação (opcional)", key="rem_obs")

            if st.button("Criar remessa", type="primary", use_container_width=True):
                try:
                    db_insert_remessa(cliente["id"], numero, data_rem, preview_key, observacao)
                    st.success("Remessa criada com sucesso.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro ao criar remessa: {e}")

            st.divider()
            st.write("#### Últimas remessas")
            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=100))

            if not rems:
                st.info("Nenhuma remessa cadastrada ainda.")
            else:
                st.dataframe([{
                    "id": r.get("id"),
                    "data": r.get("data"),
                    "número": r.get("numero") or r.get("numero_remessa"),
                    "remessa": r.get("remessa_key"),
                    "status": r.get("status"),
                } for r in rems], use_container_width=True)

    # -------------------------
    # Relatórios (Entrega + Auditoria)
    # -------------------------
    with tabs[3]:
        st.write("### Relatórios")
        st.caption("Entrega por e-mail dos anexos (Envios/Botões) e auditoria completa de disparos.")

        all_clientes = _resp_data(db_list_clientes())
        clientes = filter_clientes_for_user(all_clientes, user_email)

        if not clientes:
            st.warning("Sem cliente vinculado ao seu usuário.")
        else:
            map_label_to_cliente = {f'{c.get("razao_social","")} ({c.get("slug","")})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="rep_cli")
            cliente = map_label_to_cliente[cliente_label]

            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=300))
            if not rems:
                st.info("Nenhuma remessa para este cliente ainda.")
            else:
                def rem_label(r):
                    rk = r.get("remessa_key") or "-"
                    rid = r.get("id")
                    num = r.get("numero") or r.get("numero_remessa") or "-"
                    dt = r.get("data") or "-"
                    return f"{rk} (nº {num}, {dt}, id {rid})"

                map_label_to_rem = {rem_label(r): r for r in rems}
                rem_label_sel = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="rep_rem")
                rem = map_label_to_rem[rem_label_sel]

                ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=500))
                env_u = get_latest_envios_upload(ups)
                bot_u = get_latest_botoes_upload(ups)

                st.divider()
                st.write("#### Entrega por e-mail (anexos)")
                c1, c2, c3 = st.columns([1.2, 1.2, 1.6])
                with c1:
                    st.metric("Envios", "OK" if env_u else "Pendente")
                with c2:
                    st.metric("Botões", "OK" if bot_u else "Pendente")
                with c3:
                    st.write("Destino padrão do cliente:")
                    dest = _cliente_email_destino(cliente)
                    st.code(dest or "(sem e-mail cadastrado)")

                email_cfg = {}
                try:
                    existing = _resp_data(db_get_email_config())
                    email_cfg = existing[0] if existing else {}
                except Exception as e:
                    st.error("Não foi possível ler email_config agora (instabilidade). Tente novamente.")
                    st.caption(str(e))

                if not email_cfg:
                    st.info("Configure o SMTP em **Admin → E-mail (SMTP)**.")
                else:
                    vars_map = {
                        "cliente": cliente.get("razao_social", ""),
                        "remessa_key": rem.get("remessa_key", ""),
                        "ano": str(datetime.strptime(rem.get("data"), "%Y-%m-%d").date().year) if rem.get("data") else "",
                        "mes": str(datetime.strptime(rem.get("data"), "%Y-%m-%d").date().month) if rem.get("data") else "",
                        "data_remessa": rem.get("data") or "",
                    }

                    subj_tpl = email_cfg.get("template_assunto") or "Relatório ContactBot — {cliente} — Remessa {remessa_key}"
                    body_tpl = email_cfg.get("template_corpo") or "Olá, segue o relatório da remessa {remessa_key}.\n\nAtenciosamente,\nContactBot"

                    subject = build_email_from_template(subj_tpl, vars_map)
                    body = build_email_from_template(body_tpl, vars_map)

                    dest_default = _cliente_email_destino(cliente)
                    to_email = st.text_input("E-mail de destino", value=dest_default, key="rep_to_email")

                    st.write("Assunto (prévia):")
                    st.code(subject)
                    st.write("Mensagem (prévia):")
                    st.text_area("Corpo", value=body, height=150, key="rep_body_preview")

                    can_send = True
                    if not to_email.strip():
                        st.warning("Preencha o e-mail de destino.")
                        can_send = False
                    if not env_u and not bot_u:
                        st.warning("Esta remessa não tem anexos. Faça upload antes.")
                        can_send = False

                    if st.button("Enviar relatório desta remessa", type="primary", use_container_width=True, disabled=not can_send):
                        attachments: List[Tuple[str, bytes, str]] = []
                        env_attached = False
                        bot_attached = False
                        try:
                            smtp_host = (email_cfg.get("smtp_host") or "").strip()
                            smtp_port = int(email_cfg.get("smtp_port") or 465)
                            smtp_user = (email_cfg.get("smtp_user") or "").strip()
                            smtp_pass = (email_cfg.get("smtp_pass") or "").strip()
                            smtp_tls_flag = bool(email_cfg.get("smtp_tls", False))
                            from_name = (email_cfg.get("from_name") or "ContactBot").strip()
                            from_email = (email_cfg.get("from_email") or smtp_user).strip()

                            if not smtp_host or not from_email:
                                st.error("SMTP Host e From E-mail são obrigatórios.")
                                st.stop()

                            for u in [env_u, bot_u]:
                                if not u:
                                    continue
                                path = u.get("storage_path")
                                fname = u.get("file_name") or "arquivo.csv"
                                url = storage_signed_url(UPLOADS_BUCKET, path, expires_in=3600)
                                if not url:
                                    continue
                                content = fetch_bytes_from_signed_url(url)
                                attachments.append((fname, content, "text/csv"))
                                if u.get("file_tipo") == "envios":
                                    env_attached = True
                                if u.get("file_tipo") == "botoes":
                                    bot_attached = True

                            smtp_send_email(
                                smtp_host=smtp_host,
                                smtp_port=smtp_port,
                                smtp_user=smtp_user,
                                smtp_pass=smtp_pass,
                                from_name=from_name,
                                from_email=from_email,
                                to_email=to_email.strip(),
                                subject=subject,
                                body_text=body,
                                attachments=attachments,
                                use_ssl_direct=(smtp_port == 465 and not smtp_tls_flag),
                            )

                            # AUDITORIA 100% (tabela email_logs)
                            db_insert_email_log({
                                "created_at": datetime.now(timezone.utc).isoformat(),
                                "cliente_id": cliente.get("id"),
                                "remessa_id": rem.get("id"),
                                "to_email": to_email.strip(),
                                "subject": subject,
                                "status": "sent",
                                "error": None,
                                "attachments_count": len(attachments),
                                "envios_attached": bool(env_attached),
                                "botoes_attached": bool(bot_attached),
                                "triggered_by_user_email": (user_email or "").strip(),
                                "triggered_by_user_id": user_id or None,
                            })

                            st.success("Relatório enviado com sucesso.")
                        except Exception as e:
                            # também audita erro
                            try:
                                db_insert_email_log({
                                    "created_at": datetime.now(timezone.utc).isoformat(),
                                    "cliente_id": cliente.get("id"),
                                    "remessa_id": rem.get("id"),
                                    "to_email": (to_email.strip() if "to_email" in locals() else None),
                                    "subject": (subject if "subject" in locals() else None),
                                    "status": "error",
                                    "error": str(e),
                                    "attachments_count": len(attachments),
                                    "envios_attached": bool(env_attached),
                                    "botoes_attached": bool(bot_attached),
                                    "triggered_by_user_email": (user_email or "").strip(),
                                    "triggered_by_user_id": user_id or None,
                                })
                            except Exception:
                                pass
                            st.error(f"Falha ao enviar e-mail: {e}")

                st.divider()
                st.write("#### Auditoria de e-mails (histórico)")
                colA, colB, colC = st.columns([1.2, 1.2, 1.2])
                with colA:
                    filt_status = st.selectbox("Status", ["Todos", "sent", "error"], index=0, key="log_status")
                with colB:
                    limit = st.number_input("Quantidade", min_value=50, max_value=1000, value=200, step=50, key="log_limit")
                with colC:
                    st.caption("Os registros são gravados em email_logs.")

                status_filter = None if filt_status == "Todos" else filt_status

                try:
                    logs = _resp_data(db_list_email_logs(
                        cliente_id=cliente.get("id"),
                        remessa_id=rem.get("id"),
                        status=status_filter,
                        limit=int(limit),
                    ))
                    if not logs:
                        st.info("Nenhum registro encontrado para este filtro.")
                    else:
                        st.dataframe([{
                            "data/hora": x.get("created_at"),
                            "status": x.get("status"),
                            "destino": x.get("to_email"),
                            "assunto": x.get("subject"),
                            "anexos": x.get("attachments_count"),
                            "envios": x.get("envios_attached"),
                            "botoes": x.get("botoes_attached"),
                            "disparado_por": x.get("triggered_by_user_email"),
                            "erro": (x.get("error") or ""),
                        } for x in logs], use_container_width=True)
                except Exception as e:
                    st.error("Não foi possível carregar a auditoria agora. Verifique se você rodou o SQL do email_logs.")
                    st.caption(str(e))

    # -------------------------
    # Remuneração (somente ENVIO; botões NÃO entram)
    # -------------------------
    with tabs[4]:
        st.write("### Remuneração")
        st.caption("Cálculo por remessa e consolidado mensal por cliente. (Interações de botões não entram na remuneração.)")

        all_clientes = _resp_data(db_list_clientes())
        clientes = filter_clientes_for_user(all_clientes, user_email)

        if not clientes:
            if is_admin_user():
                st.warning("Cadastre o primeiro cliente em **Admin → Clientes**.")
            else:
                st.warning("Seu usuário ainda não está vinculado a um cliente.")
        else:
            map_label_to_cliente = {f'{c.get("razao_social","")} ({c.get("slug","")})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="pay_cli")
            cliente = map_label_to_cliente[cliente_label]
            plano_tipo = cliente.get("plano_tipo", "pos")

            today = date.today()
            colm1, colm2 = st.columns(2)
            with colm1:
                year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="pay_year")
            with colm2:
                month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="pay_month")

            rems = _resp_data(db_list_remessas(cliente_id=cliente["id"], limit=500))

            def in_month(r):
                try:
                    d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                    return d.year == int(year) and d.month == int(month)
                except Exception:
                    return False

            rems_month = [r for r in rems if in_month(r)]

            st.write(f"Plano: **{plano_tipo.upper()}**")
            st.divider()

            st.write("#### Detalhamento por remessa")
            if not rems_month:
                st.info("Nenhuma remessa neste período.")
            else:
                def rem_label(r):
                    rk = r.get("remessa_key") or "-"
                    rid = r.get("id")
                    num = r.get("numero") or r.get("numero_remessa") or "-"
                    return f"{rk} (nº {num}, id {rid})"

                map_label_to_rem = {rem_label(r): r for r in rems_month}
                rem_label_sel = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="pay_rem")
                rem = map_label_to_rem[rem_label_sel]

                ups = _resp_data(db_list_uploads(remessa_id=rem["id"], limit=500))
                envios_files = [u for u in ups if u.get("file_tipo") == "envios"]

                if not envios_files:
                    st.warning("Sem CSV de envios nesta remessa.")
                else:
                    envios_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                    env_u = envios_files[0]

                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    if not url:
                        st.error("Não foi possível gerar link assinado para o CSV de envios.")
                    else:
                        try:
                            csv_bytes = fetch_bytes_from_signed_url(url)
                            metrics = compute_envios_metrics(csv_bytes)

                            qty_total = metrics["total_rows"]
                            qty_billable = metrics["billable"]
                            qty_undelivered = metrics["undelivered"]

                            unit = tier_price(plano_tipo, qty_billable)
                            total = qty_billable * unit

                            c1, c2, c3, c4 = st.columns(4)
                            c1.metric("Total de linhas", fmt_int_pt(qty_total))
                            c2.metric("Cobráveis", fmt_int_pt(qty_billable))
                            c3.metric("Undelivered (não cobra)", fmt_int_pt(qty_undelivered))
                            c4.metric("Valor unitário", fmt_brl(unit))

                            st.success(f"Total estimado da remessa: {fmt_brl(total)}")

                            st.caption(f"Coluna de status: {metrics.get('status_col') or '-'} • Delimitador: {metrics.get('delimiter') or '-'}")

                            st.write("**Distribuição por status:**")
                            by_status = metrics["by_status"]
                            if by_status:
                                st.dataframe(
                                    [{"status": k, "quantidade": fmt_int_pt(v)} for k, v in sorted(by_status.items(), key=lambda x: x[0])],
                                    use_container_width=True
                                )
                            else:
                                st.info("Não foi possível identificar status no arquivo.")

                            nxt = next_tier(plano_tipo, qty_billable)
                            if nxt:
                                a, b, p = nxt
                                st.info(f"Próxima faixa: {fmt_int_pt(a)} cobráveis • unitário {fmt_brl(p)}")

                        except Exception as e:
                            st.error(f"Falha ao processar o CSV de envios: {e}")

            st.divider()
            st.write("#### Consolidado mensal")
            if not rems_month:
                st.info("Nada a consolidar neste período.")
            else:
                rows_out = []
                total_month = 0.0

                for r in rems_month:
                    ups = _resp_data(db_list_uploads(remessa_id=r["id"], limit=500))
                    envios_files = [u for u in ups if u.get("file_tipo") == "envios"]
                    if not envios_files:
                        rows_out.append({
                            "remessa": r.get("remessa_key"),
                            "data": r.get("data"),
                            "cobráveis": "-",
                            "unitário": "-",
                            "total": "-",
                            "observação": "sem CSV de envios",
                        })
                        continue

                    envios_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                    env_u = envios_files[0]
                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    if not url:
                        rows_out.append({
                            "remessa": r.get("remessa_key"),
                            "data": r.get("data"),
                            "cobráveis": "-",
                            "unitário": "-",
                            "total": "-",
                            "observação": "sem link assinado",
                        })
                        continue

                    try:
                        csv_bytes = fetch_bytes_from_signed_url(url)
                        metrics = compute_envios_metrics(csv_bytes)
                        qty_billable = metrics["billable"]
                        unit = tier_price(plano_tipo, qty_billable)
                        tot = qty_billable * unit
                        total_month += tot

                        rows_out.append({
                            "remessa": r.get("remessa_key"),
                            "data": r.get("data"),
                            "cobráveis": fmt_int_pt(qty_billable),
                            "unitário": fmt_brl(unit),
                            "total": fmt_brl(tot),
                            "observação": "",
                        })
                    except Exception:
                        rows_out.append({
                            "remessa": r.get("remessa_key"),
                            "data": r.get("data"),
                            "cobráveis": "-",
                            "unitário": "-",
                            "total": "-",
                            "observação": "erro ao ler CSV",
                        })

                st.dataframe(rows_out, use_container_width=True)
                st.success(f"Total estimado do mês: {fmt_brl(total_month)}")

    # -------------------------
    # Admin
    # -------------------------
    if is_admin_user():
        with tabs[5]:
            st.write("### Administração")
            st.caption("Configurações internas do sistema: clientes, preços, e-mail e PIX.")

            sec = st.tabs(["Clientes", "Valores (Envios)", "E-mail (SMTP)", "PIX (Mercado Pago)"])

            # Clientes
            with sec[0]:
                st.write("#### Clientes")
                clientes = _resp_data(db_list_clientes())

                with st.expander("Cadastrar novo cliente", expanded=True):
                    cnpj = st.text_input("CNPJ", value="", key="adm_cnpj")
                    razao = st.text_input("Razão social", value="", key="adm_razao")
                    contato_nome = st.text_input("Contato (nome)", value="", key="adm_contato_nome")
                    contato_email = st.text_input("E-mail principal (obrigatório)", value="", key="adm_contato_email")
                    contato_whatsapp = st.text_input("WhatsApp", value="", key="adm_contato_whats")

                    plano_label = st.selectbox("Plano", ["Pós-pago", "Pré-pago"], index=0, key="adm_plano")
                    plano_tipo = "pos" if plano_label == "Pós-pago" else "pre"

                    st.caption("O identificador (slug) é gerado automaticamente a partir da razão social.")

                    if st.button("Salvar cliente", type="primary", use_container_width=True):
                        try:
                            if not (cnpj or "").strip():
                                st.warning("Informe o CNPJ.")
                                st.stop()
                            if not (razao or "").strip():
                                st.warning("Informe a razão social.")
                                st.stop()
                            if not (contato_email or "").strip():
                                st.warning("Informe o e-mail principal (obrigatório).")
                                st.stop()

                            db_insert_cliente(cnpj, razao, contato_nome, contato_email, contato_whatsapp, plano_tipo)
                            st.success("Cliente cadastrado com sucesso.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao cadastrar cliente: {e}")

                st.divider()
                st.write("#### Lista de clientes")
                if not clientes:
                    st.info("Nenhum cliente cadastrado ainda.")
                else:
                    map_label = {f'{c.get("razao_social","")} ({c.get("slug","")}) [id {c.get("id")}]': c for c in clientes}
                    sel = st.selectbox("Selecionar cliente", list(map_label.keys()), key="adm_cli_edit")
                    c = map_label[sel]

                    col1, col2 = st.columns(2)
                    with col1:
                        e_razao = st.text_input("Razão social", value=c.get("razao_social") or "", key="adm_e_razao")
                        e_nome = st.text_input("Contato (nome)", value=c.get("contato_nome") or "", key="adm_e_nome")
                        e_email = st.text_input("E-mail principal", value=_cliente_email_destino(c) or "", key="adm_e_email")
                    with col2:
                        e_cnpj = st.text_input("CNPJ", value=c.get("cnpj") or "", key="adm_e_cnpj")
                        e_whats = st.text_input("WhatsApp", value=c.get("contato_whatsapp") or "", key="adm_e_whats")
                        plano_atual = "Pós-pago" if (c.get("plano_tipo") == "pos") else "Pré-pago"
                        e_plano_label = st.selectbox("Plano", ["Pós-pago", "Pré-pago"], index=0 if plano_atual == "Pós-pago" else 1, key="adm_e_plano")
                        e_plano_tipo = "pos" if e_plano_label == "Pós-pago" else "pre"

                    e_ativo = st.checkbox("Ativo", value=bool(c.get("ativo", True)), key="adm_e_ativo")

                    if st.button("Atualizar cliente", use_container_width=True):
                        try:
                            payload = {
                                "cnpj": (e_cnpj or "").strip() or None,
                                "razao_social": (e_razao or "").strip() or None,
                                "contato_nome": (e_nome or "").strip() or None,
                                "contato_whatsapp": (e_whats or "").strip() or None,
                                "plano_tipo": e_plano_tipo,
                                "ativo": bool(e_ativo),
                            }
                            if (e_email or "").strip():
                                payload["email_principal"] = (e_email or "").strip()
                                payload["contato_email"] = (e_email or "").strip()
                            db_update_cliente(c["id"], payload)
                            st.success("Cliente atualizado.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao atualizar cliente: {e}")

                    st.divider()
                    st.dataframe(
                        [{
                            "id": x.get("id"),
                            "cnpj": x.get("cnpj"),
                            "razao_social": x.get("razao_social"),
                            "slug": x.get("slug"),
                            "plano": x.get("plano_tipo"),
                            "ativo": x.get("ativo"),
                            "email_principal": _cliente_email_destino(x),
                        } for x in clientes],
                        use_container_width=True
                    )

            # Valores
            with sec[1]:
                st.write("#### Valores por faixa (Envios)")
                st.caption("Você edita apenas o valor unitário. As quantidades permanecem fixas.")

                def render_tiers(plan_tipo: str, title: str):
                    st.subheader(title)
                    try:
                        resp = db_list_pricing_tiers(plan_tipo)
                        rows = _resp_data(resp) or []
                        rows = sorted(rows, key=lambda x: int(x.get("min_qty") or 0))
                        table_exists = True
                    except Exception as e:
                        table_exists = False
                        rows = []
                        st.error(f"Não foi possível acessar pricing_tiers ({plan_tipo}): {e}")

                    if not table_exists:
                        st.info("Se a tabela não existe, crie no Supabase (SQL).")
                        return

                    if not rows:
                        st.warning("Sem faixas no banco.")
                        if st.button(f"Criar faixas padrão ({plan_tipo.upper()})", key=f"seed_{plan_tipo}", use_container_width=True):
                            try:
                                seed = []
                                for mn, mx, pr in DEFAULT_TIERS[plan_tipo]:
                                    seed.append({
                                        "plano_tipo": plan_tipo,
                                        "min_qty": int(mn),
                                        "max_qty": int(mx),
                                        "unit_price": float(pr),
                                        "ativo": True,
                                    })
                                db_insert_pricing_tiers(seed)
                                st.success("Faixas criadas.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Falha ao inserir faixas: {e}")
                        return

                    for r in rows:
                        mn = int(r.get("min_qty") or 0)
                        mx = int(r.get("max_qty") or 10**12)
                        pr = float(r.get("unit_price") or 0.0)
                        ativo = bool(r.get("ativo", True))

                        label = f"De {fmt_int_pt(mn)} até {fmt_int_pt(mx)}" if mx < 10**11 else f"Acima de {fmt_int_pt(mn)}"
                        with st.expander(f"{label} • {fmt_brl(pr)}", expanded=False):
                            c1, c2, c3, c4 = st.columns([1, 1, 1, 1])
                            with c1:
                                st.number_input("Mínimo", value=mn, step=1, disabled=True, key=f"{plan_tipo}_mn_{r['id']}")
                            with c2:
                                st.number_input("Máximo", value=mx, step=1, disabled=True, key=f"{plan_tipo}_mx_{r['id']}")
                            with c3:
                                new_price = st.number_input("Valor unitário (R$)", value=pr, step=0.01, key=f"{plan_tipo}_pr_{r['id']}")
                            with c4:
                                new_ativo = st.checkbox("Ativo", value=ativo, key=f"{plan_tipo}_at_{r['id']}")

                            if st.button("Salvar", key=f"{plan_tipo}_save_{r['id']}", use_container_width=True):
                                try:
                                    db_update_pricing_tier(r["id"], {"unit_price": float(new_price), "ativo": bool(new_ativo)})
                                    st.success("Salvo.")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Erro ao salvar: {e}")

                render_tiers("pos", "Pós-pago")
                st.divider()
                render_tiers("pre", "Pré-pago")

            # Email SMTP
            with sec[2]:
                st.write("#### E-mail (SMTP)")
                st.caption("Porta 465 = SSL direto (TLS desmarcado).")

                try:
                    existing = _resp_data(db_get_email_config())
                    row = existing[0] if existing else {}
                except Exception as e:
                    row = {}
                    st.error("Falha ao ler email_config (instabilidade).")
                    st.caption(str(e))

                is_active = st.checkbox("Ativar envio por e-mail", value=bool(row.get("is_active", False)), key="em_active")
                smtp_host = st.text_input("SMTP Host", value=row.get("smtp_host") or "", key="em_host")
                smtp_port = st.number_input("SMTP Port", value=int(row.get("smtp_port") or 465), step=1, key="em_port")
                smtp_user = st.text_input("SMTP User", value=row.get("smtp_user") or "", key="em_user")
                smtp_pass = st.text_input("SMTP Pass", value=row.get("smtp_pass") or "", type="password", key="em_pass")
                smtp_tls = st.checkbox("TLS (STARTTLS — 587)", value=bool(row.get("smtp_tls", False)), key="em_tls")

                if int(smtp_port) == 465 and smtp_tls:
                    st.warning("Para porta 465, deixe TLS desmarcado (SSL direto).")

                from_name = st.text_input("From Name", value=row.get("from_name") or "ContactBot", key="em_from_name")
                from_email = st.text_input("From E-mail", value=row.get("from_email") or (smtp_user or ""), key="em_from_email")

                template_assunto = st.text_input(
                    "Template de assunto",
                    value=row.get("template_assunto") or "Relatório ContactBot — {cliente} — Remessa {remessa_key}",
                    key="em_subj"
                )
                template_corpo = st.text_area(
                    "Template de mensagem",
                    value=row.get("template_corpo") or "Olá, {cliente}.\n\nSeguem anexos os relatórios da remessa {remessa_key} ({data_remessa}).\n\nAtenciosamente,\nContactBot",
                    height=180,
                    key="em_body"
                )

                colA, colB = st.columns([1, 1])
                with colA:
                    if st.button("Salvar configuração", type="primary", use_container_width=True):
                        try:
                            db_upsert_email_config({
                                "is_active": bool(is_active),
                                "smtp_host": (smtp_host or "").strip() or None,
                                "smtp_port": int(smtp_port),
                                "smtp_user": (smtp_user or "").strip() or None,
                                "smtp_pass": (smtp_pass or "").strip() or None,
                                "smtp_tls": bool(smtp_tls),
                                "from_name": (from_name or "").strip() or None,
                                "from_email": (from_email or "").strip() or None,
                                "template_assunto": (template_assunto or "").strip() or None,
                                "template_corpo": (template_corpo or "").strip() or None,
                            })
                            st.success("Configuração salva.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao salvar: {e}")

                with colB:
                    test_to = st.text_input("Enviar teste para", value=ADMIN_EMAIL, key="em_test_to")
                    if st.button("Testar envio", use_container_width=True):
                        try:
                            if not smtp_host or not smtp_port or not from_email or not test_to:
                                st.error("Preencha SMTP Host, Port, From E-mail e o destinatário de teste.")
                                st.stop()

                            smtp_send_email(
                                smtp_host=smtp_host,
                                smtp_port=int(smtp_port),
                                smtp_user=smtp_user,
                                smtp_pass=smtp_pass,
                                from_name=from_name,
                                from_email=from_email,
                                to_email=test_to.strip(),
                                subject="Teste ContactBot — SMTP OK",
                                body_text="Teste de envio SMTP realizado com sucesso.\n\nContactBot",
                                attachments=[],
                                use_ssl_direct=(int(smtp_port) == 465 and not smtp_tls),
                            )
                            st.success("E-mail de teste enviado.")
                        except Exception as e:
                            st.error(f"Falha no teste SMTP: {e}")

            # Mercado Pago
            with sec[3]:
                st.write("#### PIX (Mercado Pago)")
                st.caption("A integração e rotinas de recarga do pré-pago serão implementadas no próximo passo.")

                try:
                    existing = _resp_data(db_get_mercadopago_config())
                    row = existing[0] if existing else {}
                except Exception as e:
                    row = {}
                    st.error("Falha ao ler mercadopago_config (instabilidade).")
                    st.caption(str(e))

                mp_active = st.checkbox("Ativar integração Mercado Pago", value=bool(row.get("is_active", False)), key="mp_active")
                access_token = st.text_input("Access Token", value=row.get("access_token") or "", type="password", key="mp_token")
                public_key = st.text_input("Public Key", value=row.get("public_key") or "", key="mp_pub")
                webhook_secret = st.text_input("Webhook Secret", value=row.get("webhook_secret") or "", type="password", key="mp_webhook")

                if st.button("Salvar configurações", use_container_width=True):
                    try:
                        db_upsert_mercadopago_config({
                            "is_active": bool(mp_active),
                            "access_token": (access_token or "").strip() or None,
                            "public_key": (public_key or "").strip() or None,
                            "webhook_secret": (webhook_secret or "").strip() or None,
                        })
                        st.success("Configuração Mercado Pago salva.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erro ao salvar: {e}")

    st.stop()

# =========================
# Login / Cadastro (não logado)
# =========================
st.subheader("Acesso")

col_left, col_right = st.columns([1.2, 1.0], gap="large")

with col_left:
    st.subheader("Entrar")
    login_email = st.text_input("E-mail", value="", placeholder="seuemail@dominio.com")
    login_pass = st.text_input("Senha", value="", type="password", placeholder="Digite sua senha")

    if st.button("Entrar", type="primary", use_container_width=True):
        try:
            resp = do_login(login_email, login_pass)
            ok = session_set_from_auth_response(resp)
            if ok:
                st.success("Login realizado.")
                st.rerun()
            else:
                st.error("Login não retornou sessão. Verifique e-mail/senha.")
        except Exception as e:
            st.error(f"Login falhou: {e}")

    st.divider()

    st.subheader("Criar conta (cliente)")
    st.caption("Use o e-mail que está cadastrado como e-mail principal do seu cliente.")

    su_email = st.text_input("E-mail", value="", key="su_email")
    su_pass1 = st.text_input("Senha", value="", type="password", key="su_pass1")
    su_pass2 = st.text_input("Confirmar senha", value="", type="password", key="su_pass2")

    if st.button("Criar conta", use_container_width=True):
        try:
            if not su_email.strip():
                st.warning("Digite o e-mail.")
                st.stop()
            if not su_pass1.strip() or not su_pass2.strip():
                st.warning("Digite a senha e confirme.")
                st.stop()
            if su_pass1 != su_pass2:
                st.warning("As senhas não conferem.")
                st.stop()

            resp = do_signup(su_email, su_pass1)
            # alguns projetos exigem confirmação de e-mail no Supabase.
            # se estiver desativado, o login funciona na sequência.
            st.success("Conta criada. Agora faça login acima.")
        except Exception as e:
            st.error(f"Falha ao criar conta: {e}")

with col_right:
    st.subheader("Administração (restrito)")
    st.caption("Ações administrativas usando SERVICE ROLE KEY.")

    st.write("**Criar usuário (sem e-mail / sem confirmação)**")
    new_email = st.text_input("E-mail do novo usuário", value="", key="new_email_admin")
    new_pass1 = st.text_input("Senha", value="", type="password", key="new_pass1_admin")
    new_pass2 = st.text_input("Confirmar senha", value="", type="password", key="new_pass2_admin")

    if st.button("Criar usuário (admin)", use_container_width=True):
        try:
            if not new_email.strip():
                st.warning("Digite o e-mail.")
                st.stop()
            if not new_pass1.strip() or not new_pass2.strip():
                st.warning("Digite a senha e confirme.")
                st.stop()
            if new_pass1 != new_pass2:
                st.warning("As senhas não batem.")
                st.stop()

            admin_create_user(new_email, new_pass1)
            st.success("Usuário criado e confirmado. Faça login na coluna da esquerda.")
        except Exception as e:
            st.error(f"Falha ao criar usuário: {e}")

    st.divider()

    st.write("**Definir senha de usuário existente**")
    adm_email = st.text_input("E-mail do usuário", value="", key="adm_email")
    adm_pass1 = st.text_input("Nova senha", value="", type="password", key="adm_pass1")
    adm_pass2 = st.text_input("Confirmar nova senha", value="", type="password", key="adm_pass2")

    if st.button("Definir senha (admin)", use_container_width=True):
        try:
            if not adm_email.strip():
                st.warning("Digite o e-mail.")
                st.stop()
            if not adm_pass1.strip() or not adm_pass2.strip():
                st.warning("Digite a senha e confirme.")
                st.stop()
            if adm_pass1 != adm_pass2:
                st.warning("As senhas não batem.")
                st.stop()

            admin_set_password(adm_email, adm_pass1)
            st.success("Senha definida. Agora faça login.")
        except Exception as e:
            st.error(f"Falha ao definir senha: {e}")

st.divider()
st.caption("Recuperação de senha por e-mail permanece fora deste app por enquanto.")
