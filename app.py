import os
import io
import csv
import re
import json
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, date
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

def inject_css():
    st.markdown(
        f"""
        <style>
            html, body, [class*="css"] {{
                color: {TEXT_GRAY};
            }}
            .block-container {{
                padding-top: 1.25rem;
            }}
            /* Tabs */
            button[data-baseweb="tab"] {{
                font-weight: 600;
            }}
            /* Buttons */
            .stButton button {{
                background: {PRIMARY_BLUE};
                color: white;
                border-radius: 10px;
                border: 1px solid {PRIMARY_BLUE};
                padding: 0.6rem 1rem;
                font-weight: 700;
            }}
            .stButton button:hover {{
                background: {SECONDARY_BLUE};
                border-color: {SECONDARY_BLUE};
                color: white;
            }}
            /* Inputs */
            [data-baseweb="input"] > div, [data-baseweb="textarea"] > div {{
                border-radius: 10px;
                border-color: {SOFT_GRAY_BORDER};
            }}
            /* Metrics */
            [data-testid="stMetric"] {{
                background: white;
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 12px;
                padding: 14px 14px;
            }}
            /* Dataframe container look */
            .stDataFrame {{
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 12px;
                overflow: hidden;
            }}
            /* Info box */
            .cb-card {{
                background: white;
                border: 1px solid {SOFT_GRAY_BORDER};
                border-radius: 14px;
                padding: 14px 16px;
            }}
            .cb-title {{
                font-size: 26px;
                font-weight: 800;
                margin-bottom: 0.2rem;
            }}
            .cb-sub {{
                color: #5B6472;
                font-size: 14px;
                margin-top: 0rem;
            }}
            .cb-pill {{
                display: inline-block;
                padding: 6px 10px;
                border-radius: 999px;
                border: 1px solid {SOFT_GRAY_BORDER};
                background: {SOFT_GRAY_BG};
                font-size: 12px;
                font-weight: 700;
                color: #3B4250;
            }}
            .cb-divider {{
                margin: 16px 0;
                height: 1px;
                background: {SOFT_GRAY_BORDER};
            }}
            .cb-muted {{
                color: #6B7280;
                font-size: 13px;
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

# ADMIN (apenas seu usuário)
ADMIN_EMAIL = "amadvjuridica@gmail.com"

# SMTP default (você confirmou 465)
DEFAULT_SMTP_PORT = 465

# ============================================================
# FAIXAS PADRÃO (fallback) — CORRETAS
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
# FORMATAÇÃO (pt-BR) — números com ponto de milhar
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

def admin_set_password(email: str, new_password: str):
    u = admin_find_user_by_email(email)
    if not u:
        raise ValueError("Não achei esse e-mail no Supabase Auth > Users.")
    uid = u.get("id")
    return supabase_admin.auth.admin.update_user_by_id(uid, {"password": new_password.strip()})

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
    # heurística simples
    if sample_text.count(";") > sample_text.count(","):
        return ";"
    return ","

# ============================================================
# DB HELPERS (tolerante a schema)
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
        "plano_tipo": plano_tipo,   # "pos" ou "pre"
        "ativo": True,
    }

    # seu banco tem NOT NULL em email_principal
    # então preenche automaticamente com o contato_email (se existir)
    if "email_principal" not in payload:
        payload["email_principal"] = contato_email_clean or "financeiro@exemplo.com"

    return supabase_admin.table("clientes").insert(payload).execute()

def db_update_cliente(cliente_id, payload: dict):
    return supabase_admin.table("clientes").update(payload).eq("id", cliente_id).execute()

def remessa_get_key(r: dict) -> str:
    # suporta "remessa_key" ou "titulo"
    return (r.get("remessa_key") or r.get("titulo") or "")

def remessa_get_numero(r: dict) -> int:
    return int(r.get("numero_remessa") or r.get("numero") or 0)

def db_list_remessas(cliente_id=None, limit=200):
    # suporta colunas "data" e ordena também por "numero" ou "numero_remessa"
    q = supabase_admin.table("remessas").select("*").order("data", desc=True).limit(limit)
    if cliente_id:
        q = q.eq("cliente_id", cliente_id)
    return q.execute()

def db_insert_remessa(cliente_id, numero_remessa, data_remessa, remessa_key, observacao=None):
    # seu banco pode usar "numero" e "titulo"
    payload = {
        "cliente_id": cliente_id,
        "data": str(data_remessa),
        "status": "aguardando_upload",
        "versao": 1,
    }

    # tenta preencher ambos de forma segura (se um não existir, o PostgREST ignora? não ignora.
    # então fazemos insert com o nome que mais provável existir: numero e titulo.
    payload["numero"] = int(numero_remessa)
    payload["titulo"] = remessa_key

    # observação pode ou não existir
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

# ---- Admin tables (config)
def db_get_email_config():
    return supabase_admin.table("email_config").select("*").order("created_at", desc=True).limit(1).execute()

def db_upsert_email_config(payload: dict):
    existing = _resp_data(db_get_email_config())
    if existing:
        row_id = existing[0]["id"]
        return supabase_admin.table("email_config").update(payload).eq("id", row_id).execute()
    return supabase_admin.table("email_config").insert(payload).execute()

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

# ---- Email logs (auditoria)
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

# ============================================================
# STORAGE HELPERS
# ============================================================
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

# ============================================================
# CSV -> MÉTRICAS (corrigido: ignora linhas vazias)
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
    # detecta delimitador
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
        # ignora linha “toda vazia”
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
            else:
                # status desconhecido: por segurança NÃO cobra
                pass

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

# ============================================================
# UI
# ============================================================
st.markdown(
    """
    <div class="cb-card">
        <div class="cb-title">ContactBot</div>
        <div class="cb-sub">Gestão de remessas, uploads e remuneração — com entrega por e-mail e auditoria.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.expander("Diagnóstico rápido (config)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))
    st.write("UPLOADS_BUCKET:", UPLOADS_BUCKET)

# ============================================================
# PAINEL (LOGADO)
# ============================================================
if session_is_logged_in():
    user = st.session_state.get("user", {}) or {}
    user_email = user.get("email", "")
    user_id = user.get("id", "")

    top_l, top_r = st.columns([4, 1])
    with top_l:
        st.subheader("✅ Painel")
        st.caption(f"Usuário: {user_email} | ID: {user_id}")
    with top_r:
        if st.button("Sair", use_container_width=True):
            do_logout()

    st.divider()

    # MENU APROVADO (+ Configurações Admin só para você)
    base_tabs = ["Dashboard", "Uploads (CSV)", "Campanhas (Remessas)", "Relatórios", "Remuneração"]
    if is_admin_user():
        base_tabs.append("Configurações (Admin)")
    tabs = st.tabs(base_tabs)

    # -------------------------
    # Dashboard
    # -------------------------
    with tabs[0]:
        st.info("Em breve: KPIs por cliente, volume por mês, status de remessas e alertas operacionais.")

    # -------------------------
    # Uploads (CSV)
    # -------------------------
    with tabs[1]:
        st.write("### Uploads (CSV)")
        st.caption("Faça upload dos retornos: **Envios** e **Botões**. O app vincula à remessa e atualiza o status.")

        clientes_resp = db_list_clientes()
        clientes = _resp_data(clientes_resp)

        if not clientes:
            if is_admin_user():
                st.warning("Nenhum cliente cadastrado. Vá em **Configurações (Admin) → Clientes**.")
            else:
                st.warning("Nenhum cliente cadastrado. Solicite ao administrador.")
        else:
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="up_cli")
            cliente = map_label_to_cliente[cliente_label]

            rem_resp = db_list_remessas(cliente_id=cliente["id"], limit=200)
            rems = _resp_data(rem_resp)

            if not rems:
                st.warning("Crie uma remessa primeiro (aba Campanhas/Remessas).")
            else:
                # label suportando titulo/remessa_key
                map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems}
                rem_label = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="up_rem")
                rem = map_label_to_rem[rem_label]

                file_tipo = st.selectbox("Tipo do arquivo", ["envios", "botoes", "base"], index=0)
                uploaded = st.file_uploader("Envie um CSV", type=["csv"])

                if uploaded:
                    data = uploaded.getvalue()
                    file_name = uploaded.name
                    size_bytes = len(data)
                    digest = sha256_hex(data)

                    st.caption(f"Arquivo: **{file_name}** | {fmt_int(size_bytes)} bytes | SHA256 `{digest[:16]}...`")

                    try:
                        headers, rows = parse_csv_preview(data, max_rows=30)
                        st.write("Colunas detectadas:", headers or "(sem cabeçalho)")
                        if rows:
                            st.dataframe(rows, use_container_width=True)
                    except Exception as e:
                        st.warning(f"Preview falhou: {e}")

                    if st.button("Salvar arquivo", type="primary", use_container_width=True):
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

                            up_resp = db_list_uploads(remessa_id=rem["id"], limit=200)
                            ups = _resp_data(up_resp)
                            status = remessa_status_from_uploads(ups)
                            db_update_remessa_status(rem["id"], status)

                            st.success(f"✅ Upload salvo. Status da remessa: **{status}**")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Falha ao salvar: {e}")

                st.divider()
                st.write("#### Uploads desta remessa")
                up_resp = db_list_uploads(remessa_id=rem["id"], limit=200)
                ups = _resp_data(up_resp)

                if not ups:
                    st.info("Nenhum upload nesta remessa ainda.")
                else:
                    st.dataframe([{
                        "data": u.get("created_at"),
                        "tipo": u.get("file_tipo"),
                        "arquivo": u.get("file_name"),
                        "tamanho": fmt_int(u.get("size_bytes")),
                        "storage_path": u.get("storage_path"),
                    } for u in ups], use_container_width=True)

    # -------------------------
    # Campanhas (Remessas)
    # -------------------------
    with tabs[2]:
        st.write("### Campanhas (Remessas)")
        st.caption("Remessa = lote de envios de um cliente em uma data. Pode ser esporádico. Fechamento: mensal (pós-pago).")

        clientes_resp = db_list_clientes()
        clientes = _resp_data(clientes_resp)

        if not clientes:
            if is_admin_user():
                st.warning("Cadastre clientes primeiro em **Configurações (Admin) → Clientes**.")
            else:
                st.warning("Solicite ao admin cadastrar clientes.")
        else:
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="rem_cli")
            cliente = map_label_to_cliente[cliente_label]

            c1, c2 = st.columns(2)
            with c1:
                numero = st.number_input("Número da remessa", min_value=1, step=1, value=49, key="rem_num")
            with c2:
                data_rem = st.date_input("Data da remessa", value=date.today(), key="rem_data")

            preview_key = remessa_key_from(numero, data_rem, cliente["slug"])
            st.success(f"Identificador: **{preview_key}**")

            observacao = st.text_input("Observação (opcional)", key="rem_obs")

            if st.button("Criar remessa", type="primary", use_container_width=True):
                try:
                    db_insert_remessa(cliente["id"], numero, data_rem, preview_key, observacao)
                    st.success("✅ Remessa criada.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro ao criar remessa: {e}")

            st.divider()
            st.write("#### Últimas remessas do cliente")
            rem_resp = db_list_remessas(cliente_id=cliente["id"], limit=200)
            rems = _resp_data(rem_resp)

            if not rems:
                st.info("Nenhuma remessa ainda.")
            else:
                st.dataframe([{
                    "id": r.get("id"),
                    "data": r.get("data"),
                    "número": remessa_get_numero(r),
                    "remessa": remessa_get_key(r),
                    "status": r.get("status"),
                } for r in rems], use_container_width=True)

    # -------------------------
    # Relatórios (próximo passo)
    # -------------------------
    with tabs[3]:
        st.info("Próximo passo: relatório sintético + analítico (CSV/PDF) por remessa e consolidado mensal, com envio automático.")

    # -------------------------
    # Remuneração (somente ENVIO; botões NÃO entram)
    # -------------------------
    with tabs[4]:
        st.write("### Remuneração")
        st.caption("Cálculo por remessa e consolidado mensal por cliente. **Botões NÃO entram na remuneração.**")

        clientes_resp = db_list_clientes()
        clientes = _resp_data(clientes_resp)

        if not clientes:
            st.warning("Cadastre clientes primeiro.")
        else:
            map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
            cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="pay_cli")
            cliente = map_label_to_cliente[cliente_label]
            plano_tipo = cliente.get("plano_tipo", "pos")  # pos / pre

            today = date.today()
            colm1, colm2 = st.columns(2)
            with colm1:
                year = st.number_input("Ano", min_value=2020, max_value=2100, value=today.year, step=1, key="pay_year")
            with colm2:
                month = st.number_input("Mês", min_value=1, max_value=12, value=today.month, step=1, key="pay_month")

            rem_resp = db_list_remessas(cliente_id=cliente["id"], limit=500)
            rems = _resp_data(rem_resp)

            def in_month(r):
                try:
                    d = datetime.strptime(r.get("data"), "%Y-%m-%d").date()
                    return d.year == int(year) and d.month == int(month)
                except Exception:
                    return False

            rems_month = [r for r in rems if in_month(r)]

            st.write(f"Plano: **{plano_tipo.upper()}**")
            st.divider()

            # ========= Por remessa
            st.write("#### Por remessa (detalhado)")
            if not rems_month:
                st.info("Nenhuma remessa neste mês para este cliente.")
            else:
                map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems_month}
                rem_label = st.selectbox("Escolha uma remessa", list(map_label_to_rem.keys()), key="pay_rem")
                rem = map_label_to_rem[rem_label]

                up_resp = db_list_uploads(remessa_id=rem["id"], limit=200)
                ups = _resp_data(up_resp)
                envios_files = [u for u in ups if u.get("file_tipo") == "envios"]

                if not envios_files:
                    st.warning("Esta remessa ainda não tem CSV de **envios**.")
                else:
                    envios_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                    env_u = envios_files[0]

                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    if not url:
                        st.error("Não consegui gerar link assinado para baixar o CSV de envios.")
                    else:
                        csv_bytes = fetch_bytes_from_signed_url(url)
                        metrics = compute_envios_metrics(csv_bytes)

                        qty_billable = metrics["billable"]
                        qty_undelivered = metrics["undelivered"]
                        qty_total = metrics["total_rows"]

                        unit = tier_price(plano_tipo, qty_billable)
                        total = qty_billable * unit

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Total linhas", fmt_int(qty_total))
                        c2.metric("Cobráveis", fmt_int(qty_billable))
                        c3.metric("Undelivered (não cobra)", fmt_int(qty_undelivered))
                        c4.metric("Unitário", fmt_money(unit))

                        st.success(f"Total da remessa (estimado): **{fmt_money(total)}**")
                        st.caption(f"Coluna de status: {metrics['status_col']} | Delimitador: {metrics['delimiter']}")

                        st.write("**Por status (encontrados no CSV):**")
                        by_status = metrics["by_status"]
                        if by_status:
                            st.dataframe(
                                [{"status": k, "qtd": fmt_int(v)} for k, v in sorted(by_status.items(), key=lambda x: x[0])],
                                use_container_width=True
                            )
                        else:
                            st.info("Não encontrei valores de status.")

                        nxt = next_tier(plano_tipo, qty_billable)
                        if nxt:
                            a, b, p = nxt
                            st.info(f"Próxima faixa começa em **{fmt_int(a)}** cobráveis (unitário {fmt_money(p)}).")

            st.divider()

            # ========= Consolidado mensal
            st.write("#### Consolidado mensal do cliente")
            if not rems_month:
                st.info("Nada para consolidar.")
            else:
                rows_out = []
                total_month = 0.0

                for r in rems_month:
                    up_resp = db_list_uploads(remessa_id=r["id"], limit=200)
                    ups = _resp_data(up_resp)
                    envios_files = [u for u in ups if u.get("file_tipo") == "envios"]
                    if not envios_files:
                        rows_out.append({
                            "remessa": remessa_get_key(r),
                            "data": r.get("data"),
                            "cobráveis": "-",
                            "unit": "-",
                            "total": "-",
                            "obs": "sem CSV envios",
                        })
                        continue

                    envios_files.sort(key=lambda x: x.get("created_at") or "", reverse=True)
                    env_u = envios_files[0]
                    url = storage_signed_url(UPLOADS_BUCKET, env_u.get("storage_path"), expires_in=3600)
                    if not url:
                        rows_out.append({
                            "remessa": remessa_get_key(r),
                            "data": r.get("data"),
                            "cobráveis": "-",
                            "unit": "-",
                            "total": "-",
                            "obs": "sem link assinado",
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
                            "remessa": remessa_get_key(r),
                            "data": r.get("data"),
                            "cobráveis": fmt_int(qty_billable),
                            "unit": fmt_money(unit),
                            "total": fmt_money(tot),
                            "obs": "",
                        })
                    except Exception:
                        rows_out.append({
                            "remessa": remessa_get_key(r),
                            "data": r.get("data"),
                            "cobráveis": "-",
                            "unit": "-",
                            "total": "-",
                            "obs": "erro ao ler CSV",
                        })

                st.dataframe(rows_out, use_container_width=True)
                st.success(f"Total do mês (estimado): **{fmt_money(total_month)}**")

                if plano_tipo == "pre":
                    st.info("Pré-pago: próximo passo é SALDO, validade (30 dias), bloqueio e recarga (PIX).")

    # -------------------------
    # Configurações (Admin) — só para você
    # -------------------------
    if is_admin_user():
        with tabs[5]:
            st.write("### Configurações (Admin)")
            st.caption("Somente administrador: clientes, faixas, e-mail (SMTP) e PIX (Mercado Pago).")

            sec = st.tabs(["Clientes", "Valores (Remuneração)", "E-mail (SMTP)", "PIX (Mercado Pago)", "Entrega por e-mail (anexos)"])

            # ---- Clientes
            with sec[0]:
                st.write("#### Clientes")

                clientes_resp = db_list_clientes()
                clientes = _resp_data(clientes_resp)

                with st.expander("➕ Cadastrar novo cliente", expanded=True):
                    cnpj = st.text_input("CNPJ", value="", key="adm_cnpj")
                    razao = st.text_input("Razão social", value="", key="adm_razao")
                    contato_nome = st.text_input("Contato (nome)", value="", key="adm_contato_nome")
                    contato_email = st.text_input("Contato (e-mail)", value="", key="adm_contato_email")
                    contato_whatsapp = st.text_input("Contato (WhatsApp)", value="", key="adm_contato_whats")

                    plano_label = st.selectbox("Plano", ["Pós-pago", "Pré-pago"], index=0, key="adm_plano")
                    plano_tipo = "pos" if plano_label == "Pós-pago" else "pre"

                    st.caption("Slug é gerado automaticamente pela Razão Social.")

                    if st.button("Salvar cliente", type="primary", use_container_width=True):
                        try:
                            if not (cnpj or "").strip():
                                st.warning("Informe o CNPJ.")
                                st.stop()
                            if not (razao or "").strip():
                                st.warning("Informe a Razão Social.")
                                st.stop()
                            if not (contato_email or "").strip():
                                st.warning("Informe o e-mail do contato (será usado como destino padrão).")
                                st.stop()

                            db_insert_cliente(cnpj, razao, contato_nome, contato_email, contato_whatsapp, plano_tipo)
                            st.success("✅ Cliente cadastrado.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao cadastrar cliente: {e}")

                st.divider()
                st.write("#### Clientes cadastrados")

                if not clientes:
                    st.info("Nenhum cliente cadastrado ainda.")
                else:
                    map_label = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
                    sel = st.selectbox("Selecionar cliente", list(map_label.keys()), key="adm_cli_edit")
                    c = map_label[sel]

                    col1, col2 = st.columns(2)
                    with col1:
                        e_razao = st.text_input("Razão social", value=c.get("razao_social") or "", key="adm_e_razao")
                        e_contato_nome = st.text_input("Contato (nome)", value=c.get("contato_nome") or "", key="adm_e_nome")
                        e_contato_email = st.text_input("Contato (e-mail)", value=c.get("contato_email") or "", key="adm_e_email")
                    with col2:
                        e_cnpj = st.text_input("CNPJ", value=c.get("cnpj") or "", key="adm_e_cnpj")
                        e_contato_whats = st.text_input("Contato (WhatsApp)", value=c.get("contato_whatsapp") or "", key="adm_e_whats")
                        plano_atual = "Pós-pago" if (c.get("plano_tipo") == "pos") else "Pré-pago"
                        e_plano_label = st.selectbox("Plano", ["Pós-pago", "Pré-pago"], index=0 if plano_atual == "Pós-pago" else 1, key="adm_e_plano")
                        e_plano_tipo = "pos" if e_plano_label == "Pós-pago" else "pre"

                    e_ativo = st.checkbox("Ativo", value=bool(c.get("ativo", True)), key="adm_e_ativo")
                    st.caption("Slug não é editável para não quebrar histórico.")

                    if st.button("Atualizar cliente", use_container_width=True):
                        try:
                            payload = {
                                "cnpj": (e_cnpj or "").strip() or None,
                                "razao_social": (e_razao or "").strip() or None,
                                "contato_nome": (e_contato_nome or "").strip() or None,
                                "contato_email": (e_contato_email or "").strip() or None,
                                "contato_whatsapp": (e_contato_whats or "").strip() or None,
                                "plano_tipo": e_plano_tipo,
                                "ativo": bool(e_ativo),
                                "email_principal": (e_contato_email or "").strip() or None,
                            }
                            db_update_cliente(c["id"], payload)
                            st.success("✅ Cliente atualizado.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao atualizar cliente: {e}")

            # ---- Valores remuneração (faixas)
            with sec[1]:
                st.write("#### Valores (Remuneração) — por faixa")
                st.caption("Você edita SOMENTE o valor unitário (R$). As quantidades ficam fixas.")

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
                        st.error(f"Não consegui acessar pricing_tiers ({plan_tipo}): {e}")

                    if not table_exists:
                        st.info("Se a tabela não existir, crie no Supabase (SQL).")
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
                                st.success("✅ Faixas criadas.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Falha ao inserir faixas: {e}")
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
                                st.number_input("Min", value=mn, step=1, disabled=True, key=f"{plan_tipo}_mn_{r['id']}")
                            with c2:
                                st.number_input("Max", value=mx, step=1, disabled=True, key=f"{plan_tipo}_mx_{r['id']}")
                            with c3:
                                new_price = st.number_input("Valor unitário (R$)", value=pr, step=0.01, key=f"{plan_tipo}_pr_{r['id']}")
                            with c4:
                                new_ativo = st.checkbox("Ativo", value=ativo, key=f"{plan_tipo}_at_{r['id']}")

                            if st.button("Salvar", key=f"{plan_tipo}_save_{r['id']}", use_container_width=True):
                                try:
                                    db_update_pricing_tier(r["id"], {"unit_price": float(new_price), "ativo": bool(new_ativo)})
                                    st.success("✅ Salvo.")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Erro ao salvar: {e}")

                render_tiers("pos", "PÓS-PAGO")
                st.divider()
                render_tiers("pre", "PRÉ-PAGO")

            # ---- E-mail config
            with sec[2]:
                st.write("#### E-mail (SMTP) — envio automático")
                st.caption("Porta **465** (SSL). Preencha e salve. Depois usamos na entrega por e-mail.")

                existing = _resp_data(db_get_email_config())
                row = existing[0] if existing else {}

                is_active = st.checkbox("Ativar envio por e-mail", value=bool(row.get("is_active", False)), key="em_active")
                smtp_host = st.text_input("SMTP Host", value=row.get("smtp_host") or "", key="em_host")
                smtp_port = st.number_input("SMTP Port", value=int(row.get("smtp_port") or DEFAULT_SMTP_PORT), step=1, key="em_port")
                smtp_user = st.text_input("SMTP User", value=row.get("smtp_user") or "", key="em_user")
                smtp_pass = st.text_input("SMTP Pass", value=row.get("smtp_pass") or "", type="password", key="em_pass")

                from_name = st.text_input("From Name", value=row.get("from_name") or "ContactBot", key="em_from_name")
                from_email = st.text_input("From E-mail", value=row.get("from_email") or smtp_user or "", key="em_from_email")

                template_assunto = st.text_input(
                    "Template de assunto",
                    value=row.get("template_assunto") or "Relatório ContactBot — {cliente} — {mes}/{ano}",
                    key="em_subj"
                )
                template_corpo = st.text_area(
                    "Template de mensagem",
                    value=row.get("template_corpo") or "Olá, segue o relatório.\n\nAtt,\nContactBot",
                    height=160,
                    key="em_body"
                )

                if st.button("Salvar configurações de e-mail", use_container_width=True):
                    try:
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
                    except Exception as e:
                        st.error(f"Erro ao salvar config de e-mail: {e}")

            # ---- Mercado Pago
            with sec[3]:
                st.write("#### PIX (Mercado Pago)")
                st.caption("Aqui ficam as chaves. Próximo passo: gerar PIX de recarga (pré-pago).")

                existing = _resp_data(db_get_mercadopago_config())
                row = existing[0] if existing else {}

                mp_active = st.checkbox("Ativar integração Mercado Pago", value=bool(row.get("is_active", False)), key="mp_active")
                access_token = st.text_input("Access Token", value=row.get("access_token") or "", type="password", key="mp_token")
                public_key = st.text_input("Public Key", value=row.get("public_key") or "", key="mp_pub")
                webhook_secret = st.text_input("Webhook Secret", value=row.get("webhook_secret") or "", type="password", key="mp_webhook")

                if st.button("Salvar configurações Mercado Pago", use_container_width=True):
                    try:
                        db_upsert_mercadopago_config({
                            "is_active": bool(mp_active),
                            "access_token": (access_token or "").strip() or None,
                            "public_key": (public_key or "").strip() or None,
                            "webhook_secret": (webhook_secret or "").strip() or None,
                        })
                        st.success("✅ Configurações salvas.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erro ao salvar config Mercado Pago: {e}")

            # ---- Entrega por e-mail (anexos) + Auditoria (profissional)
            with sec[4]:
                st.write("#### Entrega por e-mail (anexos)")
                st.caption("Envia os arquivos da remessa (Envios + Botões) e registra auditoria em **email_logs**.")

                # Escolher cliente + remessa
                clientes_resp = db_list_clientes()
                clientes = _resp_data(clientes_resp)
                if not clientes:
                    st.warning("Cadastre um cliente primeiro.")
                else:
                    map_label_to_cliente = {f'{c["razao_social"]} ({c["slug"]})': c for c in clientes}
                    cliente_label = st.selectbox("Cliente", list(map_label_to_cliente.keys()), key="mail_cli")
                    cliente = map_label_to_cliente[cliente_label]

                    rem_resp = db_list_remessas(cliente_id=cliente["id"], limit=300)
                    rems = _resp_data(rem_resp)
                    if not rems:
                        st.warning("Crie uma remessa primeiro.")
                    else:
                        map_label_to_rem = {f'{remessa_get_key(r)} (nº {remessa_get_numero(r)})': r for r in rems}
                        rem_label = st.selectbox("Remessa", list(map_label_to_rem.keys()), key="mail_rem")
                        rem = map_label_to_rem[rem_label]

                        # Checar uploads
                        up_resp = db_list_uploads(remessa_id=rem["id"], limit=200)
                        ups = _resp_data(up_resp)
                        env_u = next((u for u in ups if u.get("file_tipo") == "envios"), None)
                        bot_u = next((u for u in ups if u.get("file_tipo") == "botoes"), None)

                        colA, colB, colC = st.columns([1, 1, 2])
                        with colA:
                            st.markdown(f"<span class='cb-pill'>Envios: {'OK' if env_u else 'Pendente'}</span>", unsafe_allow_html=True)
                        with colB:
                            st.markdown(f"<span class='cb-pill'>Botões: {'OK' if bot_u else 'Pendente'}</span>", unsafe_allow_html=True)
                        with colC:
                            st.markdown(f"<span class='cb-muted'>Destino padrão do cliente: <b>{cliente.get('contato_email') or cliente.get('email_principal') or '-'}</b></span>", unsafe_allow_html=True)

                        st.divider()

                        email_cfg_rows = _resp_data(db_get_email_config())
                        if not email_cfg_rows:
                            st.warning("Configure o SMTP em **Configurações → E-mail (SMTP)**.")
                            st.stop()

                        cfg = email_cfg_rows[0]
                        if not bool(cfg.get("is_active", False)):
                            st.warning("Envio por e-mail está desativado. Ative em **E-mail (SMTP)**.")
                            st.stop()

                        to_default = (cliente.get("contato_email") or cliente.get("email_principal") or "").strip()
                        to_email = st.text_input("E-mail de destino", value=to_default, key="mail_to")

                        # assunto/corpo
                        d = datetime.strptime(rem.get("data"), "%Y-%m-%d").date() if rem.get("data") else date.today()
                        subj_tpl = cfg.get("template_assunto") or "Relatório ContactBot — {cliente} — {mes}/{ano}"
                        body_tpl = cfg.get("template_corpo") or "Olá, segue o relatório.\n\nAtt,\nContactBot"

                        assunto_prev = subj_tpl.format(cliente=cliente.get("razao_social", ""), mes=d.month, ano=d.year, remessa=remessa_get_key(rem))
                        corpo_prev = body_tpl.format(cliente=cliente.get("razao_social", ""), mes=d.month, ano=d.year, remessa=remessa_get_key(rem))

                        st.text_input("Assunto (prévia)", value=assunto_prev, key="mail_subj")
                        st.text_area("Mensagem (prévia)", value=corpo_prev, height=120, key="mail_body")

                        can_send = bool(env_u or bot_u) and bool(to_email.strip())

                        if st.button("Enviar relatório desta remessa", type="primary", use_container_width=True, disabled=not can_send):
                            started = datetime.now(timezone.utc).isoformat()
                            attachments: List[Tuple[str, bytes, str]] = []
                            attach_meta = []

                            try:
                                # anexos
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

                                # auditoria
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
                                # auditoria de erro
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

                        # Auditoria (histórico)
                        st.write("#### Auditoria de e-mails (histórico)")
                        st.caption("Registros em **email_logs** — útil para comprovação e suporte.")

                        # buscamos logs e montamos lista de status existente (sem hardcode feio)
                        logs_resp = db_list_email_logs(cliente_id=cliente["id"], remessa_id=rem["id"], status=None, limit=300)
                        logs = _resp_data(logs_resp) or []

                        existing_statuses = sorted(list({(l.get("status") or "").strip() for l in logs if (l.get("status") or "").strip()}))
                        options = ["Todos"] + (existing_statuses if existing_statuses else ["sent", "error"])

                        cF1, cF2 = st.columns([1, 1])
                        with cF1:
                            status_filter = st.selectbox("Status", options, index=0, key="mail_log_status")
                        with cF2:
                            limit = st.number_input("Quantidade", min_value=50, max_value=500, value=200, step=50, key="mail_log_limit")

                        logs_resp2 = db_list_email_logs(cliente_id=cliente["id"], remessa_id=rem["id"], status=status_filter, limit=int(limit))
                        logs2 = _resp_data(logs_resp2) or []

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
                                    "erro": (l.get("error_message") or "")[:140] if l.get("status") == "error" else "",
                                })

                            st.dataframe(out, use_container_width=True)

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

    if st.button("Entrar", type="primary", use_container_width=True):
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

    st.divider()
    st.caption("Criação de usuários e troca de senha ficam no painel do admin (para não expor).")

with col_right:
    st.subheader("Admin (somente)")
    st.caption("Criação de usuário e redefinição de senha (sem e-mail), usando SERVICE ROLE KEY.")

    if not session_is_logged_in():
        st.info("Faça login como admin para gerenciar usuários.")
    else:
        if is_admin_user():
            st.write("##### Criar usuário")
            new_email = st.text_input("E-mail do novo usuário", value="", key="new_email")
            new_pass1 = st.text_input("Senha do novo usuário", value="", type="password", key="new_pass1")
            new_pass2 = st.text_input("Confirmar senha", value="", type="password", key="new_pass2")

            if st.button("Criar usuário", use_container_width=True):
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
                    st.success("✅ Usuário criado e confirmado.")
                except Exception as e:
                    st.error(f"Falha ao criar usuário: {e}")

            st.divider()

            st.write("##### Definir senha (usuário existente)")
            adm_email = st.text_input("E-mail do usuário", value="", key="adm_email")
            adm_pass1 = st.text_input("Nova senha", value="", type="password", key="adm_pass1")
            adm_pass2 = st.text_input("Confirmar nova senha", value="", type="password", key="adm_pass2")

            if st.button("Definir senha", use_container_width=True):
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
                    st.success("✅ Senha definida.")
                except Exception as e:
                    st.error(f"Falha ao definir senha: {e}")
        else:
            st.warning("Você não é admin.")

st.divider()
st.caption("Reset por e-mail segue desativado neste app (decisão de segurança).")
