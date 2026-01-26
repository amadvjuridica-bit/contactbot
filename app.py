import os
import io
import csv
import hashlib
from datetime import datetime, timezone

import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# =========================
# Config
# =========================
st.set_page_config(page_title="ContactBot — Login", layout="wide")

load_dotenv()

def get_secret(name: str, default: str = "") -> str:
    """
    Busca config primeiro no .env (local), depois em st.secrets (Streamlit Cloud).
    """
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

# Bucket onde vamos guardar CSVs
UPLOADS_BUCKET = "contactbot-uploads"

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
        st.info("Streamlit Cloud: configure em Manage app → Settings → Secrets (formato TOML).")
        st.stop()

ensure_env_or_stop()

@st.cache_resource(show_spinner=False)
def get_clients() -> tuple[Client, Client]:
    # Client para login normal (publishable/anon)
    supa_public = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    # Client admin (service role)
    supa_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return supa_public, supa_admin

supabase_public, supabase_admin = get_clients()

# =========================
# Session helpers (página única)
# =========================
def session_is_logged_in() -> bool:
    return bool(st.session_state.get("access_token")) and bool(st.session_state.get("user"))

def session_set_from_auth_response(resp):
    """
    Salva sessão em st.session_state a partir da resposta do supabase-py.
    """
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
    st.session_state["user"] = {
        "email": user_email,
        "id": user_id,
    }
    return True

def do_logout():
    try:
        supabase_public.auth.sign_out()
    except Exception:
        pass

    for k in ["access_token", "refresh_token", "user"]:
        if k in st.session_state:
            del st.session_state[k]

    st.rerun()

# =========================
# Helpers (ADMIN / AUTH)
# =========================
def admin_find_user_by_email(email: str):
    email = (email or "").strip().lower()
    if not email:
        return None

    page = 1
    per_page = 200
    for _ in range(20):  # 4000 usuários
        resp = supabase_admin.auth.admin.list_users(page=page, per_page=per_page)

        users = getattr(resp, "users", None)
        if users is None and isinstance(resp, dict):
            users = resp.get("users", [])

        if not users:
            return None

        for u in users:
            u_email = (u.get("email") or "").strip().lower()
            if u_email == email:
                return u

        page += 1

    return None

def admin_create_user(email: str, password: str):
    email = email.strip()
    password = password.strip()
    return supabase_admin.auth.admin.create_user(
        {"email": email, "password": password, "email_confirm": True}
    )

def admin_set_password(email: str, new_password: str):
    u = admin_find_user_by_email(email)
    if not u:
        raise ValueError("Não achei esse e-mail no Supabase Auth > Users.")
    uid = u.get("id")
    if not uid:
        raise ValueError("Usuário encontrado, mas sem 'id'.")
    return supabase_admin.auth.admin.update_user_by_id(uid, {"password": new_password})

def do_login(email: str, password: str):
    email = email.strip()
    password = password.strip()
    return supabase_public.auth.sign_in_with_password({"email": email, "password": password})

# =========================
# Upload CSV helpers
# =========================
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_storage_path(user_email: str, original_name: str) -> str:
    safe_email = (user_email or "unknown").replace("@", "_at_").replace(".", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{safe_email}/{ts}__{original_name}"

def parse_csv_preview(data: bytes, max_rows: int = 30):
    """
    Tenta ler as primeiras linhas do CSV e devolve:
    - headers
    - rows (lista de dicts)
    """
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

def storage_upload_csv(bucket: str, path: str, data: bytes):
    """
    Sobe bytes para o Supabase Storage (via service role).
    """
    # supabase-py v2: upload(path, file, file_options={...})
    return supabase_admin.storage.from_(bucket).upload(
        path,
        data,
        file_options={"content-type": "text/csv", "upsert": False},
    )

def storage_signed_url(bucket: str, path: str, expires_in: int = 3600) -> str:
    """
    Cria link assinado (private bucket).
    """
    resp = supabase_admin.storage.from_(bucket).create_signed_url(path, expires_in)
    if isinstance(resp, dict) and "signedURL" in resp:
        return resp["signedURL"]
    # algumas versões retornam {"data": {"signedUrl": "..."}}
    if isinstance(resp, dict) and "data" in resp and isinstance(resp["data"], dict):
        return resp["data"].get("signedUrl") or resp["data"].get("signedURL") or ""
    return ""

def db_insert_upload_record(user_id: str, user_email: str, file_name: str, bucket: str, path: str, size_bytes: int, sha256: str):
    return supabase_admin.table("uploads").insert({
        "user_id": user_id,
        "user_email": user_email,
        "file_name": file_name,
        "storage_bucket": bucket,
        "storage_path": path,
        "size_bytes": size_bytes,
        "sha256": sha256,
    }).execute()

def db_list_uploads(limit: int = 50):
    return supabase_admin.table("uploads").select("*").order("created_at", desc=True).limit(limit).execute()

# =========================
# UI
# =========================
st.title("🔐 ContactBot — Login")

with st.expander("Diagnóstico rápido (config)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))
    st.write("UPLOADS_BUCKET:", UPLOADS_BUCKET)

# =========================
# PAINEL (página única) — aparece só quando logado
# =========================
if session_is_logged_in():
    user = st.session_state.get("user", {}) or {}
    user_email = user.get("email", "")
    user_id = user.get("id", "")

    top_l, top_r = st.columns([4, 1])
    with top_l:
        st.subheader("✅ Painel (logado)")
        st.caption(f"Logado como: {user_email} | User ID: {user_id}")
    with top_r:
        if st.button("Sair (logout)", use_container_width=True):
            do_logout()

    st.divider()

    tabs = st.tabs(["Dashboard", "Uploads (CSV)", "Envios", "Relatórios"])

    with tabs[0]:
        st.write("📌 **Dashboard** (placeholder)")
        st.info("Aqui vai entrar o resumo executivo e os KPIs.")

    with tabs[1]:
        st.write("📤 **Uploads de CSV**")

        uploaded = st.file_uploader("Envie um CSV", type=["csv"])
        if uploaded:
            data = uploaded.getvalue()
            file_name = uploaded.name
            size_bytes = len(data)
            digest = sha256_hex(data)

            st.caption(f"Arquivo: **{file_name}** | Tamanho: **{size_bytes} bytes** | SHA256: `{digest[:16]}...`")

            # Preview
            try:
                headers, rows = parse_csv_preview(data, max_rows=30)
                if not headers:
                    st.warning("Não encontrei cabeçalho (primeira linha). Mesmo assim dá pra salvar.")
                else:
                    st.success(f"Colunas detectadas: {len(headers)}")
                    st.dataframe(rows, use_container_width=True)
            except Exception as e:
                st.warning(f"Não consegui gerar preview do CSV: {e}")

            st.divider()

            if st.button("Salvar este CSV no Supabase", type="primary", use_container_width=True):
                try:
                    path = make_storage_path(user_email, file_name)

                    # 1) Upload no Storage
                    storage_upload_csv(UPLOADS_BUCKET, path, data)

                    # 2) Registro no banco
                    db_insert_upload_record(
                        user_id=user_id,
                        user_email=user_email,
                        file_name=file_name,
                        bucket=UPLOADS_BUCKET,
                        path=path,
                        size_bytes=size_bytes,
                        sha256=digest,
                    )

                    st.success("✅ CSV salvo no Storage e registrado na tabela uploads!")
                    st.rerun()

                except Exception as e:
                    st.error(f"Falha ao salvar no Supabase: {e}")

        st.divider()
        st.subheader("Últimos uploads")

        try:
            resp = db_list_uploads(limit=50)
            rows = []
            if hasattr(resp, "data"):
                rows = resp.data or []
            elif isinstance(resp, dict):
                rows = resp.get("data", []) or []

            if not rows:
                st.info("Nenhum upload registrado ainda.")
            else:
                # Tabela simples
                st.dataframe(
                    [{
                        "created_at": r.get("created_at"),
                        "user_email": r.get("user_email"),
                        "file_name": r.get("file_name"),
                        "size_bytes": r.get("size_bytes"),
                        "storage_path": r.get("storage_path"),
                    } for r in rows],
                    use_container_width=True
                )

                st.caption("Baixar: selecione um item abaixo (link assinado de 1h).")
                options = {f'{r.get("created_at")} | {r.get("file_name")}': r for r in rows}
                choice = st.selectbox("Escolha um upload para baixar", list(options.keys()))
                chosen = options[choice]

                if st.button("Gerar link de download (1 hora)", use_container_width=True):
                    url = storage_signed_url(UPLOADS_BUCKET, chosen.get("storage_path"), expires_in=3600)
                    if not url:
                        st.error("Não consegui gerar o link assinado.")
                    else:
                        st.success("Link gerado ✅")
                        st.code(url)  # link aparece aqui

        except Exception as e:
            st.error(f"Erro ao listar uploads: {e}")

    with tabs[2]:
        st.write("📨 **Envios** (placeholder)")
        st.info("Aqui vai ficar a gestão dos disparos em massa e filas por cliente.")

    with tabs[3]:
        st.write("📊 **Relatórios** (placeholder)")
        st.info("Aqui entram os relatórios sintético/analítico e as tabelas diárias.")

    st.stop()

# =========================
# LOGIN / ADMIN — aparece só quando NÃO logado
# =========================
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
                st.error("Login não retornou sessão. Confira e-mail/senha e a confirmação de e-mail no Supabase.")
        except Exception as e:
            st.error(f"Login falhou: {e}")

    st.divider()

    st.subheader("Criar usuário (sem e-mail / sem confirmação)")
    new_email = st.text_input("E-mail do novo usuário", value="", key="new_email")
    new_pass1 = st.text_input("Senha do novo usuário", value="", type="password", key="new_pass1")
    new_pass2 = st.text_input("Confirmar senha", value="", type="password", key="new_pass2")

    if st.button("Criar usuário agora", use_container_width=True):
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
            st.success("✅ Usuário criado e confirmado (sem e-mail). Agora faça login acima.")
        except Exception as e:
            st.error(f"Falha ao criar usuário: {e}")

with col_right:
    st.subheader("Admin (definir senha sem e-mail)")
    st.caption("Isso resolve 'senha incorreta' sem reset por e-mail. Usa SERVICE ROLE KEY do .env/Secrets.")

    adm_email = st.text_input("E-mail do usuário", value="", key="adm_email")
    adm_pass1 = st.text_input("Nova senha", value="", type="password", key="adm_pass1")
    adm_pass2 = st.text_input("Confirmar nova senha", value="", type="password", key="adm_pass2")

    if st.button("Definir senha agora", use_container_width=True):
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
            st.success("✅ Senha definida! Agora faça login na coluna da esquerda.")
        except Exception as e:
            st.error(f"Falha ao definir senha: {e}")

st.divider()
st.caption("Reset por e-mail está desativado neste app por enquanto.")
