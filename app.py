import os
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

    # session pode ser objeto (Session) ou dict dependendo da versão/uso
    access_token = getattr(session, "access_token", None) or (session.get("access_token") if isinstance(session, dict) else None)
    refresh_token = getattr(session, "refresh_token", None) or (session.get("refresh_token") if isinstance(session, dict) else None)

    # user pode ser objeto (User) ou dict
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
    # Tenta sign_out (não é obrigatório, mas é bom)
    try:
        supabase_public.auth.sign_out()
    except Exception:
        pass

    # Limpa sessão local do Streamlit
    for k in ["access_token", "refresh_token", "user"]:
        if k in st.session_state:
            del st.session_state[k]

    st.rerun()

# =========================
# Helpers (ADMIN / AUTH)
# =========================
def admin_find_user_by_email(email: str):
    """
    Procura usuário por email via admin list_users (paginação simples).
    Retorna dict do usuário ou None.
    """
    email = (email or "").strip().lower()
    if not email:
        return None

    page = 1
    per_page = 200
    for _ in range(20):  # 20 * 200 = 4000 usuários
        resp = supabase_admin.auth.admin.list_users(page=page, per_page=per_page)

        # resp pode ser objeto com .users, ou dict com "users"
        users = getattr(resp, "users", None)
        if users is None and isinstance(resp, dict):
            users = resp.get("users", [])

        if not users:
            return None

        for u in users:
            # u pode ser dict
            u_email = (u.get("email") or "").strip().lower()
            if u_email == email:
                return u
        page += 1

    return None

def admin_create_user(email: str, password: str):
    email = email.strip()
    password = password.strip()
    return supabase_admin.auth.admin.create_user(
        {
            "email": email,
            "password": password,
            "email_confirm": True,   # cria já confirmado (sem e-mail)
        }
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
# UI
# =========================
st.title("🔐 ContactBot — Login")

with st.expander("Diagnóstico rápido (config)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))

# =========================
# PAINEL (página única) — aparece só quando logado
# =========================
if session_is_logged_in():
    user = st.session_state.get("user", {}) or {}
    user_email = user.get("email", "")
    user_id = user.get("id", "")

    # Topbar simples
    top_l, top_r = st.columns([4, 1])
    with top_l:
        st.subheader("✅ Painel (logado)")
        st.caption(f"Logado como: {user_email} | User ID: {user_id}")
    with top_r:
        if st.button("Sair (logout)", use_container_width=True):
            do_logout()

    st.divider()

    tabs = st.tabs(["Dashboard", "Uploads", "Envios", "Relatórios"])

    with tabs[0]:
        st.write("📌 **Dashboard** (placeholder)")
        st.info("Aqui vai entrar o resumo executivo e os KPIs.")

    with tabs[1]:
        st.write("📤 **Uploads** (placeholder)")
        uploaded = st.file_uploader("Envie um arquivo (CSV/Excel)", type=["csv", "xlsx", "xls"])
        if uploaded:
            st.success(f"Arquivo recebido: {uploaded.name} ({uploaded.size} bytes)")
            st.caption("Depois vamos: validar colunas → salvar no Supabase Storage → registrar no banco.")

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
