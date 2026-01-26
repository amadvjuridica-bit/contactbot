import os
import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# =========================
# Config
# =========================
st.set_page_config(page_title="ContactBot — Login", layout="wide")

load_dotenv()

# 1) Primeiro tenta .env
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

# 2) Se estiver no Streamlit Cloud, pode vir de st.secrets
# (isso não atrapalha local; só ajuda em produção)
if not SUPABASE_URL and "SUPABASE_URL" in st.secrets:
    SUPABASE_URL = str(st.secrets["SUPABASE_URL"]).strip()
if not SUPABASE_ANON_KEY and "SUPABASE_ANON_KEY" in st.secrets:
    SUPABASE_ANON_KEY = str(st.secrets["SUPABASE_ANON_KEY"]).strip()
if not SUPABASE_SERVICE_ROLE_KEY and "SUPABASE_SERVICE_ROLE_KEY" in st.secrets:
    SUPABASE_SERVICE_ROLE_KEY = str(st.secrets["SUPABASE_SERVICE_ROLE_KEY"]).strip()

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
        st.error(f"Faltando no .env / secrets: {', '.join(missing)}")
        st.info("Local: crie um arquivo .env na mesma pasta do app.py e reinicie o Streamlit.")
        st.info("Streamlit Cloud: App > Settings > Secrets (formato TOML).")
        st.stop()

ensure_env_or_stop()

@st.cache_resource(show_spinner=False)
def get_clients() -> tuple[Client, Client]:
    # Client para login normal (anon)
    supa_public = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    # Client admin (service role)
    supa_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return supa_public, supa_admin

supabase_public, supabase_admin = get_clients()

# =========================
# Helpers (Supabase Admin/Auth)
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
        users = getattr(resp, "users", None) or (resp.get("users", []) if isinstance(resp, dict) else [])
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
# Sessão (Streamlit)
# =========================
def set_logged_user(user: dict, session: dict):
    st.session_state["auth_user"] = user
    st.session_state["auth_session"] = session
    st.session_state["is_logged_in"] = True

def clear_logged_user():
    for k in ["auth_user", "auth_session", "is_logged_in", "page"]:
        if k in st.session_state:
            del st.session_state[k]

def is_logged_in() -> bool:
    return bool(st.session_state.get("is_logged_in")) and bool(st.session_state.get("auth_user"))

# =========================
# UI: Login
# =========================
def render_login():
    st.title("🔐 ContactBot — Login")

    with st.expander("Diagnóstico rápido (.env / secrets)"):
        st.write("SUPABASE_URL:", SUPABASE_URL)
        st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
        st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))

    col_left, col_right = st.columns([1.2, 1.0], gap="large")

    with col_left:
        st.subheader("Entrar")

        login_email = st.text_input("E-mail", value="", placeholder="seuemail@dominio.com")
        login_pass = st.text_input("Senha", value="", type="password", placeholder="Digite sua senha")

        if st.button("Entrar", type="primary", use_container_width=True):
            try:
                resp = do_login(login_email, login_pass)

                session = getattr(resp, "session", None) or (resp.get("session") if isinstance(resp, dict) else None)
                user = getattr(resp, "user", None) or (resp.get("user") if isinstance(resp, dict) else None)

                # supabase-py pode devolver User/Session como objetos
                # vamos transformar em dict "safe" quando possível
                if user and not isinstance(user, dict) and hasattr(user, "model_dump"):
                    user = user.model_dump()
                if session and not isinstance(session, dict) and hasattr(session, "model_dump"):
                    session = session.model_dump()

                if session and user:
                    set_logged_user(user, session)
                    st.success("✅ Login OK! Abrindo painel…")
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
        st.caption("Isso resolve 'senha incorreta' sem reset por e-mail. Usa SERVICE ROLE KEY do .env/secrets.")

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

# =========================
# UI: App pós-login (estrutura)
# =========================
def render_app():
    user = st.session_state.get("auth_user") or {}
    email = user.get("email", "")
    uid = user.get("id", "")

    # Sidebar: menu
    with st.sidebar:
        st.markdown("## ContactBot")
        st.caption(f"Logado como: **{email}**")
        st.caption(f"User ID: `{uid}`")

        st.divider()

        page = st.radio(
            "Menu",
            ["Dashboard", "Usuários", "Upload de Base", "Relatórios", "Configurações"],
            index=0,
            key="page"
        )

        st.divider()

        if st.button("🚪 Sair", use_container_width=True):
            clear_logged_user()
            st.success("Saiu da sessão.")
            st.rerun()

    # Conteúdo
    st.title("📊 ContactBot — Painel")

    if page == "Dashboard":
        st.subheader("Dashboard (primeira versão)")
        st.info("Aqui vai o resumo do dia/mês, volume enviado, cliques, conversão, etc.")
        st.write("✅ Estrutura pronta. Próximo passo: plugar seus CSVs e criar os cards/gráficos.")

    elif page == "Usuários":
        st.subheader("Usuários")
        st.info("Aqui vamos criar: Admin + usuários por cliente, permissões e auditoria.")

    elif page == "Upload de Base":
        st.subheader("Upload de Base (CSV)")
        st.info("Aqui você vai subir o arquivo do cliente (base), validar colunas e salvar no banco.")
        uploaded = st.file_uploader("Envie um CSV", type=["csv"])
        if uploaded:
            st.success("Arquivo recebido. Próximo passo: leitura/validação e armazenamento.")

    elif page == "Relatórios":
        st.subheader("Relatórios")
        st.info("Aqui entram: resultado do envio + cliques, sintético e analítico.")

    elif page == "Configurações":
        st.subheader("Configurações")
        st.info("Aqui entra: configurações por cliente (telefone, templates, limites, etc).")

# =========================
# Router (Login vs App)
# =========================
if is_logged_in():
    render_app()
else:
    render_login()
