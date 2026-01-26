import os
import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# =========================
# Config
# =========================
st.set_page_config(page_title="ContactBot — Login", layout="wide")

load_dotenv()

# Lê do .env (local) e também do st.secrets (Streamlit Cloud)
def _get_secret(key: str) -> str:
    v = os.getenv(key, "").strip()
    if v:
        return v
    try:
        return str(st.secrets.get(key, "")).strip()
    except Exception:
        return ""

SUPABASE_URL = _get_secret("SUPABASE_URL")
SUPABASE_ANON_KEY = _get_secret("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = _get_secret("SUPABASE_SERVICE_ROLE_KEY")

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
        st.error(f"Faltando: {', '.join(missing)}")
        st.info(
            "Local: crie um arquivo .env na mesma pasta do app.py e reinicie o Streamlit.\n\n"
            "Streamlit Cloud: vá em Manage app → Settings → Secrets e coloque as chaves lá."
        )
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
# Session helpers
# =========================
def is_logged_in() -> bool:
    return bool(st.session_state.get("auth_user")) and bool(st.session_state.get("auth_session"))

def set_auth_state(user: dict, session: dict):
    st.session_state["auth_user"] = user
    st.session_state["auth_session"] = session

def clear_auth_state():
    st.session_state.pop("auth_user", None)
    st.session_state.pop("auth_session", None)

def do_logout():
    # tenta invalidar no supabase também
    try:
        supabase_public.auth.sign_out()
    except Exception:
        pass
    clear_auth_state()
    st.success("✅ Você saiu da conta.")
    st.rerun()

# =========================
# Helpers
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
    # varre até achar ou até um limite razoável
    for _ in range(20):  # 20 * 200 = 4000 usuários
        resp = supabase_admin.auth.admin.list_users(page=page, per_page=per_page)
        users = getattr(resp, "users", None) or resp.get("users", []) if isinstance(resp, dict) else []
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
# UI
# =========================
st.title("🔐 ContactBot — Login")

with st.expander("Diagnóstico rápido (.env / secrets)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))

# =========================
# PÓS-LOGIN (PAINEL)
# =========================
if is_logged_in():
    user = st.session_state["auth_user"]
    st.success("✅ Logado!")
    col_a, col_b = st.columns([1, 1])
    with col_a:
        st.write("**Usuário:**", user.get("email"))
        st.write("**User ID:**", user.get("id"))
    with col_b:
        if st.button("Sair", type="secondary", use_container_width=True):
            do_logout()

    st.divider()

    st.subheader("📌 Painel (inicial)")
    st.info(
        "Aqui é onde vamos colocar o app de verdade.\n\n"
        "Próximo passo: criar o menu do ContactBot (Upload da base, Processamento, Relatórios)."
    )

    # Placeholder de navegação (a gente troca pelo menu real depois)
    aba = st.radio("O que você quer abrir agora?", ["Upload (em breve)", "Relatórios (em breve)", "Config (em breve)"], horizontal=True)
    st.write("Você selecionou:", aba)

    st.stop()

# =========================
# TELA DE LOGIN (quando NÃO está logado)
# =========================
col_left, col_right = st.columns([1.2, 1.0], gap="large")

with col_left:
    st.subheader("Entrar")

    login_email = st.text_input("E-mail", value="", placeholder="seuemail@dominio.com")
    login_pass = st.text_input("Senha", value="", type="password", placeholder="Digite sua senha")

    if st.button("Entrar", type="primary", use_container_width=True):
        try:
            resp = do_login(login_email, login_pass)

            session = getattr(resp, "session", None) or resp.get("session") if isinstance(resp, dict) else None
            user = getattr(resp, "user", None) or resp.get("user") if isinstance(resp, dict) else None

            if session and user:
                # Garantir dict simples
                user_dict = user if isinstance(user, dict) else (user.model_dump() if hasattr(user, "model_dump") else dict(user))
                session_dict = session if isinstance(session, dict) else (session.model_dump() if hasattr(session, "model_dump") else dict(session))

                set_auth_state(user_dict, session_dict)
                st.success("✅ Login OK! Indo para o painel…")
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
    st.caption("Isso resolve 'senha incorreta' sem reset por e-mail. Usa SERVICE ROLE KEY do .env / secrets.")

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
