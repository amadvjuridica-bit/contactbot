import os
import streamlit as st
from dotenv import load_dotenv
from supabase import create_client, Client

# =========================
# Config
# =========================
st.set_page_config(page_title="ContactBot — Login", layout="wide")

# Carrega .env (funciona LOCAL). No Streamlit Cloud, o certo é st.secrets.
load_dotenv()

def get_setting(key: str, default: str = "") -> str:
    """
    Ordem de prioridade:
    1) Variável de ambiente do sistema (os.environ)
    2) Streamlit Secrets (st.secrets)
    3) .env carregado via load_dotenv (já cai no os.getenv)
    """
    v = os.getenv(key)
    if v is not None and str(v).strip() != "":
        return str(v).strip()

    try:
        # st.secrets pode existir no Cloud
        if key in st.secrets:
            return str(st.secrets[key]).strip()
    except Exception:
        pass

    return default

SUPABASE_URL = get_setting("SUPABASE_URL", "").strip()
SUPABASE_ANON_KEY = get_setting("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SERVICE_ROLE_KEY = get_setting("SUPABASE_SERVICE_ROLE_KEY", "").strip()

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
        st.info(
            "Local: crie um arquivo .env na mesma pasta do app.py.\n"
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

def _pick(obj, key: str):
    """Pega chave tanto de dict quanto de objeto com atributo."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)

# =========================
# UI
# =========================
st.title("🔐 ContactBot — Login")

with st.expander("Diagnóstico rápido (config)"):
    st.write("SUPABASE_URL:", SUPABASE_URL)
    st.write("SUPABASE_ANON_KEY:", _mask(SUPABASE_ANON_KEY))
    st.write("SUPABASE_SERVICE_ROLE_KEY:", _mask(SUPABASE_SERVICE_ROLE_KEY))
    st.caption("No Streamlit Cloud, isso vem de Manage app → Settings → Secrets.")

col_left, col_right = st.columns([1.2, 1.0], gap="large")

with col_left:
    st.subheader("Entrar")

    login_email = st.text_input("E-mail", value="", placeholder="seuemail@dominio.com")
    login_pass = st.text_input("Senha", value="", type="password", placeholder="Digite sua senha")

    if st.button("Entrar", type="primary", use_container_width=True):
        try:
            resp = do_login(login_email, login_pass)

            # supabase-py retorna normalmente um AuthResponse com .session e .user
            session = _pick(resp, "session") or (_pick(resp, "data") and _pick(_pick(resp, "data"), "session"))
            user = _pick(resp, "user") or (_pick(resp, "data") and _pick(_pick(resp, "data"), "user"))

            if session and user:
                st.success("✅ Login OK!")
                st.write("Usuário:", _pick(user, "email"))
                st.write("User ID:", _pick(user, "id"))
                st.info("Agora você pode colocar aqui o menu/painel do app após login.")
            else:
                # Mostra o que veio (pra matar o problema na hora)
                st.error("Login não retornou sessão. Isso normalmente é config errada (URL/ANON) ou usuário não confirmado.")
                st.write("DEBUG (resp):", resp)
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
