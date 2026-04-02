import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
import sqlite3
import bcrypt
import time

st.set_page_config(page_title="DB Corp Security System", layout="wide")

# ---------------- DATABASE ----------------
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password BLOB,
    role TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS logs (
    user TEXT,
    time TEXT,
    status TEXT
)
""")

conn.commit()

# ---------------- SECURITY ----------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def log_event(user, status):
    c.execute("INSERT INTO logs VALUES (?,?,?)", (user, time.ctime(), status))
    conn.commit()

# ---------------- DEMO USERS (SAFE INSERT) ----------------
c.execute("SELECT COUNT(*) FROM users")
if c.fetchone()[0] == 0:
    c.execute("INSERT INTO users VALUES (?,?,?)",
              ("admin", hash_password("1234"), "admin"))
    c.execute("INSERT INTO users VALUES (?,?,?)",
              ("analyst", hash_password("soc123"), "analyst"))
    conn.commit()

# ---------------- SESSION ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.login_attempts = 0
    st.session_state.last_activity = time.time()
    st.session_state.menu = "Login"

# ---------------- SESSION TIMEOUT ----------------
SESSION_TIMEOUT = 600

if st.session_state.logged_in:
    if time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
        st.session_state.logged_in = False
        st.warning("Session expired")
        st.stop()

st.session_state.last_activity = time.time()

# ---------------- UI ----------------
st.markdown("""
<style>
.banner-scroll {
background:linear-gradient(90deg,#06b6d4,#3b82f6,#9333ea);
padding:8px;color:white;font-weight:bold;text-align:center;
border-radius:8px;margin-bottom:10px;
}

section[data-testid="stSidebar"] * {
cursor:pointer !important;
}

.footer {
position:fixed;bottom:0;width:100%;background:#020617;
color:white;text-align:center;padding:10px;
border-top:1px solid #1e293b;
}
</style>
""", unsafe_allow_html=True)

# -------- LOGO HEADER --------
col1, col2 = st.columns([1,6])

with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=80)

with col2:
    st.markdown("### DB Corp Cybersecurity Operations Dashboard")

# -------- SCROLLING LINE --------
st.markdown(
    '<div class="banner-scroll"><marquee>AI-Powered Anomaly Detection | Cyber Threat Monitoring | Security Intelligence Dashboard</marquee></div>',
    unsafe_allow_html=True
)

# ---------------- MENU ----------------
menu_options = ["Login","Register","Dashboard","Logs"]

menu = st.sidebar.selectbox(
    "Menu",
    menu_options,
    index=menu_options.index(st.session_state.menu)
)

# ---------------- LOGIN ----------------
if menu == "Login":

    st.info("Demo → admin / 1234 | analyst / soc123")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.session_state.login_attempts >= 5:
        st.error("Too many attempts")
        st.stop()

    if st.button("Login"):

        c.execute("SELECT * FROM users WHERE username=?", (user,))
        result = c.fetchone()

        if result and verify_password(pwd, result[1]):
            st.session_state.logged_in = True
            st.session_state.username = user
            st.session_state.role = result[2]
            st.session_state.menu = "Dashboard"

            log_event(user, "SUCCESS")

            st.success("Login successful")
            st.rerun()
        else:
            st.session_state.login_attempts += 1
            log_event(user, "FAILED")
            st.error("Invalid credentials")

# ---------------- REGISTER ----------------
elif menu == "Register":

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Register"):

        try:
            c.execute("INSERT INTO users VALUES (?,?,?)",
                      (user, hash_password(pwd), "analyst"))
            conn.commit()
            st.success("Account created (Analyst role)")
        except:
            st.error("Username already exists")

# ---------------- DASHBOARD ----------------
elif menu == "Dashboard":

    if not st.session_state.logged_in:
        st.warning("Login required")
        st.stop()

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.menu = "Login"
        st.stop()

    file = st.file_uploader("Upload dataset", type=["csv","xlsx"])

    st.markdown("""
    <div style='background:#111827;padding:15px;border-left:5px solid #22c55e;
    border-radius:10px;margin-top:10px;'>
    <b style='color:#22c55e;'>Dataset Requirements</b><br>
    User ID, Country, Login Successful, RTT, Is Attack IP
    </div>
    """, unsafe_allow_html=True)

    if file:
        df = pd.read_csv(file) if file.name.endswith(".csv") else pd.read_excel(file)

        df["Login Successful"] = df["Login Successful"].astype(int)
        df["Is Attack IP"] = df["Is Attack IP"].astype(int)

        features = df[["Round-Trip Time [ms]","Login Successful","Is Attack IP"]]

        model = IsolationForest(contamination=0.1)
        model.fit(features)

        df["Anomaly"] = model.predict(features)
        df["Anomaly"] = df["Anomaly"].apply(lambda x: "Suspicious" if x==-1 else "Normal")

        df["Risk Score"] = (-model.decision_function(features)).round(3)

        suspicious = df[df["Anomaly"]=="Suspicious"]

        st.metric("Suspicious Logins", len(suspicious))

        col1, col2 = st.columns(2)

        with col1:
            st.plotly_chart(px.pie(df, names="Login Successful"))

        with col2:
            st.plotly_chart(px.histogram(df, x="Round-Trip Time [ms]"))

        st.dataframe(df)
        st.dataframe(suspicious)

# ---------------- LOGS ----------------
elif menu == "Logs":

    if st.session_state.role != "admin":
        st.error("Admin only")
        st.stop()

    logs = pd.read_sql("SELECT * FROM logs", conn)
    st.dataframe(logs)

# ---------------- FOOTER ----------------
st.markdown("""
<div class="footer">
Enterprise Cybersecurity Protection | Threat Monitoring | Incident Response |
Phone: +1-800-555-0148 | Email: enterprise-security@protectionlabs.io
</div>
""", unsafe_allow_html=True)
