import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
import sqlite3
import bcrypt
import time

# ---------------- PAGE CONFIG ----------------
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

# ---------------- DEMO USERS ----------------
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

if "menu" not in st.session_state:
    st.session_state.menu = "Login"

# ---------------- UI ----------------
st.markdown("""
<style>
/* ✅ FINAL CURSOR FIX (targets ALL clickable sidebar elements) */
[data-testid="stSidebar"] * {
    cursor: pointer !important;
}

/* Header */
.cyber-header {
font-size:28px;
color:#22c55e;
text-shadow:0 0 10px #22c55e;
}

/* Banner */
.banner-scroll {
background:linear-gradient(90deg,#06b6d4,#3b82f6,#9333ea);
padding:8px;color:white;text-align:center;
border-radius:8px;margin-bottom:10px;
}

/* Footer */
.footer {
position:fixed;
bottom:0;
width:100%;
background:#020617;
color:white;
text-align:center;
padding:10px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
col1, col2 = st.columns([1,6])
with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=80)
with col2:
    st.markdown('<div class="cyber-header">DB Corp Cybersecurity Operations</div>', unsafe_allow_html=True)

st.markdown(
    '<div class="banner-scroll"><marquee>AI-Powered Anomaly Detection | Cyber Threat Monitoring | Security Intelligence Dashboard</marquee></div>',
    unsafe_allow_html=True
)

# ---------------- MENU (CONTROLLED) ----------------
menu_options = ["Login","Register","Dashboard","Logs"]

menu = st.sidebar.selectbox(
    "Menu",
    menu_options,
    index=menu_options.index(st.session_state.menu)
)

# keep sync
st.session_state.menu = menu

# ---------------- LOGIN ----------------
if menu == "Login":

    st.info("Demo → admin / 1234 | analyst / soc123")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Login"):

        c.execute("SELECT * FROM users WHERE username=?", (user,))
        result = c.fetchone()

        if result and verify_password(pwd, result[1]):
            st.session_state.logged_in = True
            st.session_state.username = user
            st.session_state.role = result[2]

            log_event(user, "SUCCESS")

            # ✅ FORCE REDIRECT
            st.session_state.menu = "Dashboard"
            st.rerun()

        else:
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
            st.success("Account created")
        except:
            st.error("Username exists")

# ---------------- DASHBOARD ----------------
elif menu == "Dashboard":

    if not st.session_state.logged_in:
        st.warning("Login first")
        st.stop()

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.menu = "Login"
        st.rerun()

    file = st.file_uploader("Upload Authentication Logs", type=["csv","xlsx"])

    if file:
        df = pd.read_csv(file) if file.name.endswith(".csv") else pd.read_excel(file)

        df["Login Successful"] = df["Login Successful"].astype(int)
        df["Is Attack IP"] = df["Is Attack IP"].astype(int)

        features = df[["Round-Trip Time [ms]","Login Successful","Is Attack IP"]]

        model = IsolationForest(contamination=0.1)
        model.fit(features)

        df["Anomaly_raw"] = model.predict(features)
        df["Risk Score"] = (-model.decision_function(features)).round(3)

        df["Anomaly"] = df["Anomaly_raw"].apply(lambda x: "Suspicious" if x==-1 else "Normal")

        df["Reason"] = df.apply(lambda r:
            ("High latency, " if r["Round-Trip Time [ms]"]>500 else "") +
            ("Failed login, " if r["Login Successful"]==0 else "") +
            ("Attack IP" if r["Is Attack IP"]==1 else "")
        , axis=1)

        st.dataframe(df)

# ---------------- LOGS ----------------
elif menu == "Logs":

    if not st.session_state.logged_in or st.session_state.role != "admin":
        st.error("Admin only")
        st.stop()

    logs = pd.read_sql("SELECT * FROM logs", conn)
    st.dataframe(logs)

# ---------------- FOOTER ----------------
st.markdown("""
<div class="footer">
Enterprise Cybersecurity Protection | Threat Monitoring | Incident Response
</div>
""", unsafe_allow_html=True)
