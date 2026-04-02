import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
import sqlite3
import bcrypt
import time
import re

st.set_page_config(page_title="DB Corp Security System", layout="wide")

# -------- DATABASE --------
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password BLOB, role TEXT)")
c.execute("CREATE TABLE IF NOT EXISTS logs (user TEXT, time TEXT, status TEXT)")
conn.commit()

# remove old admin
c.execute("DELETE FROM users WHERE username='admin'")
conn.commit()

# -------- SECURITY --------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def log_event(user, status):
    c.execute("INSERT INTO logs VALUES (?,?,?)", (user, time.ctime(), status))
    conn.commit()

def strong_password(p):
    return len(p) >= 6 and re.search("[A-Z]", p) and re.search("[0-9]", p)

# -------- DEMO USER --------
c.execute("SELECT COUNT(*) FROM users")
if c.fetchone()[0] == 0:
    c.execute("INSERT INTO users VALUES (?,?,?)", ("analyst", hash_password("soc123"), "analyst"))
    conn.commit()

# -------- SESSION --------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.login_attempts = 0
    st.session_state.last_activity = time.time()

if "page" not in st.session_state:
    st.session_state.page = "Login"

# -------- SESSION TIMEOUT --------
if st.session_state.logged_in:
    if time.time() - st.session_state.last_activity > 600:
        st.session_state.logged_in = False
        st.session_state.page = "Login"
        st.warning("Session expired. Please login again.")
        st.stop()

st.session_state.last_activity = time.time()

# -------- UI STYLE (modern touch only) --------
st.markdown("""
<style>
body {background:#030712;}
[data-testid="stSidebar"] {background:#020617;}
[data-testid="stSidebar"] * {cursor:pointer !important;}

.block-container {padding-top:1rem;}

.card {
    background:#020617;
    border:1px solid #1e293b;
    padding:16px;
    border-radius:12px;
}

.title {
    font-size:26px;
    font-weight:700;
    color:#38bdf8;
}

.sub {
    color:#64748b;
    font-size:12px;
}
</style>
""", unsafe_allow_html=True)

# -------- HEADER --------
st.markdown('<div class="title">DB Corp Cybersecurity Operations</div>', unsafe_allow_html=True)
st.markdown('<div class="sub">AI-Powered Threat Intelligence Platform</div>', unsafe_allow_html=True)

# -------- MENU (FIXED CLICK ISSUE) --------
with st.sidebar:

    if st.session_state.logged_in:
        st.success(f"Logged in: {st.session_state.username}")

        menu = st.radio(
            "Navigation",
            ["Dashboard", "Logs"],
            index=["Dashboard", "Logs"].index(st.session_state.page)
        )

        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.page = "Login"
            st.rerun()

    else:
        menu = st.radio(
            "Navigation",
            ["Login", "Register"],
            index=["Login", "Register"].index(st.session_state.page)
        )

st.session_state.page = menu

# -------- LOGIN --------
if menu == "Login":

    if st.session_state.logged_in:
        st.warning("Already logged in")
        st.stop()

    st.info("Demo → analyst / soc123")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.session_state.login_attempts >= 5:
        st.error("Too many failed attempts")
        st.stop()

    if st.button("Login"):
        c.execute("SELECT * FROM users WHERE username=?", (user,))
        result = c.fetchone()

        if result and verify_password(pwd, result[1]):
            st.session_state.logged_in = True
            st.session_state.username = user
            st.session_state.role = result[2]
            st.session_state.login_attempts = 0

            log_event(user, "SUCCESS")

            st.session_state.page = "Dashboard"
            st.rerun()
        else:
            st.session_state.login_attempts += 1
            log_event(user, "FAILED")
            st.error("Invalid credentials")

# -------- REGISTER --------
elif menu == "Register":

    if st.session_state.logged_in:
        st.warning("Logout first to create new account")
        st.stop()

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Register"):
        if not strong_password(pwd):
            st.error("Password must have 6+ chars, 1 uppercase, 1 number")
        else:
            try:
                c.execute("INSERT INTO users VALUES (?,?,?)", (user, hash_password(pwd), "analyst"))
                conn.commit()
                st.success("Account created")
            except:
                st.error("Username exists")

# -------- DASHBOARD --------
elif menu == "Dashboard":

    if not st.session_state.logged_in:
        st.warning("Login first")
        st.stop()

    file = st.file_uploader("Upload Authentication Logs", type=["csv","xlsx"])

    if file:
        df = pd.read_csv(file) if file.name.endswith(".csv") else pd.read_excel(file)

        required = ["User ID","Country","Login Successful","Round-Trip Time [ms]","Is Attack IP"]
        if not all(col in df.columns for col in required):
            st.error("Dataset format invalid")
            st.stop()

        df["Login Successful"] = df["Login Successful"].astype(int)
        df["Is Attack IP"] = df["Is Attack IP"].astype(int)

        features = df[["Round-Trip Time [ms]","Login Successful","Is Attack IP"]]

        model = IsolationForest(contamination=0.1)
        model.fit(features)

        df["Anomaly_raw"] = model.predict(features)
        df["Risk Score"] = (-model.decision_function(features)).round(3)

        def explain(row):
            reasons = []
            if row["Round-Trip Time [ms]"] > 500:
                reasons.append("High latency")
            if row["Login Successful"] == 0:
                reasons.append("Failed login")
            if row["Is Attack IP"] == 1:
                reasons.append("Known attack IP")
            if row["Risk Score"] > 0.5:
                reasons.append("Model anomaly score high")
            return ", ".join(reasons) if reasons else "Normal behavior"

        df["Anomaly"] = df["Anomaly_raw"].apply(lambda x: "Suspicious" if x==-1 else "Normal")
        df["Reason"] = df.apply(explain, axis=1)
        df["Severity"] = df["Risk Score"].apply(lambda s: "High" if s>0.6 else "Medium" if s>0.3 else "Low")

        suspicious = df[df["Anomaly"]=="Suspicious"]

        st.metric("Suspicious Logins", len(suspicious))

        st.dataframe(df)

        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(px.pie(df, names="Login Successful"), use_container_width=True)
        with col2:
            st.plotly_chart(px.histogram(df, x="Round-Trip Time [ms]"), use_container_width=True)

# -------- LOGS --------
elif menu == "Logs":

    if not st.session_state.logged_in:
        st.error("Login required")
        st.stop()

    if st.session_state.role != "admin":
        st.error("Access denied (Admin only)")
        st.stop()

    logs = pd.read_sql("SELECT * FROM logs", conn)
    st.dataframe(logs)
