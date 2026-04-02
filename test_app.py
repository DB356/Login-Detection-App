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

c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password BLOB, role TEXT)")
c.execute("CREATE TABLE IF NOT EXISTS logs (user TEXT, time TEXT, status TEXT)")
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
    c.execute("INSERT INTO users VALUES (?,?,?)", ("admin", hash_password("1234"), "admin"))
    c.execute("INSERT INTO users VALUES (?,?,?)", ("analyst", hash_password("soc123"), "analyst"))
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
[data-testid="stSidebar"] * { cursor: pointer !important; }

.cyber-header {
font-size:28px;
color:#22c55e;
text-shadow:0 0 10px #22c55e;
}

.banner-scroll {
background:linear-gradient(90deg,#06b6d4,#3b82f6,#9333ea);
padding:8px;color:white;text-align:center;border-radius:8px;margin-bottom:10px;
}

.footer {
position:fixed;bottom:0;width:100%;background:#020617;color:white;text-align:center;padding:10px;
}
</style>
""", unsafe_allow_html=True)

col1, col2 = st.columns([1,6])
with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=80)
with col2:
    st.markdown('<div class="cyber-header">DB Corp Cybersecurity Operations</div>', unsafe_allow_html=True)

st.markdown('<div class="banner-scroll"><marquee>AI-Powered Anomaly Detection | Cyber Threat Monitoring | Security Intelligence Dashboard</marquee></div>', unsafe_allow_html=True)

menu_options = ["Login","Register","Dashboard","Logs"]
menu = st.sidebar.selectbox("Menu", menu_options, index=menu_options.index(st.session_state.menu))
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
            c.execute("INSERT INTO users VALUES (?,?,?)", (user, hash_password(pwd), "analyst"))
            conn.commit()
            st.success("Account created")
        except:
            st.error("Username exists")

# ---------------- DASHBOARD ----------------
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

        # -------- CLEAN PINPOINT EXPLANATION --------
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

        df["Severity"] = df["Risk Score"].apply(
            lambda s: "High" if s>0.6 else "Medium" if s>0.3 else "Low"
        )

        suspicious = df[df["Anomaly"]=="Suspicious"]

        st.metric("Suspicious Logins", len(suspicious))

        st.subheader("🔍 Pinpointed Anomaly Detection")
        st.dataframe(df[["User ID","Country","Anomaly","Risk Score","Severity","Reason"]])

        st.subheader("🚨 Suspicious Events")
        st.dataframe(suspicious)

        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(px.pie(df, names="Login Successful"), use_container_width=True)
        with col2:
            st.plotly_chart(px.histogram(df, x="Round-Trip Time [ms]"), use_container_width=True)

        # -------- TIMELINE --------
        df = df.reset_index(drop=True)
        df["Time"] = pd.date_range(start="2024-01-01", periods=len(df), freq="min")
        df["Suspicious"] = df["Anomaly"].apply(lambda x: 1 if x=="Suspicious" else 0)

        st.plotly_chart(px.line(df, x="Time", y="Suspicious"), use_container_width=True)

        # -------- DOWNLOAD --------
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download Report", csv, "report.csv")

# ---------------- LOGS (PROTECTED) ----------------
elif menu == "Logs":

    if not st.session_state.logged_in:
        st.error("Login required")
        st.stop()

    if st.session_state.role != "admin":
        st.error("Access denied (Admin only)")
        st.stop()

    logs = pd.read_sql("SELECT * FROM logs", conn)
    st.dataframe(logs)

# ---------------- FOOTER ----------------
st.markdown("""
<div class="footer">
Enterprise Cybersecurity Protection | Threat Monitoring | Incident Response
</div>
""", unsafe_allow_html=True)
