import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
import sqlite3
import bcrypt
import time
import re

st.set_page_config(page_title=“DB Corp Security System”, layout=“wide”, page_icon=”:shield:”)

# –––––––– DATABASE ––––––––

conn = sqlite3.connect(“users.db”, check_same_thread=False)
c = conn.cursor()

c.execute(“CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password BLOB, role TEXT)”)
c.execute(“CREATE TABLE IF NOT EXISTS logs (user TEXT, time TEXT, status TEXT)”)
conn.commit()

c.execute(“DELETE FROM users WHERE username=‘admin’”)
conn.commit()

# –––––––– SECURITY ––––––––

def hash_password(password):
return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
return bcrypt.checkpw(password.encode(), hashed)

def log_event(user, status):
c.execute(“INSERT INTO logs VALUES (?,?,?)”, (user, time.ctime(), status))
conn.commit()

def strong_password(p):
return len(p) >= 6 and re.search(”[A-Z]”, p) and re.search(”[0-9]”, p)

# –––––––– DEMO USER ––––––––

c.execute(“SELECT COUNT(*) FROM users”)
if c.fetchone()[0] == 0:
c.execute(“INSERT INTO users VALUES (?,?,?)”, (“analyst”, hash_password(“soc123”), “analyst”))
conn.commit()

# –––––––– SESSION ––––––––

if “logged_in” not in st.session_state:
st.session_state.logged_in = False
st.session_state.username = “”
st.session_state.role = “”
st.session_state.login_attempts = 0
st.session_state.last_activity = time.time()

if “page” not in st.session_state:
st.session_state.page = “Login”

# –––––––– SESSION TIMEOUT ––––––––

if st.session_state.logged_in:
if time.time() - st.session_state.last_activity > 600:
st.session_state.logged_in = False
st.session_state.page = “Login”
st.warning(“Session expired. Please login again.”)
st.stop()

st.session_state.last_activity = time.time()

# –––––––– STYLES ––––––––

st.markdown(”””

<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');

html, body, [data-testid="stAppViewContainer"] {
    background: #040d1a !important;
    color: #e2e8f0 !important;
    font-family: 'Syne', sans-serif !important;
}

[data-testid="stSidebar"] {
    background: #060f20 !important;
    border-right: 1px solid #0f2240 !important;
}

[data-testid="stTextInput"] input {
    background: #060f20 !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 8px !important;
    color: #e2e8f0 !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 13px !important;
}

[data-testid="stTextInput"] label {
    color: #64748b !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 11px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
}

[data-testid="stButton"] > button {
    background: linear-gradient(135deg, #0369a1, #1d4ed8) !important;
    border: none !important;
    border-radius: 8px !important;
    color: white !important;
    font-family: 'Syne', sans-serif !important;
    font-weight: 700 !important;
    font-size: 13px !important;
    letter-spacing: 1px !important;
    padding: 10px 24px !important;
    box-shadow: 0 4px 12px rgba(3,105,161,0.3) !important;
    transition: all 0.2s !important;
}

[data-testid="stButton"] > button:hover {
    background: linear-gradient(135deg, #0284c7, #2563eb) !important;
    transform: translateY(-1px) !important;
}

[data-testid="stMetric"] {
    background: #060f20;
    border: 1px solid #0f2240;
    border-radius: 10px;
    padding: 16px 20px;
}

[data-testid="stMetricValue"] {
    color: #38bdf8 !important;
    font-family: 'Space Mono', monospace !important;
}

[data-testid="stDownloadButton"] > button {
    background: linear-gradient(135deg, #065f46, #047857) !important;
}

.main-header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 20px 0 10px 0;
    border-bottom: 1px solid #0f2240;
    margin-bottom: 24px;
}

.header-title {
    font-family: 'Syne', sans-serif;
    font-size: 26px;
    font-weight: 800;
    background: linear-gradient(90deg, #38bdf8, #818cf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0;
}

.header-subtitle {
    font-family: 'Space Mono', monospace;
    font-size: 11px;
    color: #475569;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-top: 2px;
}

.ticker {
    background: #060f20;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 8px 16px;
    margin-bottom: 24px;
    font-family: 'Space Mono', monospace;
    font-size: 11px;
    color: #38bdf8;
    letter-spacing: 1px;
}

.login-card {
    max-width: 420px;
    margin: 40px auto;
    background: #060f20;
    border: 1px solid #1e3a5f;
    border-radius: 16px;
    padding: 40px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
}

.sidebar-user-card {
    background: #0c1f3a;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 14px;
    margin: 12px 0;
}

.footer {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    background: #020814;
    border-top: 1px solid #0f2240;
    color: #334155;
    text-align: center;
    padding: 10px;
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    letter-spacing: 1px;
    z-index: 999;
}
</style>

“””, unsafe_allow_html=True)

# –––––––– HEADER ––––––––

st.markdown(”””

<div class="main-header">
    <div style="font-size:32px">&#128737;</div>
    <div>
        <div class="header-title">DB Corp Security Operations</div>
        <div class="header-subtitle">AI-Powered Threat Intelligence Platform</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown(”””

<div class="ticker">
&gt; AI-POWERED ANOMALY DETECTION &nbsp;|&nbsp; REAL-TIME THREAT MONITORING &nbsp;|&nbsp; INCIDENT RESPONSE ACTIVE &nbsp;|&nbsp; v2.0
</div>
""", unsafe_allow_html=True)

# –––––––– SIDEBAR NAV ––––––––

with st.sidebar:
st.markdown(’<div style="font-family:monospace;font-size:10px;letter-spacing:3px;color:#334155;text-transform:uppercase;padding-bottom:12px;">NAVIGATION</div>’, unsafe_allow_html=True)

```
if st.session_state.logged_in:
    st.markdown(f"""
    <div class="sidebar-user-card">
        <div style="font-family:monospace;font-size:12px;color:#38bdf8;font-weight:700;">
            &#9679; {st.session_state.username}
        </div>
        <div style="font-family:monospace;font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:1px;">
            {st.session_state.role} &middot; Online
        </div>
    </div>
    """, unsafe_allow_html=True)
    nav_options = ["Dashboard", "Logs"]
else:
    nav_options = ["Login", "Register"]

if st.session_state.page not in nav_options:
    st.session_state.page = nav_options[0]

icons = {"Login": "[ Login ]", "Register": "[ Register ]", "Dashboard": "[ Dashboard ]", "Logs": "[ Logs ]"}

for option in nav_options:
    if st.button(icons.get(option, option), key=f"nav_{option}", use_container_width=True):
        st.session_state.page = option
        st.rerun()

if st.session_state.logged_in:
    st.markdown("---")
    if st.button("[ Logout ]", key="nav_logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.session_state.page = "Login"
        st.rerun()
```

# –––––––– LOGIN ––––––––

if st.session_state.page == “Login”:
if st.session_state.logged_in:
st.info(“You are already logged in as “ + st.session_state.username + “. Use the sidebar to navigate or logout.”)
st.stop()

```
st.markdown('<div class="login-card">', unsafe_allow_html=True)
st.markdown("### Welcome Back")
st.caption("SIGN IN TO YOUR ACCOUNT")
st.info("Demo credentials: analyst / soc123")

user = st.text_input("Username", placeholder="Enter username")
pwd = st.text_input("Password", type="password", placeholder="Enter password")

if st.session_state.login_attempts >= 5:
    st.error("Too many failed attempts. Please try later.")
    st.stop()

if st.button("Sign In", use_container_width=True):
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
        remaining = 5 - st.session_state.login_attempts
        st.error("Invalid credentials. " + str(remaining) + " attempts remaining.")

st.markdown('</div>', unsafe_allow_html=True)
```

# –––––––– REGISTER ––––––––

elif st.session_state.page == “Register”:
if st.session_state.logged_in:
st.info(“You are already logged in as “ + st.session_state.username + “.”)
st.stop()

```
st.markdown('<div class="login-card">', unsafe_allow_html=True)
st.markdown("### Create Account")
st.caption("REGISTER A NEW ANALYST ACCOUNT")

user = st.text_input("Username", placeholder="Choose a username")
pwd = st.text_input("Password", type="password", placeholder="Min 6 chars, 1 uppercase, 1 number")

if st.button("Create Account", use_container_width=True):
    if not strong_password(pwd):
        st.error("Password must have 6+ chars, 1 uppercase, 1 number")
    else:
        try:
            c.execute("INSERT INTO users VALUES (?,?,?)", (user, hash_password(pwd), "analyst"))
            conn.commit()
            st.success("Account created successfully. You can now login.")
        except Exception:
            st.error("Username already exists")

st.markdown('</div>', unsafe_allow_html=True)
```

# –––––––– DASHBOARD ––––––––

elif st.session_state.page == “Dashboard”:
if not st.session_state.logged_in:
st.warning(“Please login to access the dashboard.”)
st.stop()

```
st.markdown("### Security Dashboard")

file = st.file_uploader("Upload Authentication Logs (CSV or Excel)", type=["csv", "xlsx"])

if file:
    df = pd.read_csv(file) if file.name.endswith(".csv") else pd.read_excel(file)

    required = ["User ID", "Country", "Login Successful", "Round-Trip Time [ms]", "Is Attack IP"]
    if not all(col in df.columns for col in required):
        st.error("Dataset format invalid. Required: " + ", ".join(required))
        st.stop()

    df["Login Successful"] = df["Login Successful"].astype(int)
    df["Is Attack IP"] = df["Is Attack IP"].astype(int)

    features = df[["Round-Trip Time [ms]", "Login Successful", "Is Attack IP"]]
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

    df["Anomaly"] = df["Anomaly_raw"].apply(lambda x: "Suspicious" if x == -1 else "Normal")
    df["Reason"] = df.apply(explain, axis=1)
    df["Severity"] = df["Risk Score"].apply(lambda s: "High" if s > 0.6 else "Medium" if s > 0.3 else "Low")

    suspicious = df[df["Anomaly"] == "Suspicious"]

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Events", len(df))
    with col2:
        st.metric("Suspicious Logins", len(suspicious))
    with col3:
        st.metric("Attack IPs Detected", int(df["Is Attack IP"].sum()))

    st.markdown("---")
    st.subheader("Anomaly Detection Results")
    st.dataframe(df[["User ID", "Country", "Anomaly", "Risk Score", "Severity", "Reason"]], use_container_width=True)

    st.subheader("Suspicious Events")
    st.dataframe(suspicious, use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        fig1 = px.pie(df, names="Login Successful", title="Login Success Rate",
                      color_discrete_sequence=["#38bdf8", "#ef4444"])
        fig1.update_layout(paper_bgcolor="#060f20", plot_bgcolor="#060f20", font_color="#94a3b8")
        st.plotly_chart(fig1, use_container_width=True)
    with col2:
        fig2 = px.histogram(df, x="Round-Trip Time [ms]", title="Latency Distribution",
                            color_discrete_sequence=["#818cf8"])
        fig2.update_layout(paper_bgcolor="#060f20", plot_bgcolor="#060f20", font_color="#94a3b8")
        st.plotly_chart(fig2, use_container_width=True)

    df = df.reset_index(drop=True)
    df["Time"] = pd.date_range(start="2024-01-01", periods=len(df), freq="min")
    df["Suspicious"] = df["Anomaly"].apply(lambda x: 1 if x == "Suspicious" else 0)

    fig3 = px.line(df, x="Time", y="Suspicious", title="Suspicious Activity Over Time",
                   color_discrete_sequence=["#f59e0b"])
    fig3.update_layout(paper_bgcolor="#060f20", plot_bgcolor="#060f20", font_color="#94a3b8")
    st.plotly_chart(fig3, use_container_width=True)

    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download Full Report", csv, "report.csv", mime="text/csv")

else:
    st.info("Upload a CSV or Excel file to begin analysis. Required columns: User ID, Country, Login Successful, Round-Trip Time [ms], Is Attack IP")
```

# –––––––– LOGS ––––––––

elif st.session_state.page == “Logs”:
if not st.session_state.logged_in:
st.error(“Login required”)
st.stop()
if st.session_state.role != “admin”:
st.error(“Access Denied - Admin privileges required”)
st.stop()

```
st.markdown("### System Access Logs")
logs = pd.read_sql("SELECT * FROM logs", conn)
st.dataframe(logs, use_container_width=True)
```

# –––––––– FOOTER ––––––––

st.markdown(”””

<div class="footer">
DB CORP | ENTERPRISE CYBERSECURITY PLATFORM | THREAT MONITORING | INCIDENT RESPONSE | v2.0
</div>
""", unsafe_allow_html=True)
