import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
import sqlite3
import bcrypt
import time

st.set_page_config(page_title="AI Cybersecurity System", layout="wide")

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
demo_users = {
    "admin": ("1234", "admin"),
    "analyst": ("soc123", "analyst")
}

for u, (p, r) in demo_users.items():
    try:
        c.execute("INSERT INTO users VALUES (?,?,?)", (u, hash_password(p), r))
        conn.commit()
    except:
        pass

# ---------------- SESSION ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.login_attempts = 0
    st.session_state.last_activity = time.time()

# ---------------- SESSION TIMEOUT ----------------
SESSION_TIMEOUT = 600  # 10 minutes

if st.session_state.logged_in:
    if time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
        st.session_state.logged_in = False
        st.warning("Session expired. Please login again.")
        st.stop()

st.session_state.last_activity = time.time()

# ---------------- UI ----------------
st.title("🚨 AI Cybersecurity Monitoring System")

menu = st.sidebar.selectbox("Menu", ["Login","Register","Dashboard","Logs"])

# ---------------- LOGIN ----------------
if menu == "Login":

    st.info("Demo → admin / 1234 | analyst / soc123")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.session_state.login_attempts >= 5:
        st.error("Too many failed attempts. Wait 30 seconds.")
        time.sleep(3)
        st.stop()

    if st.button("Login"):

        if not user or not pwd:
            st.error("All fields required")
            st.stop()

        c.execute("SELECT * FROM users WHERE username=?", (user,))
        result = c.fetchone()

        if result and verify_password(pwd, result[1]):
            st.session_state.logged_in = True
            st.session_state.username = user
            st.session_state.role = result[2]
            st.session_state.login_attempts = 0

            log_event(user, "SUCCESS")

            st.success(f"Welcome {user}")

        else:
            st.session_state.login_attempts += 1
            log_event(user, "FAILED")
            st.error("Invalid credentials")

# ---------------- REGISTER ----------------
elif menu == "Register":

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["analyst","admin"])

    if st.button("Register"):

        if not user or not pwd:
            st.error("All fields required")
            st.stop()

        try:
            c.execute("INSERT INTO users VALUES (?,?,?)",
                      (user, hash_password(pwd), role))
            conn.commit()
            st.success("Account created")
        except:
            st.error("Username already exists")

# ---------------- DASHBOARD ----------------
elif menu == "Dashboard":

    if not st.session_state.logged_in:
        st.warning("Login required")
        st.stop()

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.success("Logged out")
        st.stop()

    st.subheader(f"User: {st.session_state.username} ({st.session_state.role})")

    file = st.file_uploader("Upload dataset", type=["csv","xlsx"])

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

        df["Anomaly"] = df["Anomaly_raw"].apply(lambda x: "Suspicious" if x==-1 else "Normal")

        # -------- Explanation --------
        def explain(row):
            reasons = []
            if row["Round-Trip Time [ms]"] > 500:
                reasons.append("High latency")
            if row["Login Successful"] == 0:
                reasons.append("Failed login")
            if row["Is Attack IP"] == 1:
                reasons.append("Attack IP")
            return ", ".join(reasons) if reasons else "Normal"

        df["Explanation"] = df.apply(explain, axis=1)

        suspicious = df[df["Anomaly"]=="Suspicious"]

        if len(suspicious)>0:
            st.error(f"🚨 {len(suspicious)} suspicious logins detected")
        else:
            st.success("System normal")

        # -------- User Behavior --------
        st.subheader("User Behavior Profiling")

        profile = df.groupby("User ID").agg({
            "Round-Trip Time [ms]":"mean",
            "Login Successful":"sum",
            "Is Attack IP":"sum"
        }).reset_index()

        st.dataframe(profile)

        # -------- Results --------
        st.subheader("Detection Results")
        st.dataframe(df[["User ID","Country","Anomaly","Risk Score","Explanation"]])

        st.subheader("Suspicious Events")
        st.dataframe(suspicious)

# ---------------- LOGS ----------------
elif menu == "Logs":

    if st.session_state.role != "admin":
        st.error("Admin only")
        st.stop()

    logs = pd.read_sql("SELECT * FROM logs", conn)
    st.dataframe(logs)
