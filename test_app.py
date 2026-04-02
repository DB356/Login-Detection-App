import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
import sqlite3
import bcrypt
import time
import re

st.set_page_config(page_title="DB Corp Security System", layout="wide", page_icon=":shield:")

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

# -------- HEADER --------
st.title("DB Corp Cybersecurity Dashboard")

# -------- SIDEBAR --------
with st.sidebar:
    if st.session_state.logged_in:
        st.write(f"User: {st.session_state.username}")
        nav_options = ["Dashboard", "Logs"]
    else:
        nav_options = ["Login", "Register"]

    if st.session_state.page not in nav_options:
        st.session_state.page = nav_options[0]

    for option in nav_options:
        if st.button(option):
            st.session_state.page = option
            st.rerun()

    if st.session_state.logged_in:
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.page = "Login"
            st.rerun()

# -------- LOGIN --------
if st.session_state.page == "Login":
    st.info("Demo: analyst / soc123")

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
elif st.session_state.page == "Register":
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Register"):
        if not strong_password(pwd):
            st.error("Weak password")
        else:
            try:
                c.execute("INSERT INTO users VALUES (?,?,?)", (user, hash_password(pwd), "analyst"))
                conn.commit()
                st.success("Account created")
            except:
                st.error("Username exists")

# -------- DASHBOARD --------
elif st.session_state.page == "Dashboard":

    if not st.session_state.logged_in:
        st.warning("Login first")
        st.stop()

    file = st.file_uploader("Upload Auth Logs", type=["csv", "xlsx"])

    if file:
        df = pd.read_csv(file) if file.name.endswith(".csv") else pd.read_excel(file)

        required = ["User ID", "Country", "Login Successful", "Round-Trip Time [ms]", "Is Attack IP"]
        if not all(col in df.columns for col in required):
            st.error("Invalid dataset")
            st.stop()

        df["Login Successful"] = df["Login Successful"].astype(int)
        df["Is Attack IP"] = df["Is Attack IP"].astype(int)

        features = df[["Round-Trip Time [ms]", "Login Successful", "Is Attack IP"]]

        model = IsolationForest(contamination=0.1)
        model.fit(features)

        df["Anomaly"] = model.predict(features)
        df["Anomaly"] = df["Anomaly"].apply(lambda x: "Suspicious" if x == -1 else "Normal")

        st.subheader("Results")
        st.dataframe(df)

        st.plotly_chart(px.pie(df, names="Login Successful"))
        st.plotly_chart(px.histogram(df, x="Round-Trip Time [ms]"))

# -------- LOGS --------
elif st.session_state.page == "Logs":

    if not st.session_state.logged_in:
        st.error("Login required")
        st.stop()

    if st.session_state.role != "admin":
        st.error("Admin only")
        st.stop()

    logs = pd.read_sql("SELECT * FROM logs", conn)
    st.dataframe(logs)
