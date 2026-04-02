import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="DB Corp Cybersecurity Dashboard", layout="wide")

# ---------------- UI Styling ----------------
st.markdown("""
<style>
body {background-color:#020617;}

.banner {
background:linear-gradient(90deg,#06b6d4,#3b82f6,#9333ea);
padding:10px;color:white;font-weight:bold;text-align:center;
font-size:18px;border-radius:8px;margin-bottom:10px}

.footer {
position:fixed;bottom:0;left:0;width:100%;
background:#020617;color:white;padding:10px;
border-top:1px solid #1e293b;text-align:center;font-size:14px}

.dataset-box {
background:#111827;
border-left:5px solid #22c55e;
padding:15px;
border-radius:10px;
margin-top:10px;
margin-bottom:15px;
box-shadow:0px 0px 10px rgba(34,197,94,0.5);
}

.dataset-title {
color:#22c55e;
font-size:18px;
font-weight:bold;
margin-bottom:8px;
}
</style>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="banner"><marquee>AI-Powered Cyber Threat Monitoring | Login Anomaly Detection</marquee></div>',
    unsafe_allow_html=True
)

# ---------------- Header ----------------
col1, col2 = st.columns([1,6])

with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)

with col2:
    st.title("DB Corp. Ltd. AI Cybersecurity Dashboard")

# ---------------- Sidebar ----------------
with st.sidebar:
    st.header("Menu")
    page = st.radio("Navigation", ["Dashboard", "Login"])

# ---------------- Login ----------------
users = {"admin":"1234","analyst":"soc123"}

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if page == "Login":
    st.subheader("Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        if u in users and users[u] == p:
            st.session_state.logged_in = True
            st.success("Login successful")
        else:
            st.error("Invalid credentials")

if not st.session_state.logged_in:
    st.warning("Please login to access dashboard")
    st.stop()

# ---------------- Upload ----------------
st.header("📂 Upload Login Dataset")

file = st.file_uploader("Upload CSV or Excel dataset", type=["csv","xlsx"])

# ---------------- Dataset Info ----------------
st.markdown("""
<div class="dataset-box">
<div class="dataset-title">⚠️ Dataset Requirements</div>

• <b>User ID</b><br>
• <b>Country</b><br>
• <b>Login Successful</b> (True/False)<br>
• <b>Round-Trip Time [ms]</b><br>
• <b>Is Attack IP</b> (True/False)<br><br>

<b>Tip:</b> Clean dataset = better AI detection accuracy
</div>
""", unsafe_allow_html=True)

# ---------------- Data Processing ----------------
if file is not None:

    try:
        if file.name.endswith(".csv"):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)
    except:
        st.error("Error reading file")
        st.stop()

    required_cols = [
        "User ID", "Country",
        "Login Successful", "Round-Trip Time [ms]", "Is Attack IP"
    ]

    if not all(col in df.columns for col in required_cols):
        st.error("Dataset missing required columns")
        st.stop()

    st.subheader("Dataset Preview")
    st.dataframe(df.head())

    # ---------------- AI MODEL ----------------
    df["Login Successful"] = df["Login Successful"].astype(int)
    df["Is Attack IP"] = df["Is Attack IP"].astype(int)

    features = df[[
        "Round-Trip Time [ms]",
        "Login Successful",
        "Is Attack IP"
    ]]

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)

    # Predictions
    df["Anomaly_Label"] = model.predict(features)
    df["Anomaly"] = df["Anomaly_Label"].apply(lambda x: "Suspicious" if x == -1 else "Normal")

    # --------- Anomaly Score (NEW) ----------
    df["Anomaly Score"] = model.decision_function(features)
    df["Risk Score"] = (-df["Anomaly Score"]).round(3)

    # ---------------- Alerts (NEW) ----------------
    suspicious = df[df["Anomaly"] == "Suspicious"]

    if len(suspicious) > 0:
        st.error(f"🚨 ALERT: {len(suspicious)} suspicious login(s) detected!")
    else:
        st.success("✅ No suspicious activity detected")

    # ---------------- Metrics ----------------
    attack = df[df["Is Attack IP"] == 1]
    failed = df[df["Login Successful"] == 0]

    c1, c2, c3 = st.columns(3)
    c1.metric("Attack IP Events", len(attack))
    c2.metric("Failed Logins", len(failed))
    c3.metric("AI Suspicious Logins", len(suspicious))

    # ---------------- Charts ----------------
    col1, col2 = st.columns(2)

    with col1:
        pie = df["Login Successful"].value_counts().reset_index()
        pie.columns = ["Status","Count"]
        fig = px.pie(pie, values="Count", names="Status")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        fig2 = px.histogram(df, x="Round-Trip Time [ms]")
        st.plotly_chart(fig2, use_container_width=True)

    # ---------------- Highlight Table (NEW) ----------------
    def highlight_rows(row):
        if row["Anomaly"] == "Suspicious":
            return ["background-color: red"] * len(row)
        return [""] * len(row)

    st.subheader("🤖 AI Detection Results")
    st.dataframe(
        df[["User ID", "Country", "Anomaly", "Risk Score"]]
        .style.apply(highlight_rows, axis=1)
    )

    # ---------------- Suspicious Section ----------------
    st.subheader("🚨 Suspicious Logins")
    st.dataframe(suspicious)

# ---------------- Footer ----------------
footer = """
<div class="footer">
AI Security Monitoring System | Demo Project | DB
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
