import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="DB Corp Cybersecurity Dashboard", layout="wide")

# ---------------- UI Styling ----------------
st.markdown("""
<style>
body {background-color:#020617;}
.banner {background:linear-gradient(90deg,#06b6d4,#3b82f6,#9333ea);padding:10px;color:white;
font-weight:bold;text-align:center;font-size:18px;border-radius:8px;margin-bottom:10px}
.footer {position:fixed;bottom:0;left:0;width:100%;background:#020617;color:white;padding:10px;
border-top:1px solid #1e293b;text-align:center;font-size:14px}
</style>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="banner"><marquee>Real-Time Cyber Threat Monitoring | Suspicious Login Detection | Security Intelligence Platform</marquee></div>',
    unsafe_allow_html=True
)

# ---------------- Header ----------------
col1, col2 = st.columns([1,6])

with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)

with col2:
    st.title("DB Corp. Ltd. Cybersecurity Operations Dashboard")

# ---------------- Sidebar ----------------
with st.sidebar:
    st.header("Menu")
    page = st.radio("Navigation", ["Dashboard", "Login", "Signup"])

users = {"admin":"1234","analyst":"soc123"}

# ---------------- Login ----------------
if page == "Login":
    st.subheader("Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        if u in users and users[u] == p:
            st.success("Login successful")
        else:
            st.error("Invalid credentials")

# ---------------- Signup ----------------
if page == "Signup":
    st.subheader("Create Account")
    st.text_input("New Username")
    st.text_input("New Password", type="password")
    st.button("Register")

# ---------------- Dataset Info ----------------
with st.expander("Dataset Requirements (Click to Expand)"):
    st.markdown("""
### Required Columns
- User ID
- Country
- ASN
- Login Successful
- Round-Trip Time [ms]
- Is Attack IP

### Optional
- Timestamp

### Cleaning Guidelines
- Remove rows with missing values
- Ensure boolean fields are True or False
- RTT must be numeric
- Country names should be consistent

### Accepted Formats
- CSV (.csv)
- Excel (.xlsx)
""")

# ---------------- Upload ----------------
st.header("Upload Login Dataset")

file = st.file_uploader("Upload CSV or Excel dataset", type=["csv","xlsx"])

if file is not None:
    if file.name.endswith(".csv"):
        df = pd.read_csv(file)
    else:
        df = pd.read_excel(file)

    st.subheader("Dataset Preview")
    st.dataframe(df.head())

    attack = df[df["Is Attack IP"] == True]
    failed = df[df["Login Successful"] == False]
    high_rtt = df[df["Round-Trip Time [ms]"] > 500]

    col1, col2 = st.columns(2)

    with col1:
        pie = df["Login Successful"].value_counts().reset_index()
        pie.columns = ["Status","Count"]
        fig = px.pie(pie, values="Count", names="Status")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        fig2 = px.histogram(df, x="Round-Trip Time [ms]")
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Country Login Activity")

    country = df["Country"].value_counts().reset_index()
    country.columns = ["Country","Count"]

    fig3 = px.bar(country, x="Country", y="Count")
    st.plotly_chart(fig3, use_container_width=True)

    c1, c2, c3 = st.columns(3)
    c1.metric("Attack IP Events", len(attack))
    c2.metric("Failed Logins", len(failed))
    c3.metric("High RTT Events", len(high_rtt))

# ---------------- Footer ----------------
footer = """
<div class="footer">
<b>Enterprise Cybersecurity Protection</b> | Threat monitoring - Security analytics - Incident response |
Phone: +1-800-555-0148 | Email: enterprise-security@protectionlabs.io
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
