import streamlit as st
import pandas as pd
import joblib

# # =========================
# # APP STATUS
# # =========================
# st.write("APP RUNNING CORRECTLY")

# =========================
# LOAD MODEL + FILES
# =========================
model = joblib.load("lgbm_model.pkl")
cols = joblib.load("columns.pkl")

# label mapping
label_map = {
    0: 'TCP_ATTACK',
    1: 'BENIGN',
    2: 'UDP_Attack'
 }

# =========================
# PAGE TITLE
# =========================
st.title("Live DDoS Attack Detection System")
st.markdown("### AI-based DDoS Attack Detection using Machine Learning")

 # Sidebar
st.sidebar.title("🛡️ DDoS Detection System")

st.sidebar.markdown("---")

st.sidebar.info(
    """
    This project uses Machine Learning to detect network attacks.

    ### Attack Types
    - ✅ BENIGN
    - ⚠️ TCP_ATTACK
    - 🚨 UDP_ATTACK

    ### Model Used
    - LightGBM Classifier

    ### Dataset
    - CICDDoS2019
    """
)

st.write("Enter network traffic details")

# =========================
# USER INPUTS
# =========================
flow_duration = st.number_input("Flow Duration")

fwd_packets = st.number_input("Total Fwd Packets")

bwd_packets = st.number_input("Total Backward Packets")

flow_bytes = st.number_input("Flow Bytes/s")

flow_packets = st.number_input("Flow Packets/s")

protocol = st.number_input("Protocol")

syn_flag = st.number_input("SYN Flag Count")

ack_flag = st.number_input("ACK Flag Count")

rst_flag = st.number_input("RST Flag Count")

psh_flag = st.number_input("PSH Flag Count")

urg_flag = st.number_input("URG Flag Count")

fwd_len = st.number_input("Fwd Packet Length Max")

total_fwd_len = st.number_input("Total Length of Fwd Packets")

# =========================
# PREDICT BUTTON
# =========================
if st.button("Predict Attack"):

    # create dataframe
    new_data = pd.DataFrame([{
        "Flow Duration": flow_duration,
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Flow Bytes/s": flow_bytes,
        "Flow Packets/s": flow_packets,
        "Protocol": protocol,
        "SYN Flag Count": syn_flag,
        "ACK Flag Count": ack_flag,
        "RST Flag Count": rst_flag,
        "PSH Flag Count": psh_flag,
        "URG Flag Count": urg_flag,
        "Fwd Packet Length Max": fwd_len,
        "Total Length of Fwd Packets": total_fwd_len
    }])

    # match training columns
    new_data = new_data.reindex(columns=cols, fill_value=0)

     

    # prediction
    pred = model.predict(new_data)

     
    # decode prediction
    result = label_map[int(pred[0])]

    # show result
    st.success(f"Prediction: {result}")