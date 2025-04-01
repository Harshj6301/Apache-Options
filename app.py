import streamlit as st
import pandas as pd
import datetime
import os

# File path for saving trade logs
LOG_FILE = "trade_logs.csv"

# Function to load trade logs from CSV
def load_trade_logs():
    if os.path.exists(LOG_FILE):
        return pd.read_csv(LOG_FILE)
    return pd.DataFrame(columns=["Date", "Symbol", "Order", "Position", "Price", "Profit/Loss"])

# Function to save trade logs to CSV
def save_trade_logs(trade_logs):
    trade_logs.to_csv(LOG_FILE, index=False)

# Title of the app
st.title("Trade Checklist App")

# Load existing trade logs
if 'trade_logs' not in st.session_state:
    st.session_state.trade_logs = load_trade_logs()

# Trade input form
st.subheader("Enter Trade Details")

with st.form(key='trade_form'):
    date = st.date_input("Trade Date", datetime.date.today())
    symbol = st.text_input("Symbol (e.g., AAPL)").upper()
    order = st.selectbox("Order Type", options=["BUY", "SELL"])
    position = st.number_input("Position Size", min_value=1)
    price = st.number_input("Entry Price", format="%.2f")
    
    submit_button = st.form_submit_button("Log Trade")

    if submit_button:
        # Log the trade
        new_trade = {
            "Date": date,
            "Symbol": symbol,
            "Order": order,
            "Position": position,
            "Price": price,
            "Profit/Loss": 0  # Placeholder for profit/loss calculation
        }
        st.session_state.trade_logs = st.session_state.trade_logs.append(new_trade, ignore_index=True)
        save_trade_logs(st.session_state.trade_logs)  # Save to CSV
        st.success("Trade logged successfully!")

# Display the trade logs
st.subheader("Trade Logs")
st.dataframe(st.session_state.trade_logs)
