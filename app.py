import streamlit as st
import pandas as pd
import datetime

# Title of the app
st.title("Trade Checklist App")

# Introduction
st.write("Welcome to the Trade Checklist App! Please follow the checklist before entering a trade.")

# Initialize a DataFrame to store trade logs
if 'trade_logs' not in st.session_state:
    st.session_state.trade_logs = pd.DataFrame(columns=["Date", "Symbol", "Order", "Position", "Price", "Profit/Loss"])

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
        st.success("Trade logged successfully!")

# Display the trade logs
st.subheader("Trade Logs")
st.dataframe(st.session_state.trade_logs)
