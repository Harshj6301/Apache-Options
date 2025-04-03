import streamlit as st
import pandas as pd
from datetime import datetime, date, time, timedelta
import logging
import requests # For instrument list
from SmartApi import SmartConnect

st.set_page_config(layout="wide", page_title="Angel One SmartAPI Tool")

# --- SmartAPI Import ---
'''
try:
    from SmartApi import SmartConnect
    # from smartapi.smartExceptions import SmartApiException # Optional for specific exception handling
    smartapi_available = True
except ImportError:
    st.error("SmartApi library not found. Please install it: pip install smartapi-python")
    smartapi_available = False
    SmartConnect = None '''

# --- Basic Logging ---
logging.basicConfig(level=logging.INFO)

# --- Instrument List Handling (Adapted from previous handler) ---
INSTRUMENT_LIST_CACHE = None
INSTRUMENT_LIST_TIMESTAMP = None
INSTRUMENT_CACHE_TTL = timedelta(hours=6)

def fetch_instrument_list():
    """Downloads and caches the instrument list."""
    global INSTRUMENT_LIST_CACHE, INSTRUMENT_LIST_TIMESTAMP
    # ... (same implementation as in smartapi_handler.py before) ...
    # ... returns the list of instruments or None ...
    # (Copy the full function here)
    now = datetime.now()
    # Check cache validity
    if INSTRUMENT_LIST_CACHE is not None and INSTRUMENT_LIST_TIMESTAMP is not None:
        if now < INSTRUMENT_LIST_TIMESTAMP + INSTRUMENT_CACHE_TTL:
            logging.info("Using cached instrument list.")
            return INSTRUMENT_LIST_CACHE

    logging.info("Fetching fresh instrument list...")
    st.info("Fetching latest instrument list from Angel One...") # Show status in UI
    try:
        # URL provided by Angel One for instruments (verify this URL is current)
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=15) # Added timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        instruments = response.json()
        if isinstance(instruments, list):
            INSTRUMENT_LIST_CACHE = instruments
            INSTRUMENT_LIST_TIMESTAMP = now
            logging.info(f"Successfully fetched and cached {len(instruments)} instruments.")
            st.info(f"Fetched {len(instruments)} instruments.")
            return instruments
        else:
            logging.error(f"Fetched instrument data is not a list: {type(instruments)}")
            st.error("Failed to process instrument list: Invalid format.")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching instrument list: {e}")
        st.error(f"Error fetching instrument list: {e}")
        return None
    except Exception as e:
        logging.error(f"Error processing instrument list: {e}")
        st.error(f"Error processing instrument list: {e}")
        return None

def get_instrument_token(symbol: str, exchange: str) -> str | None:
    """Finds the instrument token for a given symbol and exchange."""
    # ... (same implementation as in smartapi_handler.py before) ...
    # ... returns the token string or None ...
    # (Copy the full function here, making sure it logs warnings/errors)
    instruments = fetch_instrument_list()
    if instruments is None:
        st.error("Instrument list is not available for token lookup.")
        return None
    try:
        symbol_upper = symbol.upper()
        exchange_upper = exchange.upper()
        for instrument in instruments:
            inst_symbol = instrument.get('symbol', '').upper()
            inst_exch = instrument.get('exch_seg', '').upper()
            inst_token = instrument.get('token')
            inst_name = instrument.get('name', '').upper()
            # Basic equity match
            if inst_symbol == symbol_upper and inst_exch == exchange_upper and inst_name == symbol_upper:
                 if inst_exch == 'NSE' and instrument.get('lotsize') == '1':
                     logging.info(f"Found token {inst_token} for {symbol} on {exchange}")
                     return inst_token
            # Add more specific logic for derivatives if needed (check expiry, strike, type)
        logging.warning(f"Token not found for {symbol} on {exchange}")
        st.warning(f"Token not found for {symbol} on {exchange}. Check symbol or exchange.")
        return None
    except Exception as e:
        logging.error(f"Error searching for instrument token: {e}")
        st.error(f"Error during token lookup: {e}")
        return None

# --- Streamlit App ---

st.title("🚀 Angel One SmartAPI Interface")

# --- Initialize Session State ---
if 'smartapi_obj' not in st.session_state:
    st.session_state.smartapi_obj = None
if 'login_status' not in st.session_state:
    st.session_state.login_status = "Logged Out"
if 'user_profile' not in st.session_state:
    st.session_state.user_profile = None
if 'feed_token' not in st.session_state:
    st.session_state.feed_token = None
if 'refresh_token' not in st.session_state:
     st.session_state.refresh_token = None


# --- Sidebar for Login ---
st.sidebar.header("🔑 SmartAPI Login")

# Load credentials from secrets if available
try:
    api_key_s = st.secrets["smartapi"]["api_key"]
    client_id_s = st.secrets["smartapi"]["client_id"]
    password_s = st.secrets["smartapi"]["password"]
    creds_loaded = True
except:
    api_key_s = ""
    client_id_s = ""
    password_s = ""
    creds_loaded = False
    st.sidebar.info("Enter credentials manually or set up `secrets.toml`.")

# Inputs for credentials
api_key = st.sidebar.text_input("API Key", value=api_key_s, type="password" if creds_loaded else "default")
client_id = st.sidebar.text_input("Client ID", value=client_id_s)
password = st.sidebar.text_input("Password", value=password_s, type="password")
totp = st.sidebar.text_input("TOTP Code", type="password") # TOTP is always manual

login_button = st.sidebar.button("Login", disabled=(st.session_state.login_status == "Logged In"))

if login_button:
    if not smartapi_available:
        st.sidebar.error("SmartAPI library not loaded.")
    elif not all([api_key, client_id, password, totp]):
        st.sidebar.warning("Please fill in all credentials.")
    else:
        with st.spinner("Logging in..."):
            try:
                obj = SmartConnect(api_key=api_key)
                data = obj.generateSession(client_id, password, totp)

                if data and data.get('status') and data['status'] is True and data.get('data'):
                    st.session_state.smartapi_obj = obj
                    st.session_state.refresh_token = data['data']['refreshToken']
                    st.session_state.feed_token = obj.getfeedToken() # Fetch feed token
                    st.session_state.user_profile = obj.getProfile(st.session_state.refresh_token)
                    st.session_state.login_status = "Logged In"
                    st.sidebar.success(f"Login Successful!")
                    if st.session_state.user_profile and st.session_state.user_profile.get('data'):
                         st.sidebar.write(f"Welcome, {st.session_state.user_profile['data'].get('name', client_id)}")
                    else:
                         st.sidebar.write(f"Welcome, {client_id}")
                    st.sidebar.caption(f"Feed Token: {st.session_state.feed_token[:10]}...") # Show partial feed token
                    st.rerun() # Rerun to update UI elements based on login status
                else:
                    st.session_state.login_status = "Login Failed"
                    st.session_state.smartapi_obj = None
                    error_msg = data.get('message', 'Unknown login error') if data else 'Login failed'
                    st.sidebar.error(f"Login Failed: {error_msg}")

            except Exception as e:
                st.session_state.login_status = "Login Error"
                st.session_state.smartapi_obj = None
                st.sidebar.error(f"Login Error: {e}")

# Display Login Status
st.sidebar.metric("Login Status", st.session_state.login_status)
if st.session_state.user_profile and st.session_state.user_profile.get('data'):
     st.sidebar.caption(f"User: {st.session_state.user_profile['data'].get('name', 'N/A')}")
     st.sidebar.caption(f"Email: {st.session_state.user_profile['data'].get('email', 'N/A')}")
     st.sidebar.caption(f"Broker: {st.session_state.user_profile['data'].get('broker', 'N/A')}")


# --- Main Area with Tabs ---
if st.session_state.login_status == "Logged In" and st.session_state.smartapi_obj:
    obj = st.session_state.smartapi_obj # Use the stored object

    tab1, tab2 = st.tabs(["📊 Historical Data", "📈 Market Analysis"])

    # --- Tab 1: Historical Data ---
    with tab1:
        st.subheader("Fetch Historical Candlestick Data")
        col1, col2, col3 = st.columns(3)
        with col1:
            hist_symbol = st.text_input("Symbol (e.g., RELIANCE)", "RELIANCE").upper()
            hist_exchange = st.selectbox("Exchange", ["NSE", "NFO", "BSE", "MCX"], key="hist_ex") # Adjust as needed
        with col2:
            hist_interval = st.selectbox("Interval", ["ONE_MINUTE", "THREE_MINUTE", "FIVE_MINUTE", "TEN_MINUTE", "FIFTEEN_MINUTE", "THIRTY_MINUTE", "ONE_HOUR", "ONE_DAY"], index=7)
            # Date/Time Inputs
            today = date.today()
            default_from_date = today - timedelta(days=30)
            default_to_date = today

            hist_from_dt = st.date_input("From Date", value=default_from_date)
            hist_from_time = st.time_input("From Time", value=time(9, 15))

            hist_to_dt = st.date_input("To Date", value=default_to_date)
            hist_to_time = st.time_input("To Time", value=time(15, 30))

        # Combine date and time
        hist_fromdate_str = f"{hist_from_dt.strftime('%Y-%m-%d')} {hist_from_time.strftime('%H:%M')}"
        hist_todate_str = f"{hist_to_dt.strftime('%Y-%m-%d')} {hist_to_time.strftime('%H:%M')}"
        st.caption(f"Fetching from: {hist_fromdate_str} to {hist_todate_str}")


        if st.button("Fetch Historical Data"):
            if not hist_symbol:
                st.warning("Please enter a symbol.")
            else:
                with st.spinner(f"Fetching data for {hist_symbol}..."):
                    # Get token first
                    token = get_instrument_token(hist_symbol, hist_exchange)
                    if token:
                        st.write(f"Found Token: {token}")
                        try:
                            param = {
                                "exchange": hist_exchange,
                                "symboltoken": token,
                                "interval": hist_interval,
                                "fromdate": hist_fromdate_str,
                                "todate": hist_todate_str
                            }
                            hist_data = obj.getCandleData(param)

                            if hist_data and hist_data.get('status') and isinstance(hist_data.get('data'), list):
                                df_hist = pd.DataFrame(hist_data['data'])
                                if not df_hist.empty:
                                    df_hist.columns = ['Timestamp', 'Open', 'High', 'Low', 'Close', 'Volume']
                                    df_hist['Timestamp'] = pd.to_datetime(df_hist['Timestamp'])
                                    df_hist.set_index('Timestamp', inplace=True)
                                    st.success(f"Fetched {len(df_hist)} records.")
                                    st.dataframe(df_hist, use_container_width=True)

                                    # Simple Chart
                                    st.line_chart(df_hist['Close'])

                                    # --- Alert Placeholder ---
                                    if st.button("Send Data Summary to Telegram (Placeholder)"):
                                         # In a real app, this would format data and call a Telegram function
                                         st.info("Telegram alert functionality not implemented yet.")
                                         print(f"--- Telegram Alert Triggered (Manual) ---\nSymbol: {hist_symbol}\nInterval: {hist_interval}\nRecords: {len(df_hist)}\nLatest Close: {df_hist['Close'].iloc[-1] if not df_hist.empty else 'N/A'}\n---")

                                else:
                                     st.info("No data found for the specified parameters.")

                            else:
                                st.error(f"Error fetching data: {hist_data.get('message', 'API error or no data')}")

                        except Exception as e:
                            st.error(f"An error occurred: {e}")
                            logging.exception("Error during historical data fetch")
                    else:
                         # Error displayed by get_instrument_token
                         pass

    # --- Tab 2: Market Analysis ---
    with tab2:
        st.subheader("Market Pulse & Analysis")

        # --- PCR Section ---
        st.markdown("---")
        st.markdown("##### Put-Call Ratio (PCR)")
        if st.button("Get PCR"):
             with st.spinner("Fetching PCR..."):
                 try:
                     # Note: Assuming pcr() takes no arguments as per user snippet
                     # Verify actual SmartAPI signature if it requires exchange etc.
                     pcr_data = obj.putCallRatio()
                     st.json(pcr_data) # Display raw JSON response

                     # --- Alert Placeholder ---
                     if st.button("Send PCR to Telegram (Placeholder)"):
                         st.info("Telegram alert functionality not implemented yet.")
                         print(f"--- Telegram Alert Triggered (Manual) ---\nType: PCR\nData: {pcr_data}\n---")

                 except Exception as e:
                     st.error(f"An error occurred fetching PCR: {e}")
                     logging.exception("Error during PCR fetch")


        # --- Top Gainers/Losers Section ---
        st.markdown("---")
        st.markdown("##### Top Gainers & Losers (Futures/Options)")
        col_gl1, col_gl2 = st.columns(2)
        with col_gl1:
            gl_data_type = st.selectbox(
                "Data Type (G/L)",
                ["PercOILosers", "PercOIGainers", "PercPriceGainers", "PercPriceLosers"],
                key="gl_dtype"
            )
        with col_gl2:
            gl_expiry_type = st.selectbox(
                "Expiry Type (G/L)",
                ["NEAR", "NEXT", "FAR"],
                key="gl_exp"
            )
        if st.button("Get Top Gainers/Losers"):
            with st.spinner(f"Fetching {gl_data_type} for {gl_expiry_type} expiry..."):
                 try:
                    param = {
                         "datatype": gl_data_type,
                         "expirytype": gl_expiry_type
                    }
                    gl_data = obj.gainersLosers(param)

                    if gl_data and gl_data.get('status') and isinstance(gl_data.get('data'), list):
                         df_gl = pd.DataFrame(gl_data['data'])
                         st.success(f"Fetched {len(df_gl)} records.")
                         st.dataframe(df_gl, use_container_width=True)

                         # --- Alert Placeholder ---
                         if st.button("Send G/L Summary to Telegram (Placeholder)"):
                              st.info("Telegram alert functionality not implemented yet.")
                              print(f"--- Telegram Alert Triggered (Manual) ---\nType: Top G/L\nParams: {param}\nTop Result: {df_gl.iloc[0].to_dict() if not df_gl.empty else 'N/A'}\n---")

                    else:
                        st.error(f"Error fetching G/L data: {gl_data.get('message', 'API error or no data')}")

                 except Exception as e:
                     st.error(f"An error occurred fetching G/L data: {e}")
                     logging.exception("Error during G/L fetch")


        # --- OI Buildup Section ---
        st.markdown("---")
        st.markdown("##### Open Interest (OI) Buildup (Futures/Options)")
        col_oi1, col_oi2 = st.columns(2)
        with col_oi1:
             oi_expiry_type = st.selectbox(
                "Expiry Type (OI)",
                ["NEAR", "NEXT", "FAR"],
                key="oi_exp"
            )
        with col_oi2:
             oi_data_type = st.selectbox(
                "Data Type (OI)",
                ["Long Built Up", "Short Built Up", "Short Covering", "Long Unwinding"],
                key="oi_dtype"
            )
        if st.button("Get OI Buildup Data"):
             with st.spinner(f"Fetching {oi_data_type} for {oi_expiry_type} expiry..."):
                  try:
                    param = {
                         "expirytype": oi_expiry_type,
                         "datatype": oi_data_type
                    }
                    oi_data = obj.oIBuildup(param)

                    if oi_data and oi_data.get('status') and isinstance(oi_data.get('data'), list):
                         df_oi = pd.DataFrame(oi_data['data'])
                         st.success(f"Fetched {len(df_oi)} records.")
                         st.dataframe(df_oi, use_container_width=True)

                         # --- Alert Placeholder ---
                         if st.button("Send OI Summary to Telegram (Placeholder)"):
                              st.info("Telegram alert functionality not implemented yet.")
                              print(f"--- Telegram Alert Triggered (Manual) ---\nType: OI Buildup\nParams: {param}\nTop Result: {df_oi.iloc[0].to_dict() if not df_oi.empty else 'N/A'}\n---")

                    else:
                        st.error(f"Error fetching OI data: {oi_data.get('message', 'API error or no data')}")

                  except Exception as e:
                     st.error(f"An error occurred fetching OI data: {e}")
                     logging.exception("Error during OI fetch")


    # --- Add more tabs or sections as needed ---


else:
    st.info("ℹ️ Please log in using the sidebar to access API functionalities.")

# Disclaimer Footer
st.markdown("---")
st.warning("""
**Disclaimer:** This tool is for interacting with the SmartAPI based on the provided functions.
Trading involves substantial risk. Data accuracy depends on the API provider.
Always verify information and do your own research (DYOR). Ensure secure handling of credentials.
Alert functionality is currently a placeholder.
""")

# --- Placeholder for Alerting Function (to be implemented later) ---
def send_telegram_alert(message: str):
     # This function would use python-telegram-bot to send 'message'
     # Requires BOT_TOKEN and CHAT_ID to be configured (e.g., via secrets or env vars)
     logging.info(f"TELEGRAM ALERT (Not Sent): {message}")
     print(f"--- TELEGRAM ALERT --- \n{message}\n --- END ALERT ---")
     # pass # Replace with actual implementation

# Example of how to call it (replace print statements in the buttons above):
# summary = f"Historical Data:\nSymbol: {hist_symbol}\nRecords: {len(df_hist)}"
# send_telegram_alert(summary)
