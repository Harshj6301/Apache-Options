# Previous imports remain the same...
import streamlit as st
import pandas as pd
from datetime import datetime, date, time, timedelta
import logging
import requests
from SmartApi import SmartConnect
import asyncio # Needed for async telegram call

# --- Telegram Import ---
# ... (telegram import check remains the same) ...
#try:
#    import telegram
#    telegram_available = True
#except ImportError:
#    st.warning("`python-telegram-bot` library not found. Telegram alerts disabled. Install with `pip install python-telegram-bot`")
#    telegram_available = False

smartapi_available = True

# --- Basic Logging ---
logging.basicConfig(level=logging.INFO)

# --- Instrument List Handling ---
# ... (fetch_instrument_list and get_instrument_token functions remain exactly the same) ...
# [Function code omitted for brevity - ensure they are present]
INSTRUMENT_LIST_CACHE = None
INSTRUMENT_LIST_TIMESTAMP = None
INSTRUMENT_CACHE_TTL = timedelta(hours=6)

def fetch_instrument_list():
    """Downloads and caches the instrument list."""
    global INSTRUMENT_LIST_CACHE, INSTRUMENT_LIST_TIMESTAMP
    now = datetime.now()
    if INSTRUMENT_LIST_CACHE is not None and INSTRUMENT_LIST_TIMESTAMP is not None:
        if now < INSTRUMENT_LIST_TIMESTAMP + INSTRUMENT_CACHE_TTL:
            logging.info("Using cached instrument list.")
            return INSTRUMENT_LIST_CACHE
    logging.info("Fetching fresh instrument list...")
    try:
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        instruments = response.json()
        if isinstance(instruments, list):
            INSTRUMENT_LIST_CACHE = instruments
            INSTRUMENT_LIST_TIMESTAMP = now
            logging.info(f"Successfully fetched and cached {len(instruments)} instruments.")
            return instruments
        else:
            logging.error(f"Fetched instrument data is not a list: {type(instruments)}")
            return None # Return None on format error
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching instrument list: {e}")
        return None # Return None on request error
    except Exception as e:
        logging.error(f"Error processing instrument list: {e}")
        return None # Return None on other errors

def get_instrument_token(symbol: str, exchange: str) -> str | None:
    """Finds the instrument token for a given symbol and exchange."""
    instruments = fetch_instrument_list()
    if instruments is None:
        # Error is logged in fetch_instrument_list, maybe add st.warning here if needed
        # st.warning("Cannot perform token lookup: Instrument list unavailable.")
        return None
    try:
        symbol_upper = symbol.upper()
        exchange_upper = exchange.upper()
        for instrument in instruments:
            inst_symbol = instrument.get('symbol', '').upper()
            inst_exch = instrument.get('exch_seg', '').upper()
            inst_token = instrument.get('token')
            inst_name = instrument.get('name', '').upper()
            if inst_symbol == symbol_upper and inst_exch == exchange_upper and inst_name == symbol_upper:
                 if inst_exch == 'NSE' and instrument.get('lotsize') == '1':
                     logging.info(f"Found equity token {inst_token} for {symbol} on {exchange}")
                     return inst_token
            elif inst_exch == exchange_upper and inst_symbol == symbol_upper: # Wider match for non-equity
                 # Needs refinement for options/futures based on expiry/strike if needed
                 logging.info(f"Found potential non-equity token {inst_token} for {symbol} on {exchange}")
                 return inst_token
        logging.warning(f"Token not found for {symbol} on {exchange}")
        # st.warning(f"Token not found for {symbol} on {exchange}. Check symbol or exchange.") # Can be noisy
        return None
    except Exception as e:
        logging.error(f"Error searching for instrument token: {e}")
        st.error(f"Error during token lookup: {e}")
        return None


# --- Telegram Alert Function ---
# ... (send_telegram_alert function remains the same) ...
def send_telegram_alert(message: str):
    """Sends a message to the configured Telegram chat."""
    if not telegram_available:
        st.error("Telegram library not installed. Cannot send alert.")
        return
    try:
        bot_token = st.secrets["telegram"]["bot_token"]
        chat_id = st.secrets["telegram"]["chat_id"]
    except KeyError as e:
        st.error(f"Telegram secret '{e}' not found in st.secrets.toml.")
        logging.error(f"Telegram secret '{e}' not configured.")
        return
    except Exception as e:
         st.error(f"Error accessing Telegram secrets: {e}")
         logging.error(f"Error accessing secrets: {e}")
         return
    if not bot_token or not chat_id:
        st.error("Telegram bot_token or chat_id is missing/empty in secrets.")
        return
    try:
        bot = telegram.Bot(token=bot_token)
        asyncio.run(bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown'))
        st.toast(f"✅ Alert sent to Telegram!")
        logging.info(f"Telegram alert sent successfully to chat ID {chat_id}.")
    except telegram.error.TelegramError as e:
        st.error(f"Telegram API Error: {e}")
        logging.error(f"Telegram API Error sending message: {e}")
    except Exception as e:
        st.error(f"Failed to send Telegram alert: {e}")
        logging.exception("Error in send_telegram_alert function")


# --- Cached API Call Functions ---
@st.cache_data(ttl=60) # Cache results for 60 seconds
def fetch_gainers_losers_cached(_smartapi_obj: SmartConnect, gl_data_type: str, gl_expiry_type: str) -> pd.DataFrame | str:
    """Cached function to fetch gainers/losers data."""
    # Note: Caching in Streamlit works by hashing input arguments.
    # Passing the SmartConnect object might sometimes cause issues if its internal state changes often
    # in ways irrelevant to this call, or if it's not hashable.
    # If caching fails, alternative is to pass necessary credentials/tokens instead of the object.
    # For now, let's assume the object is hashable enough for TTL caching.
    logging.info(f"CACHE MISS or TTL expired for G/L: Fetching {gl_data_type} ({gl_expiry_type}) from API...")
    try:
        param = {"datatype": gl_data_type, "expirytype": gl_expiry_type}
        gl_data = _smartapi_obj.gainersLosers(param)
        if gl_data and gl_data.get('status') and isinstance(gl_data.get('data'), list):
             df_gl = pd.DataFrame(gl_data['data'])
             return df_gl
        else:
            error_msg = gl_data.get('message', 'API error or no data') if gl_data else "Unknown API error"
            logging.error(f"API Error fetching G/L: {error_msg}")
            return f"API Error: {error_msg}" # Return error string
    except Exception as e:
         logging.exception("Exception during G/L fetch")
         return f"Exception: {e}" # Return error string

@st.cache_data(ttl=60) # Cache results for 60 seconds
def fetch_oi_buildup_cached(_smartapi_obj: SmartConnect, oi_expiry_type: str, oi_data_type: str) -> pd.DataFrame | str:
    """Cached function to fetch OI buildup data."""
    logging.info(f"CACHE MISS or TTL expired for OI: Fetching {oi_data_type} ({oi_expiry_type}) from API...")
    try:
        param = {"expirytype": oi_expiry_type, "datatype": oi_data_type}
        oi_data = _smartapi_obj.oIBuildup(param)
        if oi_data and oi_data.get('status') and isinstance(oi_data.get('data'), list):
             df_oi = pd.DataFrame(oi_data['data'])
             return df_oi
        else:
            error_msg = oi_data.get('message', 'API error or no data') if oi_data else "Unknown API error"
            logging.error(f"API Error fetching OI: {error_msg}")
            return f"API Error: {error_msg}"
    except Exception as e:
         logging.exception("Exception during OI fetch")
         return f"Exception: {e}"

# @st.cache_data(ttl=60) # Cache PCR if needed (assuming it changes)
# def fetch_pcr_cached(_smartapi_obj: SmartConnect) -> dict | str:
#      logging.info("CACHE MISS or TTL expired for PCR: Fetching from API...")
#      try:
#           pcr_data = _smartapi_obj.putCallRatio()
#           if pcr_data and pcr_data.get('status'):
#                return pcr_data # Return the whole dict
#           else:
#                error_msg = pcr_data.get('message', 'API error or no data') if pcr_data else "Unknown API error"
#                logging.error(f"API Error fetching PCR: {error_msg}")
#                return f"API Error: {error_msg}"
#      except Exception as e:
#           logging.exception("Exception during PCR fetch")
#           return f"Exception: {e}"


# --- Streamlit App ---
st.title(" Apache Options - v1")

# --- Initialize Session State ---
# ... (session state initialization remains the same) ...
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
# Add state for market analysis data
if 'gl_data_state' not in st.session_state:
    st.session_state.gl_data_state = pd.DataFrame()
if 'oi_data_state' not in st.session_state:
    st.session_state.oi_data_state = pd.DataFrame()
# if 'pcr_data_state' not in st.session_state:
#      st.session_state.pcr_data_state = None


# --- Sidebar for Login ---
# ... (sidebar login logic remains the same) ...
st.sidebar.header("🔑 SmartAPI Login")
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
api_key = st.sidebar.text_input("API Key", value=api_key_s, type="password" if creds_loaded else "default")
client_id = st.sidebar.text_input("Client ID", value=client_id_s)
password = st.sidebar.text_input("Password", value=password_s, type="password")
totp = st.sidebar.text_input("TOTP Code", type="password")
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
                    st.session_state.feed_token = obj.getfeedToken()
                    st.session_state.user_profile = obj.getProfile(st.session_state.refresh_token)
                    st.session_state.login_status = "Logged In"
                    st.sidebar.success(f"Login Successful!")
                    user_name = client_id
                    if st.session_state.user_profile and isinstance(st.session_state.user_profile, dict) and st.session_state.user_profile.get('data'):
                        user_name = st.session_state.user_profile['data'].get('name', client_id)
                    st.sidebar.write(f"Welcome, {user_name}")
                    st.sidebar.caption(f"Feed Token: ...{st.session_state.feed_token[-10:]}" if st.session_state.feed_token else "N/A")
                    st.rerun()
                else:
                    st.session_state.login_status = "Login Failed"; st.session_state.smartapi_obj = None
                    error_msg = data.get('message', 'Unknown login error') if data else 'Login failed'
                    st.sidebar.error(f"Login Failed: {error_msg}")
            except Exception as e:
                st.session_state.login_status = "Login Error"; st.session_state.smartapi_obj = None
                st.sidebar.error(f"Login Error: {e}")
st.sidebar.metric("Login Status", st.session_state.login_status)
if st.session_state.user_profile and isinstance(st.session_state.user_profile, dict) and st.session_state.user_profile.get('data'):
     profile_data = st.session_state.user_profile['data']
     st.sidebar.caption(f"User: {profile_data.get('name', 'N/A')}")
     st.sidebar.caption(f"Email: {profile_data.get('email', 'N/A')}")
     st.sidebar.caption(f"Broker: {profile_data.get('broker', 'N/A')}")


# --- Main Area with Tabs ---
if st.session_state.login_status == "Logged In" and st.session_state.smartapi_obj:
    obj = st.session_state.smartapi_obj # Use the stored object

    tab1, tab2 = st.tabs(["📊 Historical Data", "📈 Market Analysis"])

    # --- Tab 1: Historical Data ---
    # ... (Historical Data tab logic remains the same as your working version) ...
    with tab1:
        st.subheader("Fetch Historical Candlestick Data")
        col1, col2, col3 = st.columns(3)
        with col1:
            hist_symbol = st.text_input("Symbol (e.g., RELIANCE)", "RELIANCE", key="hist_symbol_input").upper()
            hist_exchange = st.selectbox("Exchange", ["NSE", "NFO", "BSE", "MCX"], key="hist_exchange_select")
        with col2:
            hist_interval = st.selectbox("Interval", ["ONE_MINUTE", "THREE_MINUTE", "FIVE_MINUTE", "TEN_MINUTE", "FIFTEEN_MINUTE", "THIRTY_MINUTE", "ONE_HOUR", "ONE_DAY"], index=7, key="hist_interval_select")
            today = date.today()
            default_from_date = today - timedelta(days=30)
            hist_from_dt = st.date_input("From Date", value=default_from_date, key="hist_from_date")
            hist_from_time = st.time_input("From Time", value=time(9, 15), key="hist_from_time")
        with col3:
             default_to_date = today
             hist_to_dt = st.date_input("To Date", value=default_to_date, key="hist_to_date")
             hist_to_time = st.time_input("To Time", value=time(15, 30), key="hist_to_time")
        hist_fromdate_str = f"{hist_from_dt.strftime('%Y-%m-%d')} {hist_from_time.strftime('%H:%M')}"
        hist_todate_str = f"{hist_to_dt.strftime('%Y-%m-%d')} {hist_to_time.strftime('%H:%M')}"
        st.caption(f"Fetching from: {hist_fromdate_str} to {hist_todate_str}")
        if 'df_hist_result' not in st.session_state: st.session_state.df_hist_result = pd.DataFrame()
        if st.button("Fetch Historical Data", key="fetch_hist_button"):
            if not hist_symbol: st.warning("Please enter a symbol.")
            else:
                with st.spinner(f"Fetching data for {hist_symbol}..."):
                    token = get_instrument_token(hist_symbol, hist_exchange)
                    if token:
                        # st.write(f"Found Token: {token}") # Debug only
                        try:
                            param = { "exchange": hist_exchange, "symboltoken": token, "interval": hist_interval, "fromdate": hist_fromdate_str, "todate": hist_todate_str }
                            hist_data = obj.getCandleData(param)
                            if hist_data and hist_data.get('status') and isinstance(hist_data.get('data'), list):
                                temp_df = pd.DataFrame(hist_data['data'])
                                if not temp_df.empty:
                                    temp_df.columns = ['Timestamp', 'Open', 'High', 'Low', 'Close', 'Volume']
                                    temp_df['Timestamp'] = pd.to_datetime(temp_df['Timestamp'])
                                    temp_df.set_index('Timestamp', inplace=True)
                                    st.session_state.df_hist_result = temp_df
                                    st.success(f"Fetched {len(st.session_state.df_hist_result)} records.")
                                else: st.session_state.df_hist_result = pd.DataFrame(); st.info("No data found.")
                            else: st.session_state.df_hist_result = pd.DataFrame(); st.error(f"Error fetching data: {hist_data.get('message', 'API error')}")
                        except Exception as e: st.session_state.df_hist_result = pd.DataFrame(); st.error(f"An error occurred: {e}"); logging.exception("Hist fetch error")
        if not st.session_state.df_hist_result.empty:
            st.dataframe(st.session_state.df_hist_result, use_container_width=True)
            st.line_chart(st.session_state.df_hist_result['Close'])
            if st.button("Send Data Summary to Telegram", key="telegram_hist_alert"):
                try:
                    df_to_send = st.session_state.df_hist_result; latest_record = df_to_send.iloc[-1]
                    summary_message = ( f"📊 *Historical Data Summary*\n\n" f"`Symbol  :` {hist_symbol}\n" f"`Exchange:` {hist_exchange}\n" f"`Interval:` {hist_interval}\n" f"`Records :` {len(df_to_send)}\n" f"`Last Time:` {latest_record.name.strftime('%d-%b %H:%M')}\n" f"`Last Close:` {latest_record['Close']:.2f}\n" f"`Last Vol  :` {latest_record['Volume']:,.0f}" )
                    send_telegram_alert(summary_message)
                except IndexError: st.error("No data to send.")
                except Exception as e: st.error(f"Telegram alert failed: {e}"); logging.exception("Hist alert error")


    # --- Tab 2: Market Analysis (Modified Logic) ---
    with tab2:
        st.subheader("Market Pulse & Analysis")
        st.caption(f"Data refreshes when 'Refresh Market Data' is clicked (API calls cached for 60s). Last refresh attempt time: {datetime.now().strftime('%H:%M:%S')}")

        # --- Refresh Button ---
        if st.button("🔄 Refresh Market Data", key="refresh_market_data"):
            with st.spinner("Refreshing market data (using cache if valid)..."):
                # Trigger fetches for currently selected parameters to update session state
                # Errors/DataFrames returned by cached functions will be stored
                selected_gl_dtype = st.session_state.get("gl_dtype_select_state", "PercPriceGainers") # Use state or default
                selected_gl_expiry = st.session_state.get("gl_exp_select_state", "NEAR")
                selected_oi_dtype = st.session_state.get("oi_dtype_select_state", "Long Built Up")
                selected_oi_expiry = st.session_state.get("oi_exp_select_state", "NEAR")

                gl_result = fetch_gainers_losers_cached(obj, selected_gl_dtype, selected_gl_expiry)
                oi_result = fetch_oi_buildup_cached(obj, selected_oi_expiry, selected_oi_dtype)
                # pcr_result = fetch_pcr_cached(obj) # Uncomment if using cached PCR

                # Update session state with results (could be DataFrame or error string)
                st.session_state.gl_data_state = gl_result
                st.session_state.oi_data_state = oi_result
                # st.session_state.pcr_data_state = pcr_result # Uncomment if using cached PCR
                st.toast("Market data refresh attempted.")


        # Layout columns for concurrent display
        col_left, col_right = st.columns(2)

        # --- Left Column: Top Gainers/Losers ---
        with col_left:
            st.markdown("##### Top Gainers & Losers")
            # Dropdowns to SELECT WHICH data to view (doesn't trigger fetch on change)
            gl_data_type_select = st.selectbox(
                "Data Type (G/L)",
                ["PercOILosers", "PercOIGainers", "PercPriceGainers", "PercPriceLosers"],
                key="gl_dtype_select_state" # Store selection in state
            )
            gl_expiry_type_select = st.selectbox(
                "Expiry Type (G/L)",
                ["NEAR", "NEXT", "FAR"],
                key="gl_exp_select_state" # Store selection in state
            )

            # Display data from session state (updated by refresh button)
            gl_data_display = st.session_state.get('gl_data_state')
            if isinstance(gl_data_display, pd.DataFrame):
                 if not gl_data_display.empty:
                      st.dataframe(gl_data_display, use_container_width=True, height=300) # Set fixed height
                      # Optional: Add alert button specific to this displayed data
                      if st.button("Send G/L to Telegram", key="telegram_gl_alert_display"):
                           # Format and send st.session_state.gl_data_state
                            try:
                                df_to_send = st.session_state.gl_data_state
                                top_n = 5
                                message_lines = [f"📈 *Top {gl_data_type_select} ({gl_expiry_type_select} Expiry)*\n"] # Use selected types in title
                                for index, row in df_to_send.head(top_n).iterrows():
                                    symbol = row.get('tradingsymbol', 'N/A'); perc_change = row.get('percChange', 'N/A'); ltp = row.get('ltp', 'N/A')
                                    try: perc_change_str = f"{float(perc_change):.2f}%"
                                    except: perc_change_str = f"{perc_change}"
                                    try: ltp_str = f"{float(ltp):.2f}"
                                    except: ltp_str = f"{ltp}"
                                    message_lines.append(f"`{symbol:<15}` LTP: {ltp_str} ({perc_change_str})")
                                if len(df_to_send) > top_n: message_lines.append(f"_(Top {top_n} shown)_")
                                send_telegram_alert("\n".join(message_lines))
                            except Exception as e: st.error(f"G/L Alert failed: {e}"); logging.exception("G/L alert error")

                 else:
                      st.info(f"No data currently available for {gl_data_type_select} / {gl_expiry_type_select}.")
            elif isinstance(gl_data_display, str): # Handle error string
                 st.error(f"Could not load G/L data: {gl_data_display}")


        # --- Right Column: OI Buildup ---
        with col_right:
            st.markdown("##### Open Interest (OI) Buildup")
             # Dropdowns to SELECT WHICH data to view
            oi_expiry_type_select = st.selectbox(
                "Expiry Type (OI)",
                ["NEAR", "NEXT", "FAR"],
                key="oi_exp_select_state" # Store selection in state
            )
            oi_data_type_select = st.selectbox(
                "Data Type (OI)",
                ["Long Built Up", "Short Built Up", "Short Covering", "Long Unwinding"],
                key="oi_dtype_select_state" # Store selection in state
            )

            # Display data from session state
            oi_data_display = st.session_state.get('oi_data_state')
            if isinstance(oi_data_display, pd.DataFrame):
                 if not oi_data_display.empty:
                      st.dataframe(oi_data_display, use_container_width=True, height=300) # Set fixed height
                      # Optional: Add alert button specific to this displayed data
                      if st.button("Send OI to Telegram", key="telegram_oi_alert_display"):
                            # Format and send st.session_state.oi_data_state
                           try:
                               df_to_send = st.session_state.oi_data_state
                               top_n = 5
                               message_lines = [f"📈 *OI Buildup: {oi_data_type_select} ({oi_expiry_type_select} Expiry)*\n"] # Use selected types
                               for index, row in df_to_send.head(top_n).iterrows():
                                   symbol = row.get('symbol', 'N/A'); oi_change = row.get('oiChangePerc', 'N/A'); price_change = row.get('priceChangePerc', 'N/A'); ltp = row.get('ltp', 'N/A')
                                   try: oi_ch_str = f"{float(oi_change):.2f}%"
                                   except: oi_ch_str = f"{oi_change}"
                                   try: price_ch_str = f"{float(price_change):.2f}%"
                                   except: price_ch_str = f"{price_change}"
                                   try: ltp_str = f"{float(ltp):.2f}"
                                   except: ltp_str = f"{ltp}"
                                   message_lines.append(f"`{symbol:<15}` LTP: {ltp_str}, OI Chg: {oi_ch_str}, Price Chg: {price_ch_str}")
                               if len(df_to_send) > top_n: message_lines.append(f"_(Top {top_n} shown)_")
                               send_telegram_alert("\n".join(message_lines))
                           except Exception as e: st.error(f"OI Alert failed: {e}"); logging.exception("OI alert error")

                 else:
                      st.info(f"No data currently available for {oi_data_type_select} / {oi_expiry_type_select}.")
            elif isinstance(oi_data_display, str): # Handle error string
                 st.error(f"Could not load OI data: {oi_data_display}")


        # --- PCR Section (Simplified Display) ---
        # st.markdown("---")
        # st.markdown("##### Put-Call Ratio (PCR)")
        # You could add a small display area here reading from st.session_state.pcr_data_state
        # if you implement caching and updating for it via the Refresh button.
        # Example:
        # pcr_display_data = st.session_state.get('pcr_data_state')
        # if pcr_display_data:
        #      if isinstance(pcr_display_data, dict) and 'error' not in pcr_display_data:
        #            st.metric("PCR Value", pcr_display_data.get('data',{}).get('pcr', 'N/A'))
        #      elif isinstance(pcr_display_data, str):
        #            st.error(f"PCR Error: {pcr_display_data}")
        # else:
        #      st.caption("Click 'Refresh Market Data' to load PCR.")


else:
    st.info("ℹ️ Please log in using the sidebar to access API functionalities.")

# Disclaimer Footer
# ... (Disclaimer remains the same) ...
st.markdown("---")
st.warning("""
**Disclaimer:** This tool interacts with SmartAPI. Trading involves risk. Data accuracy depends on the API. Verify information and DYOR. Ensure secure handling of credentials. Alerts are sent manually via buttons. Market data uses a 60s cache; click Refresh to update.
""")
