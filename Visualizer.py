import pandas as pd
import plotly.express as px
import streamlit as st
import requests
from bs4 import BeautifulSoup
import os
#streamlit run "d:/Directory of my code.py" 
#do pip install requests beautifulsoup4
st.set_page_config(page_title="Event Log Visualizer", layout="wide")
st.title("🔍 Windows Event Log Visualizer (Cybersecurity Tool)")

# Stop Server Button
if st.sidebar.button("🛑 Stop Visualizer"):
    st.warning("Visualizer stopped by user.")
    os._exit(0)

# ================================
# Scrape Event Error Code Explanations
# ================================
@st.cache_data
def fetch_event_error_codes():
    url = "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    event_dict = {}
    tables = soup.find_all("table")

    for table in tables:
        rows = table.find_all("tr")
        for row in rows[1:]:  # skip header
            cols = row.find_all(["td", "th"])
            if len(cols) >= 2:
                event_id = cols[0].text.strip()
                description = cols[1].text.strip()
                event_dict[event_id] = description

    return event_dict

event_explanations = fetch_event_error_codes()

# ================================
# File Upload
# ================================
uploaded_file = st.file_uploader("Upload Event Log CSV", type=["csv"])
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    # Convert time
    df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], errors='coerce')

    # Sidebar Filters
    st.sidebar.header("Filter Logs")
    log_levels = st.sidebar.multiselect("Select Log Level", options=df["LevelDisplayName"].unique(),
                                        default=df["LevelDisplayName"].unique())
    event_ids = st.sidebar.multiselect("Select Event IDs", options=df["Id"].unique(),
                                       default=df["Id"].unique())

    df_filtered = df[(df["LevelDisplayName"].isin(log_levels)) & (df["Id"].isin(event_ids))]

    st.write(f"### Filtered Logs: {len(df_filtered)} events")
    st.dataframe(df_filtered, height=300)

    # =============================
    # Visualization 1: Events over time
    # =============================
    st.subheader("📈 Events Over Time")
    events_over_time = df_filtered.groupby(df_filtered["TimeCreated"].dt.hour).size().reset_index(name="Count")
    fig_time = px.line(events_over_time, x="TimeCreated", y="Count", title="Events per Hour")
    st.plotly_chart(fig_time, use_container_width=True)

    # =============================
    # Visualization 2: Event Levels
    # =============================
    st.subheader("🛡 Event Levels Distribution")
    fig_levels = px.pie(df_filtered, names="LevelDisplayName", title="Log Levels Distribution")
    st.plotly_chart(fig_levels, use_container_width=True)

    # =============================
    # Visualization 3: Top Event IDs
    # =============================
    st.subheader("📊 Top Event IDs with Explanations")
    top_events = df_filtered["Id"].value_counts().reset_index()
    top_events.columns = ["Event ID", "Count"]
    st.table(top_events)

    # Show explanations
    for event_id in top_events["Event ID"]:
        str_event_id = str(event_id)
        if str_event_id in event_explanations:
            st.markdown(f"**{str_event_id}** → {event_explanations[str_event_id]}")
        else:
            st.markdown(f"**{str_event_id}** → No explanation available. [View Microsoft Docs](https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes)")

    # =============================
    # Download Filtered Logs
    # =============================
    st.subheader("⬇ Download Filtered Logs")
    st.download_button("Download CSV", data=df_filtered.to_csv(index=False), file_name="Filtered_Logs.csv")

else:
    st.info("Please upload a CSV file exported from Event Viewer.")
