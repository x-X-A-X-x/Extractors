import pandas as pd
import plotly.express as px
import streamlit as st
#Enter to terminal> streamlit run "d:/Directory of your.py"
# -------------------
# Load the CSV File
# -------------------
st.set_page_config(page_title="Event Log Visualizer", layout="wide")

st.title("🔍 Windows Event Log Visualizer (Cybersecurity Tool)")

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

    # -------------------
    # Visualization 1: Events over tim
    # -------------------
    st.subheader("📈 Events Over Time")
    events_over_time = df_filtered.groupby(df_filtered["TimeCreated"].dt.hour).size().reset_index(name="Count")
    fig_time = px.line(events_over_time, x="TimeCreated", y="Count", title="Events per Hour")
    st.plotly_chart(fig_time, use_container_width=True)

    # -------------------
    # Visualization 2: Event Levels
    # -------------------
    st.subheader("🛡 Event Levels Distribution")
    fig_levels = px.pie(df_filtered, names="LevelDisplayName", title="Log Levels Distribution")
    st.plotly_chart(fig_levels, use_container_width=True)

    # -------------------
    # Visualization 3: Top Event IDs
    # -------------------
    st.subheader("📊 Top Event IDs")
    top_events = df_filtered["Id"].value_counts().reset_index()
    top_events.columns = ["Event ID", "Count"]
    fig_ids = px.bar(top_events, x="Event ID", y="Count", title="Top Event IDs")
    st.plotly_chart(fig_ids, use_container_width=True)

    # -------------------
    # Download Filtered Logs
    # -------------------
    st.subheader("⬇ Download Filtered Logs")
    st.download_button("Download CSV", data=df_filtered.to_csv(index=False), file_name="Filtered_Logs.csv")

else:
    st.info("Please upload a CSV file exported from Event Viewer.")
