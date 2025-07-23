import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk
import os
import matplotlib.pyplot as plt
from datetime import datetime

# --- Load XML File ---
xml_file = os.path.join("..", "ComputerScans 27-07-2025.xml")
tree = ET.parse(xml_file)
root = tree.getroot()

# --- Prepare Data for Table and Graphs ---
columns = ("Time", "Scanned folders", "Scanned", "Detected", "Cleaned", "Status")
records = []
scanned_over_time = []
detected_cleaned = {"Detected": 0, "Cleaned": 0}

for record in root.findall(".//RECORD"):
    row = {}
    for col in columns:
        column = record.find(f".//COLUMN[@NAME='{col}']")
        row[col] = column.text if column is not None else ""
    records.append(row)

    # Collect graph data
    try:
        scanned = int(row["Scanned"])
        time_obj = datetime.strptime(row["Time"], "%d/%m/%Y %I:%M:%S %p")
        scanned_over_time.append((time_obj, scanned))
        detected_cleaned["Detected"] += int(row["Detected"])
        detected_cleaned["Cleaned"] += int(row["Cleaned"])
    except:
        pass

# Sort by time for line graph
scanned_over_time.sort(key=lambda x: x[0])

# --- Create Main Window ---
window = tk.Tk()
window.title("ESET XML Log Viewer with Graphs")
window.geometry("950x500")

frame = tk.Frame(window)
frame.pack(fill=tk.BOTH, expand=True)

vsb = tk.Scrollbar(frame, orient="vertical")
hsb = tk.Scrollbar(frame, orient="horizontal")

treeview = ttk.Treeview(frame, columns=columns, show="headings",
                        yscrollcommand=vsb.set, xscrollcommand=hsb.set)
vsb.config(command=treeview.yview)
hsb.config(command=treeview.xview)
vsb.pack(side=tk.RIGHT, fill=tk.Y)
hsb.pack(side=tk.BOTTOM, fill=tk.X)

# Define Table Columns
for col in columns:
    treeview.heading(col, text=col)
    treeview.column(col, width=150, anchor="w")
treeview.pack(fill=tk.BOTH, expand=True)

# Insert Records
for row in records:
    tags = ()
    if int(row["Detected"]) > 0:
        tags = ("detected",)
    elif int(row["Cleaned"]) > 0:
        tags = ("cleaned",)
    treeview.insert("", tk.END, values=[row[c] for c in columns], tags=tags)

treeview.tag_configure("detected", background="#ffcccc")
treeview.tag_configure("cleaned", background="#ccffcc")

# --- Graph Functions ---
def show_graphs():
    # Line Graph: Scanned over Time
    times = [x[0] for x in scanned_over_time]
    scanned_values = [x[1] for x in scanned_over_time]

    plt.figure(figsize=(10, 5))
    plt.plot(times, scanned_values, marker="o")
    plt.title("Scanned Files Over Time")
    plt.xlabel("Time")
    plt.ylabel("Files Scanned")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Bar Graph: Detected vs Cleaned
    plt.figure(figsize=(5, 4))
    plt.bar(detected_cleaned.keys(), detected_cleaned.values(), color=["red", "green"])
    plt.title("Detected vs Cleaned Threats")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()

# --- Button to Show Graphs ---
graph_btn = tk.Button(window, text="Show Graphs", command=show_graphs)
graph_btn.pack(pady=5)

window.mainloop()
