import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk
import os

# --- Load XML File ---
xml_file = os.path.join("..", "ComputerScans 27-07-2025.xml")
tree = ET.parse(xml_file)
root = tree.getroot()

# --- Extract Data ---
scans = []
detected_counts = []
cleaned_counts = []
times = []

for record in root.findall(".//RECORD"):
    time = record.find(".//COLUMN[@NAME='Time']").text
    scanned = int(record.find(".//COLUMN[@NAME='Scanned']").text)
    detected = int(record.find(".//COLUMN[@NAME='Detected']").text)
    cleaned = int(record.find(".//COLUMN[@NAME='Cleaned']").text)

    times.append(time)
    scans.append(scanned)
    detected_counts.append(detected)
    cleaned_counts.append(cleaned)

# --- Create Main Window ---
window = tk.Tk()
window.title("ESET Log Viewer with Graphs")
window.geometry("1000x700")

# --- Table Frame ---
frame = tk.Frame(window)
frame.pack(fill=tk.BOTH, expand=True)

columns = ("Time", "Scanned", "Detected", "Cleaned")
treeview = ttk.Treeview(frame, columns=columns, show="headings")
for col in columns:
    treeview.heading(col, text=col)
    treeview.column(col, width=200, anchor="w")
treeview.pack(fill=tk.BOTH, expand=True)

# Insert table data
for t, s, d, c in zip(times, scans, detected_counts, cleaned_counts):
    treeview.insert("", tk.END, values=(t, f"{s:,}", d, c))

# --- Graph Frame ---
graph_frame = tk.LabelFrame(window, text="Scanned vs Detected vs Cleaned", padx=10, pady=10)
graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

canvas = tk.Canvas(graph_frame, bg="white", height=300)
canvas.pack(fill=tk.BOTH, expand=True)

# --- Draw Bar Graph ---
max_scan = max(scans) if scans else 1
bar_width = 10
spacing = 5
x_offset = 40
y_offset = 280

# Axes
canvas.create_line(x_offset, y_offset, 900, y_offset, width=2)  # X-axis
canvas.create_line(x_offset, y_offset, x_offset, 20, width=2)   # Y-axis

for i, (s, d, c) in enumerate(zip(scans, detected_counts, cleaned_counts)):
    x = x_offset + i * (bar_width + spacing)
    # Normalize heights
    scan_height = (s / max_scan) * 250
    det_height = (d / max_scan) * 250
    clean_height = (c / max_scan) * 250

    # Bars
    canvas.create_rectangle(x, y_offset - scan_height, x + bar_width, y_offset, fill="blue", outline="black")
    canvas.create_rectangle(x + bar_width + 1, y_offset - det_height, x + 2*bar_width, y_offset, fill="red", outline="black")
    canvas.create_rectangle(x + 2*bar_width + 2, y_offset - clean_height, x + 3*bar_width, y_offset, fill="green", outline="black")

# Labels
canvas.create_text(100, 10, text="Blue = Scanned, Red = Detected, Green = Cleaned", fill="black", font=("Arial", 10))

# --- Run GUI ---
window.mainloop()
