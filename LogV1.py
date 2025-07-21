import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk
import os

# --- Load XML File ---
xml_file = os.path.join("..", "ComputerScans 27-07-2025.xml")
tree = ET.parse(xml_file)
root = tree.getroot()

# --- Create Main Window ---
window = tk.Tk()
window.title("ESET XML Log Viewer")
window.geometry("950x500")

# --- Frame for Table ---
frame = tk.Frame(window)
frame.pack(fill=tk.BOTH, expand=True)

# --- Scrollbars ---
vsb = tk.Scrollbar(frame, orient="vertical")
hsb = tk.Scrollbar(frame, orient="horizontal")

# --- Table (Treeview) ---
columns = ("Time", "Scanned folders", "Scanned", "Detected", "Cleaned", "Status")
treeview = ttk.Treeview(frame, columns=columns, show="headings",
                        yscrollcommand=vsb.set, xscrollcommand=hsb.set)

vsb.config(command=treeview.yview)
hsb.config(command=treeview.xview)
vsb.pack(side=tk.RIGHT, fill=tk.Y)
hsb.pack(side=tk.BOTTOM, fill=tk.X)

# --- Column Setup ---
for col in columns:
    treeview.heading(col, text=col)
    treeview.column(col, width=150, anchor="w")

treeview.pack(fill=tk.BOTH, expand=True)

# --- Style for Meaningful Rows ---
style = ttk.Style()
style.configure("Treeview", rowheight=22)
style.map("Treeview", background=[('selected', 'blue')])

# Tag colors
treeview.tag_configure("detected", background="#ffcccc")   # Light red for detected threats
treeview.tag_configure("cleaned", background="#ccffcc")    # Light green for cleaned threats

# --- Insert Data and Meaningful Tags ---
total_scanned, total_detected, total_cleaned = 0, 0, 0

for record in root.findall(".//RECORD"):
    row_data = []
    detected, cleaned = 0, 0

    for col in columns:
        column = record.find(f".//COLUMN[@NAME='{col}']")
        text = column.text if column is not None else ""
        row_data.append(text)

        # Count stats
        if col == "Scanned" and text.isdigit():
            total_scanned += int(text)
        elif col == "Detected" and text.isdigit():
            detected = int(text)
            total_detected += detected
        elif col == "Cleaned" and text.isdigit():
            cleaned = int(text)
            total_cleaned += cleaned

    # Tagging rows
    if detected > 0:
        treeview.insert("", tk.END, values=row_data, tags=("detected",))
    elif cleaned > 0:
        treeview.insert("", tk.END, values=row_data, tags=("cleaned",))
    else:
        treeview.insert("", tk.END, values=row_data)

# --- Status Bar Summary ---
status_label = tk.Label(window, text=f"Total Scanned: {total_scanned:,} | "
                                    f"Total Detected: {total_detected} | "
                                    f"Total Cleaned: {total_cleaned}",
                        anchor="w", relief="sunken", bd=2, font=("Arial", 10))
status_label.pack(fill=tk.X, side=tk.BOTTOM)

# --- Run GUI ---
window.mainloop()
