import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk

# Load and parse XML file
xml_file = "ComputerScans 27-07-2025.xml"
tree = ET.parse(xml_file)
root = tree.getroot()

# Create main window
window = tk.Tk()
window.title("ESET XML Log Viewer")
window.geometry("900x400")

# Create a frame for table and scrollbar
frame = tk.Frame(window)
frame.pack(fill=tk.BOTH, expand=True)

# Scrollbars
vsb = tk.Scrollbar(frame, orient="vertical")
hsb = tk.Scrollbar(frame, orient="horizontal")

# Table (Treeview)
columns = ("Time", "Scanned folders", "Scanned", "Detected", "Cleaned", "Status")
treeview = ttk.Treeview(frame, columns=columns, show="headings",
                        yscrollcommand=vsb.set, xscrollcommand=hsb.set)

# Configure scrollbars
vsb.config(command=treeview.yview)
hsb.config(command=treeview.xview)
vsb.pack(side=tk.RIGHT, fill=tk.Y)
hsb.pack(side=tk.BOTTOM, fill=tk.X)

# Define column headings
for col in columns:
    treeview.heading(col, text=col)
    treeview.column(col, width=150, anchor="w")

treeview.pack(fill=tk.BOTH, expand=True)

# Extract and insert data into table
for record in root.findall(".//RECORD"):
    row_data = []
    for col in columns:
        column = record.find(f".//COLUMN[@NAME='{col}']")
        row_data.append(column.text if column is not None else "")
    treeview.insert("", tk.END, values=row_data)

# Run the GUI
window.mainloop()
