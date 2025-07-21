import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk

# Load and parse XML file
tree = ET.parse("ComputerScans 27-07-2025.xml")
root = tree.getroot()

# Create main window
window = tk.Tk()
window.title("ESET XML Log Viewer")
window.geometry("600x300")

# Create Treeview (table)
columns = ("Time", "Scanned folders", "Scanned", "Detected", "Cleaned", "Status")
treeview = ttk.Treeview(window, columns=columns, show="headings")

# Define column headings
for col in columns:
    treeview.heading(col, text=col)
    treeview.column(col, width=100)

# Extract data from XML and insert into Treeview
for record in root.findall(".//RECORD"):
    row_data = []
    for col in columns:
        column = record.find(f".//COLUMN[@NAME='{col}']")
        row_data.append(column.text if column is not None else "")
    treeview.insert("", tk.END, values=row_data)

treeview.pack(fill=tk.BOTH, expand=True)

# Run GUI
window.mainloop()
