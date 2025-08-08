import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import threading
import datetime
from main import run_scan_and_report

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

class AutoVulnScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AutoVulnScanner GUI")
        self.root.geometry("600x450")

        self.target_var = tk.StringVar()
        self.format_var = tk.StringVar(value="txt")
        self.scan_completed = False

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Target (domain or IP):").pack(pady=5)
        tk.Entry(self.root, textvariable=self.target_var, width=50).pack(pady=5)

        tk.Label(self.root, text="Select Tools:").pack()
        self.tools_vars = {
            "Nmap": tk.BooleanVar(value=True),
            "Nikto": tk.BooleanVar(value=True),
            "SQLMap": tk.BooleanVar(value=True),
            "WHOIS": tk.BooleanVar(value=True)
        }

        for tool, var in self.tools_vars.items():
            tk.Checkbutton(self.root, text=tool, variable=var).pack(anchor="w", padx=100)

        tk.Label(self.root, text="Report Format:").pack()
        ttk.Combobox(self.root, textvariable=self.format_var, values=["txt", "pdf"]).pack(pady=5)

        self.status_label = tk.Label(self.root, text="", fg="green")
        self.status_label.pack()

        tk.Button(self.root, text="Run Scan", command=self.run_scan).pack(pady=10)

        self.save_button = tk.Button(self.root, text="Save Report", command=self.save_report)
        self.save_button.pack(pady=5)
        self.save_button.pack_forget()  # Initially hidden

    def run_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target.")
            return

        selected_tools = [tool for tool, var in self.tools_vars.items() if var.get()]
        if not selected_tools:
            messagebox.showerror("Error", "Select at least one tool.")
            return

        self.status_label.config(text="Scanning in progress...", fg="blue")
        self.save_button.pack_forget()

        report_format = self.format_var.get()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_file = os.path.join(RESULTS_DIR, f"{target.replace('.', '_')}_{timestamp}.{report_format}")

        threading.Thread(target=self._scan_thread, args=(target, selected_tools, report_format), daemon=True).start()

    def _scan_thread(self, target, tools, report_format):
        try:
            run_scan_and_report(target, report_format, self.output_file, tools)
            self.status_label.config(text=f"Scan complete. Report saved at {self.output_file}", fg="green")
            self.save_button.pack()
            self.scan_completed = True
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", fg="red")

    def save_report(self):
        if not self.scan_completed:
            messagebox.showinfo("Info", "No report to save yet.")
            return

        dest = filedialog.asksaveasfilename(defaultextension=f".{self.format_var.get()}",
                                            filetypes=[("All Files", "*.*")])
        if dest:
            try:
                import shutil
                shutil.copy(self.output_file, dest)
                messagebox.showinfo("Success", f"Report copied to {dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not copy file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AutoVulnScannerGUI(root)
    root.mainloop()
