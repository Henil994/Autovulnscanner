import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from main import run_scan_and_get_report  # We'll update main.py accordingly

class AutoVulnScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AutoVulnScanner GUI")
        self.geometry("700x500")
        self.resizable(False, False)

        self.target_var = tk.StringVar()
        self.format_var = tk.StringVar(value="txt")

        self.tool_vars = {
            "WHOIS": tk.BooleanVar(value=True),
            "Nmap": tk.BooleanVar(value=True),
            "Nikto": tk.BooleanVar(value=True),
            "SQLMap": tk.BooleanVar(value=True),
        }

        self.scan_thread = None
        self.report_content = None  # will hold report text/pdf data after scan

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Target URL or IP:").pack(pady=(10, 0))
        tk.Entry(self, textvariable=self.target_var, width=50).pack()

        tools_frame = tk.LabelFrame(self, text="Select Tools to Run")
        tools_frame.pack(pady=10, padx=10, fill="x")
        for tool, var in self.tool_vars.items():
            cb = tk.Checkbutton(tools_frame, text=tool, variable=var)
            cb.pack(side="left", padx=5)

        file_frame = tk.Frame(self)
        file_frame.pack(pady=5)
        tk.Label(file_frame, text="Format:").grid(row=0, column=0, sticky="w", padx=(15,0))
        format_options = ["txt", "pdf"]
        format_menu = ttk.Combobox(file_frame, values=format_options, textvariable=self.format_var, state="readonly", width=5)
        format_menu.grid(row=0, column=1, padx=5)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        self.scan_btn = tk.Button(btn_frame, text="Run Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=10)

        self.save_btn = tk.Button(btn_frame, text="Save Report As...", command=self.save_report)
        self.save_btn.pack(side="left", padx=10)
        self.save_btn.config(state="disabled")

        tk.Label(self, text="Scan Status / Log:").pack()
        self.log_text = tk.Text(self, height=15, width=80, state="disabled")
        self.log_text.pack(pady=(0,10))

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL or IP.")
            return

        self.scan_btn.config(state="disabled")
        self.save_btn.config(state="disabled")
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")
        self.log(f"Starting scan on {target}...")

        fmt = self.format_var.get()

        def scan_task():
            try:
                # Run the scan and get report content (string or bytes)
                report = run_scan_and_get_report(target, fmt)
                self.report_content = report
                self.log(f"Scan completed successfully.")
                self.save_btn.config(state="normal")
            except Exception as e:
                self.log(f"Error during scan: {e}")
                messagebox.showerror("Scan Error", str(e))
            finally:
                self.scan_btn.config(state="normal")

        self.scan_thread = threading.Thread(target=scan_task)
        self.scan_thread.start()

    def save_report(self):
        if not self.report_content:
            messagebox.showerror("Error", "No report available to save.")
            return

        fmt = self.format_var.get()
        filetypes = [(f"{fmt.upper()} files", f"*.{fmt}"), ("All files", "*.*")]
        initial_filename = self.target_var.get().strip().replace("://", "_").replace(".", "_").replace("/", "_") + f".{fmt}"

        dest = filedialog.asksaveasfilename(
            initialfile=initial_filename,
            defaultextension=f".{fmt}",
            filetypes=filetypes,
        )
        if dest:
            try:
                mode = "wb" if fmt == "pdf" else "w"
                data = self.report_content if fmt == "txt" else self.report_content  # bytes or str

                with open(dest, mode) as f:
                    f.write(data)
                messagebox.showinfo("Success", f"Report saved to {dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")

if __name__ == "__main__":
    app = AutoVulnScannerGUI()
    app.mainloop()
