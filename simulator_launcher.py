import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import webbrowser
import psutil
import time
import sys
import logging

# Configure logging
logging.basicConfig(
    filename='simulator_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Base directory - where the script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def run_batch_file(batch_file, window_title):
    """Run a batch file and return the process"""
    try:
        # Use full path for the batch file
        batch_path = os.path.join(BASE_DIR, batch_file)
        if not os.path.exists(batch_path):
            raise FileNotFoundError(f"Cannot find {batch_file}")

        # Create the process with a specific window title
        process = subprocess.Popen(
            f'start "{window_title}" /wait cmd /c "{batch_path}"',
            shell=True,
            cwd=BASE_DIR
        )
        return process
    except Exception as e:
        logging.error(f"Error running {batch_file}: {str(e)}")
        raise

class SimulatorControl:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyberattack Simulator Control Panel")
        self.root.geometry("400x320")
        self.root.resizable(False, False)
        
        # Configure window style
        self.root.configure(bg='#1a1a1a')
        
        # Create and pack widgets
        self.create_widgets()
        
        # Initialize status
        self.check_status()

    def create_widgets(self):
        # Title
        title = tk.Label(
            self.root,
            text="💻 Cyberattack Simulator",
            font=("Arial", 16, "bold"),
            fg="#00ff00",
            bg="#1a1a1a"
        )
        title.pack(pady=10)

        # Buttons
        button_configs = [
            ("▶️ Start Simulator", self.start_simulator),
            ("🛑 Stop Simulator", self.stop_simulator),
            ("🔍 Check Status", self.check_status),
            ("📄 Open Report", self.open_report),
            ("🌐 Open in Browser", lambda: webbrowser.open("http://localhost:3000"))
        ]

        for text, command in button_configs:
            btn = tk.Button(
                self.root,
                text=text,
                command=command,
                width=25,
                bg="#2c2c2c",
                fg="#ffffff",
                activebackground="#3c3c3c",
                activeforeground="#00ff00",
                relief=tk.FLAT,
                pady=5
            )
            btn.pack(pady=5)

        # Status label
        self.status_label = tk.Label(
            self.root,
            text="",
            fg="#00ff00",
            bg="#1a1a1a",
            justify="left",
            font=("Arial", 10)
        )
        self.status_label.pack(pady=10)

    def start_simulator(self):
        try:
            self.status_label.config(text="Starting simulator...\nPlease wait...")
            self.root.update()

            # Start the simulator using the batch file
            process = run_batch_file("start-simulator.bat", "Simulator Startup")
            
            # Wait a bit and check status
            time.sleep(5)
            self.check_status()
            
        except Exception as e:
            error_msg = f"Failed to start simulator: {str(e)}"
            logging.error(error_msg)
            messagebox.showerror("Error", error_msg)

    def stop_simulator(self):
        try:
            self.status_label.config(text="Stopping simulator...\nPlease wait...")
            self.root.update()

            # Run the stop script
            process = run_batch_file("stop-simulator.bat", "Simulator Shutdown")
            
            # Wait a bit and check status
            time.sleep(2)
            self.check_status()

        except Exception as e:
            error_msg = f"Failed to stop simulator: {str(e)}"
            logging.error(error_msg)
            messagebox.showerror("Error", error_msg)

    def check_status(self):
        try:
            flask_running = False
            react_running = False
            
            # Check for processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        if 'python' in proc.info['name'].lower() and 'app.py' in cmdline:
                            flask_running = True
                        elif 'node' in proc.info['name'].lower() and ('react-scripts' in cmdline or 'npm start' in cmdline):
                            react_running = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Update status text
            status = ""
            status += "🟢 Flask (backend): RUNNING\n" if flask_running else "🔴 Flask (backend): OFF\n"
            status += "🟢 React (frontend): RUNNING" if react_running else "🔴 React (frontend): OFF"
            
            self.status_label.config(text=status)
            
        except Exception as e:
            error_msg = f"Error checking status: {str(e)}"
            logging.error(error_msg)
            self.status_label.config(text=error_msg)

    def open_report(self):
        log_path = os.path.join(BASE_DIR, "backend", "logs", "simulation_report.txt")
        if os.path.exists(log_path):
            os.startfile(log_path)
        else:
            messagebox.showwarning("Warning", "Log file not found.")

if __name__ == '__main__':
    try:
        root = tk.Tk()
        app = SimulatorControl(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)
