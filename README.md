# Real-Time-Monitoring-Dashboard
The motivation behind this project is to create a lightweight, user-friendly, and real-time monitoring dashboard that offers advanced functionalities like live CPU graphs, process control (termination), GPU usage display, and the ability to save reports for future reference. 
🚀 Features
	•	Live CPU Usage Graph with matplotlib
	•	GPU Usage Monitoring using GPUtil (NVIDIA GPUs only)
	•	Search and Filter processes by name, CPU %, and memory %
	•	Kill Individual or Multiple Processes with confirmation dialogs
	•	Process Details Popup on double-click (PID, threads, core, status, etc.)
	•	Save Process List to File for logging or debugging
	•	Selection Persistence across refresh cycles
	•	Auto-refresh every 5 seconds

📦 Built With
	•	tkinter – for GUI development
	•	psutil – to interact with system processes and performance metrics
	•	GPUtil – for GPU monitoring (optional, fallback included)
	•	matplotlib – to plot CPU usage over time
	•	threading – to run monitoring in the background without freezing the GUI
