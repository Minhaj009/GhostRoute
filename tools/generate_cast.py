#!/usr/bin/env python3
import subprocess
import json
import time

def generate_cast():
    # Run ghostroute scan --demo and capture full ANSI stdout
    proc = subprocess.run(['./ghostroute.exe', 'scan', '--demo'], capture_output=True)
    raw_output = proc.stdout.decode('utf-8', errors='replace')
    
    # Normalize CRLF
    normalized_output = raw_output.replace('\r\n', '\n').replace('\n', '\r\n')

    header = {
        "version": 2,
        "width": 96,
        "height": 34,
        "timestamp": int(time.time()),
        "title": "GhostRoute: Offline Cloud Zombie & Dangling DNS Hunter",
        "env": {
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color"
        }
    }

    events = []
    current_time = 0.0

    # Initial prompt
    events.append([round(current_time, 3), "o", "\x1b[?25h$ "])
    current_time += 0.4

    # Type command: ghostroute scan --demo
    cmd = "ghostroute scan --demo"
    for char in cmd:
        current_time += 0.065
        events.append([round(current_time, 3), "o", char])

    current_time += 0.35
    events.append([round(current_time, 3), "o", "\r\n"])
    current_time += 0.1

    # Emit output lines with slight pacing for natural rendering
    lines = normalized_output.split('\r\n')
    for line in lines:
        current_time += 0.015
        events.append([round(current_time, 3), "o", line + "\r\n"])

    # Pause after scan completes
    current_time += 4.5
    events.append([round(current_time, 3), "o", "$ "])
    current_time += 0.5
    for char in "exit":
        current_time += 0.08
        events.append([round(current_time, 3), "o", char])
    current_time += 0.2
    events.append([round(current_time, 3), "o", "\r\n"])

    with open("demo.cast", "w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    print(f"demo.cast generated successfully ({len(events)} events, duration: {round(current_time, 1)}s)")

if __name__ == "__main__":
    generate_cast()
