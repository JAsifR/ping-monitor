# Advanced Network Ping Monitor

A real-time network monitoring tool that continuously pings multiple hosts and tracks latency, jitter, packet loss, uptime percentage and network quality with geolocation and CSV logging.

## Features
- Monitors multiple hosts simultaneously using threads
- Tracks average, min and max latency in milliseconds
- Calculates jitter and packet loss percentage
- Uptime percentage per host
- Network quality rating: Excellent, Good, Fair, Poor, Critical
- Geolocation of each host with ISP info
- Detects and logs outages with timestamps
- Live updating terminal table
- Saves full logs to CSV automatically

## Technologies
- Python 3
- socket, threading, subprocess, platform
- requests (geolocation)
- collections, csv

## Usage
```bash
pip install requests
python ping_monitor.py
```

## Skills Demonstrated
- Network monitoring and diagnostics
- Multi-threading
- IT support and infrastructure monitoring concepts
- Data logging and analysis
