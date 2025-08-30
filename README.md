# 🕵️ Network Sniffer (Flask + Scapy)

A simple **real-time packet sniffer** built using **Python, Flask, and Scapy**.  
It captures, analyzes, and displays network packets in a web interface styled with **Tailwind CSS**.

---

## 🚀 Features
- Capture **live packets** (TCP, UDP, Others)
- View **Source IP, Destination IP, Protocol, and Payload**
- **Start / Stop** capturing from the web UI
- **Clear packet history**
- Auto-scrolls as new packets arrive
- Gradient UI with TailwindCSS styling & animations

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-sniffer.git
   cd network-sniffer


🛠️ Tech Stack

Python 3.8+

Flask – Web server & API

Scapy – Packet sniffing & analysis

TailwindCSS – Styling & animations

JavaScript (Fetch API) – Real-time packet updates

##Windows

Show network adapters:

Get-NetAdapter | Format-Table -Auto


Find adapter GUIDs:

Get-NetAdapter | Select Name, InterfaceGuid

List interfaces:

ifconfig
# or
ip addr show

🔹 Scapy (Python)

List available interfaces:

from scapy.all import get_if_list
print(get_if_list())


Show default interface:

from scapy.all import conf
print(conf.iface)