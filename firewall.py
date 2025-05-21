from flask import Flask, request, jsonify, render_template
import scapy.all as scapy
import sqlite3
import threading
import psutil
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from collections import defaultdict
import time
import json

# Packet Sniffer (Threaded)
# -------------------------------

#new code for packet_callback:
from queue import SimpleQueue
packet_queue = SimpleQueue()

# Modify callback
def packet_callback(packet):
    # testing:
    # #print(process_packets().dns_ip)
    # if packet.haslayer(scapy.DNS):
    #     dns_layer = packet[scapy.DNS]
    #     print(f"DNS Query/Response: {dns_layer.summary()}")  
    # # Check if the packet has an IP layer
    # if packet.haslayer(scapy.IP):
    #     packet_queue.put(packet)

    # related to DNS:
    if packet.haslayer(scapy.DNS):
        dns_layer = packet[scapy.DNS]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
        dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"

        # DNS Query
        if dns_layer.qr == 0 and dns_layer.qd:
            query_name = dns_layer.qd.qname.decode()
            dns_log_entry = {
                "time": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "type": "query",
                "domain": query_name
            }
            firewall.dns_logs.append(dns_log_entry)
            print(f"[DNS QUERY] {src_ip} → {query_name}")

        # DNS Response
        elif dns_layer.qr == 1 and dns_layer.an:
            try:
                answers = []
                for i in range(dns_layer.ancount):
                    ans = dns_layer.an[i]
                    answers.append(f"{ans.rrname.decode()} -> {ans.rdata}")
                dns_log_entry = {
                    "time": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "type": "response",
                    "answers": answers
                }
                firewall.dns_logs.append(dns_log_entry)
                print(f"[DNS RESPONSE] {src_ip} ← {answers}")
            except Exception as e:
                print("Error parsing DNS response:", e)

    if packet.haslayer(scapy.IP):
        packet_queue.put(packet)

# Background worker
def process_packets():
    while True:
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer(scapy.IP):
                
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                dns_ip = packet[scapy.DNS]
                protocol = None
                port = None

                if packet.haslayer(scapy.TCP):
                    protocol = "TCP"
                    port = packet[scapy.TCP].dport
                elif packet.haslayer(scapy.UDP):
                    protocol = "UDP"
                    port = packet[scapy.UDP].dport

                if protocol and port:
                    action = "block" if src_ip in firewall.blacklist else firewall.check_firewall_rules(protocol, port)
                    firewall.log_packet(src_ip, dst_ip, protocol, len(packet))
                    if action == "block":
                        print(f"Blocked packet from {src_ip} to {dst_ip} on port {port}")
        except:
            continue

# old code for sniffing: 
# def start_sniffing():
#     scapy.sniff(prn=packet_callback, store=0, iface=get_interface_name())

# new code for sniffing:
def start_sniffing():
    scapy.sniff(prn=packet_callback, store=0, iface=get_interface_name(), filter="ip")

# -------------------------------
def get_interface_name():
    COMMON_INTERFACES = ["Wi-Fi","wlan0", "eth0", "ens33", "eno1", "Ethernet", "Ethernet 2", "Wi-Fi", "Wi-Fi 2", "lo"]
    addresses = psutil.net_if_addrs()
    for interface in COMMON_INTERFACES:
        if interface in addresses:
            return interface
    available_interfaces = list(addresses.keys())
    return available_interfaces[0] if available_interfaces else None

# old code for sniffing_thread:
# sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
# sniffing_thread.start()

# new code for sniffing_thread:
threading.Thread(target=start_sniffing, daemon=True).start()

# Start background threads
threading.Thread(target=start_sniffing, daemon=True).start()
threading.Thread(target=process_packets, daemon=True).start()


# extra function to log packets quickly: 
def quick_log(self, src_ip, dst_ip, protocol, packet_size):
    now = time.time()
    # should comment to see more logs:
    # if now - self.traffic_data[src_ip]["last_time"] < 1:
    #     return  # Skip logging if logged too recently
    self.log_packet(src_ip, dst_ip, protocol, packet_size)

def fast_check(self, ip, protocol, port):
    if ip in self.blacklist:
        return "block"
    return self.check_firewall_rules(protocol, port)

# -------------------------------
# Firewall Class
# -------------------------------
class Firewall:
    def __init__(self):
        self.rules = []
        self.blacklist = {}  # Changed from set to dict to store timestamps
        self.traffic_data = defaultdict(lambda: {"count": 0, "size": 0, "last_time": time.time()})
        self.packet_logs = []
        self.dns_logs = []  # added for DNS logs
        self.setup_db()

    def setup_db(self):
        self.conn = sqlite3.connect("firewall.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                action TEXT
            )
        """)
        self.conn.commit()

    def add_rule(self, rule):
        self.rules.append(rule)

    def remove_rule(self, port):
        self.rules = [rule for rule in self.rules if rule["port"] != int(port)]

    def add_blacklist(self, ip):
        self.blacklist[ip] = time.strftime("%Y-%m-%d %H:%M:%S")

    def remove_blacklist(self, ip):
        if ip in self.blacklist:
            del self.blacklist[ip]

    def is_blocked(self, ip):
        return ip in self.blacklist

    def log_packet(self, src_ip, dst_ip, protocol, packet_size):
        # Don't log packets from blocked IPs
        if src_ip in self.blacklist:
            return
            
        speed = 0
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        current_time = time.time()
        prev_time = self.traffic_data[src_ip]["last_time"]
        interval = max(current_time - prev_time, 1)
        speed = (self.traffic_data[src_ip]["size"] + packet_size) / interval / 1024

        self.traffic_data[src_ip]["count"] += 1
        self.traffic_data[src_ip]["size"] += packet_size
        self.traffic_data[src_ip]["last_time"] = current_time

        log_entry = {
            "time": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "speed": f"{speed:.2f} KB/s"
        }
        self.packet_logs.append(log_entry)
        # added: 
        if len(self.packet_logs) > 500:  # keep recent 500 logs only
            self.packet_logs.pop(0)

# continue with the rest of the code

    def check_firewall_rules(self, protocol, port):
        for rule in self.rules:
            if rule["protocol"] == protocol and rule["port"] == int(port):
                return rule["action"]
        return "allow"

    def detect_anomalies(self):
        df = pd.DataFrame([{"IP": ip, "PacketCount": data["count"]} for ip, data in self.traffic_data.items()])
        if len(df) > 5:
            model = IsolationForest(contamination=0.1)
            df["Anomaly"] = model.fit_predict(df[["PacketCount"]])
            return df[df["Anomaly"] == -1]["IP"].tolist()
        return []

    def generate_live_graph(self):
        plt.figure(figsize=(8, 4))
        ips = list(self.traffic_data.keys())
        packet_counts = [data["count"] for data in self.traffic_data.values()]
        plt.bar(ips, packet_counts, color='blue')
        plt.xlabel("IP Addresses")
        plt.ylabel("Packets Sent")
        plt.title("Live Network Traffic")
        plt.xticks(rotation=45)
        plt.savefig("static/traffic_chart.png")
        plt.close()

# -------------------------------
# Flask Web App
# -------------------------------
app = Flask(__name__)
firewall = Firewall()

# for dashboard:
@app.route("/traffic_overview")
def traffic_overview():
    protocol_counts = {"TCP": 0, "UDP": 0}
    for log in firewall.packet_logs:
        protocol = log.get("protocol")
        if protocol in protocol_counts:
            protocol_counts[protocol] += 1
            print(protocol_counts[protocol]) # added for testing
    return jsonify(protocol_counts)

# traffic_overview()
@app.route("/debug_logs")
def debug_logs():
    return jsonify(firewall.packet_logs[-5:])  # last 10 logs

# new code: 

@app.route("/get_packets", methods=["GET"])
def get_packets():
    # Filter out packets from blocked IPs
    filtered_logs = [log for log in firewall.packet_logs if log["src_ip"] not in firewall.blacklist]
    # Return more logs to show more activity
    return jsonify(filtered_logs[-200:])  # Increased from 100 to 200

@app.route("/get_dns_logs", methods=["GET"])
def get_dns_logs():
    return jsonify(firewall.dns_logs[-100:])  # Only latest 100 for performance

@app.route("/")
def home():
    return render_template("Web.html")

@app.route("/monitor")
def monitor():
    return render_template("monitor.html")

@app.route("/activity")
def activity():
    return render_template("activity.html")

@app.route("/setting")
def setting():
    return render_template("setting.html")

@app.route("/credits")
def credits():
    return render_template("credits.html")

@app.route("/info")
def info():
    return render_template("info.html")

@app.route("/rulesForFirewall")
def rulesForFirewall():
    return render_template("rulesForFirewall.html")


# @app.route("/get_packets", methods=["GET"])
# def get_packets():
#     return jsonify(firewall.packet_logs)

@app.route("/add_rule", methods=["POST"])
def add_rule():
    data = request.json
    firewall.add_rule(data)
    return jsonify({"message": "Rule added successfully!"})

@app.route("/delete_rule", methods=["POST"])
def delete_rule():
    data = request.json
    firewall.remove_rule(data["port"])
    return jsonify({"message": "Rule deleted!"})

@app.route("/add_blacklist", methods=["POST"])
def add_blacklist():
    data = request.json
    firewall.add_blacklist(data["ip"])
    return jsonify({"message": f"IP {data['ip']} added to blacklist."})

@app.route("/remove_blacklist", methods=["POST"])
def remove_blacklist():
    data = request.json
    firewall.remove_blacklist(data["ip"])
    return jsonify({"message": f"IP {data['ip']} removed from blacklist."})

@app.route("/get_blacklist", methods=["GET"])
def get_blacklist():
    return jsonify(list(firewall.blacklist))

@app.route("/logs", methods=["GET"])
def get_logs():
    firewall.cursor.execute("SELECT * FROM logs")
    logs = firewall.cursor.fetchall()
    return jsonify(logs)

@app.route("/get_traffic_data", methods=["GET"])
def get_traffic_data():
    return jsonify(firewall.traffic_data)

@app.route("/detect_anomalies", methods=["GET"])
def detect_anomalies():
    anomalies = firewall.detect_anomalies()
    return jsonify({"anomalous_ips": anomalies})

@app.route("/clear_dns_logs", methods=["POST"]) #clears dns logs:
def clear_dns_logs():
    firewall.dns_logs.clear()
    return jsonify({"message": "DNS logs cleared."})

@app.route("/clear_traffic", methods=["POST"]) #clears traffic data:
def clear_traffic():
    firewall.packet_logs.clear()
    firewall.traffic_data.clear()
    return jsonify({"message": "Traffic reset successfully."})

@app.route('/network_speed')
def network_speed():
    net1 = psutil.net_io_counters()
    time.sleep(1)  # Wait 1 second
    net2 = psutil.net_io_counters()

    # Bytes received and sent in 1 second, converted to Mbps
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    bytes_recv = net2.bytes_recv - net1.bytes_recv

    # Convert bytes/sec to megabits/sec (1 byte = 8 bits, 1e6 = megabit)
    upload_speed = (bytes_sent * 8) / 1e6
    download_speed = (bytes_recv * 8) / 1e6

    return jsonify({
        'upload': round(upload_speed, 2),
        'download': round(download_speed, 2)
    })


# # firewall essential function:
# @app.route("/top_bandwidth_ips")
# def top_bandwidth_ips():
#     data = []
#     # First add all unblocked IPs
#     for ip, info in firewall.traffic_data.items():
#         if ip not in firewall.blacklist:
#             speed = info["size"] / max(time.time() - info["last_time"], 1) / 1024
#             data.append({
#                 "ip": ip,
#                 "count": info["count"],
#                 "speed": round(speed, 2),
#                 "blocked": False
#             })
    
#     # Then add all blocked IPs
#     for ip in firewall.blacklist:
#         if ip in firewall.traffic_data:
#             info = firewall.traffic_data[ip]
#             speed = info["size"] / max(time.time() - info["last_time"], 1) / 1024
#             data.append({
#                 "ip": ip,
#                 "count": info["count"],
#                 "speed": round(speed, 2),
#                 "blocked": True
#             })
    
#     sorted_ips = sorted(data, key=lambda x: x["speed"], reverse=True)
#     return jsonify(sorted_ips)


@app.route("/top_bandwidth_ips")
def top_bandwidth_ips():
    data = []
    for ip, info in firewall.traffic_data.items():
        speed = info["size"] / max(time.time() - info["last_time"], 1) / 1024
        blocked_time = firewall.blacklist.get(ip, None)
        data.append({
            "ip": ip,
            "packets": info["count"],
            "speed": round(speed, 2),
            "blocked": ip in firewall.blacklist,
            "blocked_since": blocked_time if blocked_time else None
        })
    sorted_ips = sorted(data, key=lambda x: x["speed"], reverse=True)
    return jsonify(sorted_ips)

# colors: 
@app.route("/save_settings", methods=["POST"])
def save_settings():
    data = request.json
    # Save settings to a file or database
    with open("settings.json", "w") as f:
        json.dump(data, f)
    return jsonify({"message": "Settings saved successfully"})

@app.route("/get_settings", methods=["GET"])
def get_settings():
    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
        return jsonify(settings)
    except FileNotFoundError:
        # Return default settings if file doesn't exist
        return jsonify({
            "logSize": 200,
            "refreshInterval": 2000,
            "maxConnections": 100,
            "blockDuration": 30,
            "theme": "default",
            "backgroundColor": "#f0f8ff"  # Default light blue color
        })

# -------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)

# investigate: 

# def traffic_overview():
#     protocol_counts = defaultdict(int)
#     for log in firewall.packet_logs:
#         protocol_counts[log["protocol"]] += 1
#     return jsonify(protocol_counts)

# @app.route("/top_ips")
# def top_ips():
#     ip_stats = defaultdict(lambda: {"count": 0, "blocked": 0, "allowed": 0})
#     for log in firewall.packet_logs:
#         src = log["src_ip"]
#         ip_stats[src]["count"] += 1
#         if src in firewall.blacklist:
#             ip_stats[src]["blocked"] += 1
#         else:
#             ip_stats[src]["allowed"] += 1
#     sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["count"], reverse=True)
#     return jsonify(sorted_ips[:5])