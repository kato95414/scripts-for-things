import time
import requests
import pyshark
import json
from collections import defaultdict
from rich import print
from rich.table import Table
from rich.console import Console

# VirusTotal API Configuration
VT_API_KEY = "your_virustotal_api_key"  # Replace with your actual VirusTotal API key
VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Function to check IP reputation via VirusTotal with delay for rate limiting
def check_ip_reputation(ip, last_api_call_time):
    try:
        # Enforce a 15-second delay between API calls
        current_time = time.time()
        if current_time - last_api_call_time < 15:
            time.sleep(15 - (current_time - last_api_call_time))

        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"{VT_BASE_URL}{ip}", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and "attributes" in data["data"] and "last_analysis_stats" in data["data"]["attributes"]:
                analysis = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "harmless": analysis.get("harmless", 0),
                    "malicious": analysis.get("malicious", 0),
                    "suspicious": analysis.get("suspicious", 0),
                    "undetected": analysis.get("undetected", 0)
                }, current_time
        return {"error": f"HTTP {response.status_code}"}, current_time
    except requests.exceptions.RequestException as e:
        print(f"[yellow]Error checking IP {ip} with VirusTotal:[/yellow] {e}")
        return {"error": "API request failed"}, current_time

# Main function
def filter_protocols(pcap_file):
    last_api_call_time = time.time() - 15  # Initialize to ensure immediate first call

    try:
        capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    except FileNotFoundError:
        print(f"[red]Error: The file '{pcap_file}' was not found. Please provide a valid file path.[/red]")
        return
    except Exception as e:
        print(f"[red]An unexpected error occurred while opening the pcap file:[/red] {e}")
        return

    packet_count = 0
    data = {
        'tcp_packets': [],
        'http_requests': [],
        'http_responses': [],
        'dns_queries': [],
        'smtp_packets': [],
        'ftp_commands': [],
        'ssh_packets': [],
        'other_protocols': []
    }

    protocol_counts = defaultdict(int)
    protocol_bytes = defaultdict(int)
    talkers = defaultdict(int)
    destinations = defaultdict(int)
    reputation_results = {"source_ips": {}, "destination_ips": {}}

    try:
        for packet in capture:
            packet_count += 1
            try:
                layers = [layer.layer_name for layer in packet.layers]
                pkt_len = int(packet.length)
                timestamp = packet.sniff_time

                src_ip = getattr(packet.ip, 'src', None) if 'ip' in layers else None
                dst_ip = getattr(packet.ip, 'dst', None) if 'ip' in layers else None

                if src_ip:
                    talkers[src_ip] += 1
                    if src_ip not in reputation_results["source_ips"]:
                        reputation, last_api_call_time = check_ip_reputation(src_ip, last_api_call_time)
                        reputation_results["source_ips"][src_ip] = reputation
                if dst_ip:
                    destinations[dst_ip] += 1
                    if dst_ip not in reputation_results["destination_ips"]:
                        reputation, last_api_call_time = check_ip_reputation(dst_ip, last_api_call_time)
                        reputation_results["destination_ips"][dst_ip] = reputation

                packet_info = {
                    'timestamp': str(timestamp),
                    'packet_length': pkt_len,
                    'layers': layers,
                    'src_ip': src_ip if src_ip else "N/A",
                    'dst_ip': dst_ip if dst_ip else "N/A"
                }

                if 'tcp' in layers:
                    src_port = getattr(packet.tcp, 'srcport', 'Unknown')
                    dst_port = getattr(packet.tcp, 'dstport', 'Unknown')
                    tcp_packet = {
                        'timestamp': packet_info['timestamp'],
                        'packet_length': packet_info['packet_length'],
                        'src_ip': src_ip if src_ip else 'Unknown',
                        'dst_ip': dst_ip if dst_ip else 'Unknown',
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'layers': packet_info['layers']
                    }
                    data['tcp_packets'].append(tcp_packet)
                    protocol_counts['tcp'] += 1
                    protocol_bytes['tcp'] += pkt_len

            except AttributeError as e:
                print(f"[yellow]AttributeError in packet {packet_count}:[/yellow] {e}")
                continue
            except Exception as e:
                print(f"[red]Error processing packet {packet_count}:[/red] {e}")
                continue
    except Exception as e:
        print(f"[red]An error occurred during packet processing:[/red] {e}")
    finally:
        capture.close()

    # Export results to JSON
    try:
        output_data = {
            "protocol_data": data,
            "reputation_results": reputation_results,
            "protocol_counts": dict(protocol_counts),
            "protocol_bytes": dict(protocol_bytes),
            "top_talkers": sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_destinations": sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5],
        }
        with open('protocol_data_with_reputation.json', 'w', encoding='utf-8') as json_file:
            json.dump(output_data, json_file, indent=4)
            print("[green]Data successfully exported to protocol_data_with_reputation.json[/green]")
    except Exception as e:
        print(f"[red]Error exporting results to JSON:[/red] {e}")

    # Print tables and detailed TCP packet report
    try:
        console = Console()

        # Top Talkers Table
        if talkers:
            talker_table = Table(title="Top Source Talkers with Reputation")
            talker_table.add_column("Rank")
            talker_table.add_column("IP")
            talker_table.add_column("Count")
            talker_table.add_column("Malicious")
            talker_table.add_column("Suspicious")
            talker_table.add_column("Harmless")
            talker_table.add_column("Undetected")

            for rank, (ip, count) in enumerate(sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:5], 1):
                reputation = reputation_results["source_ips"].get(ip, {})
                talker_table.add_row(
                    str(rank),
                    ip,
                    str(count),
                    str(reputation.get("malicious", "N/A")),
                    str(reputation.get("suspicious", "N/A")),
                    str(reputation.get("harmless", "N/A")),
                    str(reputation.get("undetected", "N/A"))
                )
            console.print(talker_table)

        # Top Destinations Table
        if destinations:
            dest_table = Table(title="Top Destinations with Reputation")
            dest_table.add_column("Rank")
            dest_table.add_column("IP")
            dest_table.add_column("Count")
            dest_table.add_column("Malicious")
            dest_table.add_column("Suspicious")
            dest_table.add_column("Harmless")
            dest_table.add_column("Undetected")

            for rank, (ip, count) in enumerate(sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5], 1):
                reputation = reputation_results["destination_ips"].get(ip, {})
                dest_table.add_row(
                    str(rank),
                    ip,
                    str(count),
                    str(reputation.get("malicious", "N/A")),
                    str(reputation.get("suspicious", "N/A")),
                    str(reputation.get("harmless", "N/A")),
                    str(reputation.get("undetected", "N/A"))
                )
            console.print(dest_table)

        # Detailed TCP Packet Report
        print("\n[bold cyan]===== Detailed TCP Packet Report =====[/bold cyan]\n")
        for idx, tcp in enumerate(data['tcp_packets'], 1):
            print(f"[{idx}] Timestamp: {tcp['timestamp']}")
            print(f"    Packet Length: {tcp['packet_length']} bytes")
            print(f"    Source: {tcp['src_ip']}:{tcp['src_port']}")
            print(f"    Destination: {tcp['dst_ip']}:{tcp['dst_port']}")
            print(f"    Layers: {', '.join(tcp['layers'])}\n")

    except Exception as e:
        print(f"[red]Error displaying the summary statistics or detailed report:[/red] {e}")


if __name__ == "__main__":
    pcap_file = input("put it in me daddy:").strip()
    filter_protocols(pcap_file)
