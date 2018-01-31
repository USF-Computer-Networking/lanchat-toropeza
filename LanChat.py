from threading import Thread

from scapy.all import *

found_ips = []

server_port = 8080
client_port = 8081
server_info = ("localhost", server_port)
client_info = ("localhost", client_port)

def arp_found(packet):
    found_ip = packet[0][ARP].psrc
    if found_ip not in found_ips:
        found_ips.append(found_ip)
        print "Found IP" + found_ip

def run_sniff():
    sniff(filter="arp",prn=arp_found)

def send_message(message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.sendto(message, server_info)
    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(server_info)

    while True:
        message, client = server_socket.recvfrom(client_port)
        print "Received message: " + message

def usage():
    print "Available actions"
    print "     -h (Help)"
    print "     scan (Scans the LAN for ARP messages and displays their Src Ips)"
    print "     message <message> (Sends the given message to a running LanChat Server)"
    print "     server (Starts a LanChat Server)"

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    action = sys.argv[1]

    if action == "-h":
        usage()
    elif action == "scan":
        run_sniff()
    elif action == "message":
        if (len(sys.argv) < 3):
            usage()
            sys.exit(1)
        message = sys.argv[2]
        send_message(message)
    elif sys.argv[1] == "server":
        start_server()
    else:
        usage()
        sys.exit(1)