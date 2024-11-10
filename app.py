from flask_socketio import SocketIO, emit
from flask import Flask, render_template, request
from scapy.sendrecv import sniff
import json
import ipaddress
from urllib.request import urlopen
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

# Initialize SocketIO with CORS enabled
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Rest of the PacketInfo class and other functions remain the same...
class PacketInfo:
    def __init__(self):
        self.src = ""
        self.src_port = 0
        self.dest = ""
        self.dest_port = 0
        self.protocol = ""
        self.timestamp = 0
        self.payload_bytes = 0
        self.header_bytes = 0
        self.packet_size = 0

    def setDest(self, p):
        try:
            self.dest = p["IP"].dst
        except:
            self.dest = None

    def setSrc(self, p):
        try:
            self.src = p["IP"].src
        except:
            self.src = None

    def setSrcPort(self, p):
        try:
            self.src_port = p.sport
        except:
            self.src_port = None

    def setDestPort(self, p):
        try:
            self.dest_port = p.dport
        except:
            self.dest_port = None

    def setProtocol(self, p):
        try:
            self.protocol = p.proto
        except:
            self.protocol = None

    def setTimestamp(self, p):
        try:
            self.timestamp = p.time
        except:
            self.timestamp = None

    def setPayloadBytes(self, p):
        try:
            self.payload_bytes = len(p.payload)
        except:
            self.payload_bytes = 0

    def setHeaderBytes(self, p):
        try:
            self.header_bytes = len(p) - len(p.payload)
        except:
            self.header_bytes = 0

    def setPacketSize(self, p):
        try:
            self.packet_size = len(p)
        except:
            self.packet_size = 0

def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        data = json.load(res)
        return data['country']
    except Exception:
        return None

packet_count = 0

def process_packet(packet):
    try:
        global packet_count
        packet_count += 1
        
        pkt_info = PacketInfo()
        pkt_info.setDest(packet)
        pkt_info.setSrc(packet)
        pkt_info.setSrcPort(packet)
        pkt_info.setDestPort(packet)
        pkt_info.setProtocol(packet)
        pkt_info.setTimestamp(packet)
        pkt_info.setPayloadBytes(packet)
        pkt_info.setHeaderBytes(packet)
        pkt_info.setPacketSize(packet)

        packet_details = {
            'id': packet_count,
            'src': pkt_info.src,
            'src_port': pkt_info.src_port,
            'dest': pkt_info.dest,
            'dest_port': pkt_info.dest_port,
            'protocol': pkt_info.protocol,
            'size': pkt_info.packet_size,
            'timestamp': pkt_info.timestamp
        }

        # Add country flags for non-private IPs
        for ip_field in ['src', 'dest']:
            ip = packet_details[ip_field]
            if ip and not ipaddress.ip_address(ip).is_private:
                country = ipInfo(ip)
                if country and country not in ['ano', 'unknown']:
                    flag = f'<img src="static/images/blank.gif" class="flag flag-{country.lower()}" title="{country}">'
                else:
                    flag = '<img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
            else:
                flag = '<img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
            packet_details[f'{ip_field}_flag'] = flag

        socketio.emit('newpacket', {'packet': packet_details})

    except:
        traceback.print_exc()

def start_capture():
    sniff(prn=process_packet, store=0)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def test_connect():
    print('Client connected')
    socketio.start_background_task(start_capture)

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)