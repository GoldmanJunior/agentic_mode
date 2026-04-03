import random
import datetime


def generer_ip_aleatoire():
    """
    Génère une adresse IPv4 aléatoire valide.
    Chaque octet est compris entre 0 et 255.
    """
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_network_event(event_type):
    '''Génère un événement réseau'''

    if event_type == "normale":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        num_bytes = random.randint(100, 5000)
        packets = random.randint(1, 50)
        port = random.randint(1, 65535)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "normale"
        }
    elif event_type == "port_scan":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        port = random.randint(1, 65535)
        num_bytes = random.randint(40, 200)
        packets = random.randint(1, 50)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "port_scan"
        }
    elif event_type == "ddos":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        num_bytes = random.randint(50000, 500000)
        port = random.randint(1, 65535)
        packets = random.randint(1000, 10000)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "ddos"
        }
    elif event_type == "brute_force":
        timestamp = datetime.datetime.now().isoformat()
        src_ip=generer_ip_aleatoire()
        dst_ip=generer_ip_aleatoire()
        num_bytes = random.randint(100, 5000)
        packets = random.randint(1000, 10000)
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": 22,
            "protocol": "TCP",
            "bytes": num_bytes,
            "packets": packets,
            "event_type": "brute_force"
        }
    else:
        raise ValueError("Type d'événement inconnu")
    
def run_collecte_agent(event_type):
    '''Simule la collecte d'événements réseau'''
    event = generate_network_event(event_type)
    return event