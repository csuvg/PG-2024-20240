import pyshark
import os
import csv
import ipaddress
from collections import defaultdict
from datetime import datetime

# Función para determinar si una IP es local
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Verifica si la IP está en un rango privado
        return ip_obj.is_private
    except ValueError:
        return False
    

def process_connections(packets):
    connections = defaultdict(lambda: {
        'start_time': None,
        'end_time': None,
        'orig_pkts': 0,
        'orig_ip_bytes': 0,
        'resp_pkts': 0,
        'resp_ip_bytes': 0,
        'tunnel_parents': set()
    })

    for packet in packets:
        if packet:
            conn_id = (packet['id.orig_h'], packet['id.orig_p'], packet['id.resp_h'], packet['id.resp_p'], packet['proto'])
            reverse_conn_id = (packet['id.resp_h'], packet['id.resp_p'], packet['id.orig_h'], packet['id.orig_p'], packet['proto'])

            if connections[conn_id]['start_time'] is None:
                connections[conn_id]['start_time'] = packet['ts']
            connections[conn_id]['end_time'] = packet['ts']

            if conn_id in connections:
                connections[conn_id]['orig_pkts'] += 1
                connections[conn_id]['orig_ip_bytes'] += int(packet['orig_bytes'])
            if reverse_conn_id in connections:
                connections[reverse_conn_id]['resp_pkts'] += 1
                connections[reverse_conn_id]['resp_ip_bytes'] += int(packet['orig_bytes'])

            # Identificación de túneles
            if 'ip' in packet:
                if hasattr(packet.ip, 'tunnel'):
                    connections[conn_id]['tunnel_parents'].add(packet.ip.tunnel)
                if hasattr(packet.ip, 'encap_limit'):
                    connections[conn_id]['tunnel_parents'].add('encap_limit')
                if hasattr(packet.ip, 'ipsec_spi'):
                    connections[conn_id]['tunnel_parents'].add('ipsec_spi')

                

    return connections

# Función para capturar paquetes
def capture_packets(interface='eth0', packet_count=10):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(packet_count=packet_count)
    return capture

# Función para extraer características de cada paquete
def extract_packet_features(packet):
    try:
        ts = packet.sniff_time
        uid = packet.number
        id_orig_h = packet.ip.src if 'IP' in packet else ''
        id_orig_p = packet[packet.transport_layer].srcport if packet.transport_layer in packet else ''
        id_resp_h = packet.ip.dst if 'IP' in packet else ''
        id_resp_p = packet[packet.transport_layer].dstport if packet.transport_layer in packet else ''
        proto = packet.transport_layer if 'IP' in packet else ''
        service = packet.highest_layer
        duration = '' 
        orig_bytes = packet.length
        resp_bytes = packet.get_multiple_fields(['http.content_length', 'data.len'])[0] if 'HTTP' in packet else ''
        conn_state = 'S0'  
        local_orig = is_local_ip(id_orig_h)
        local_resp = is_local_ip(id_resp_h)
        missed_bytes = ''  
        history = ''  
        orig_pkts = ''  
        orig_ip_bytes = ''  
        resp_pkts = '' 
        resp_ip_bytes = ''  
        tunnel_parents = ''  
        label = ''  
        detailed_label = '' 
        
        features = {
            'ts': ts,
            'uid': uid,
            'id.orig_h': id_orig_h,
            'id.orig_p': id_orig_p,
            'id.resp_h': id_resp_h,
            'id.resp_p': id_resp_p,
            'proto': proto,
            'service': service,
            'duration': duration,
            'orig_bytes': orig_bytes,
            'resp_bytes': resp_bytes,
            'conn_state': conn_state,
            'local_orig': local_orig,
            'local_resp': local_resp,
            'missed_bytes': missed_bytes,
            'history': history,
            'orig_pkts': orig_pkts,
            'orig_ip_bytes': orig_ip_bytes,
            'resp_pkts': resp_pkts,
            'resp_ip_bytes': resp_ip_bytes,
            'tunnel_parents': tunnel_parents,
            'label': label,
            'detailed-label': detailed_label
        }
        return features
    except AttributeError:
        return None
    
# Función para escribir los resultados en un archivo CSV
def write_to_csv(packet_features, filename='capturado.csv'):
    # Obtener la ruta del directorio donde está el script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Construir la ruta completa para guardar el archivo
    filepath = os.path.join(script_dir, filename)
    
    with open(filepath, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for features in packet_features:
            if features:
                writer.writerow(features)


# Capturar paquetes y extraer características
packets = capture_packets(interface='Wi-Fi', packet_count=10)
packet_features = [extract_packet_features(packet) for packet in packets if packet]

# Procesar conexiones para calcular duración, orig_pkts y orig_ip_bytes
connections = process_connections(packet_features)

# Agregar características calculadas a cada paquete
for packet in packet_features:
    if packet:
        conn_id = (packet['id.orig_h'], packet['id.orig_p'], packet['id.resp_h'], packet['id.resp_p'], packet['proto'])
        connection = connections[conn_id]
        packet['duration'] = (connection['end_time'] - connection['start_time']).total_seconds() if connection['end_time'] and connection['start_time'] else ''
        packet['orig_pkts'] = connection['orig_pkts']
        packet['orig_ip_bytes'] = connection['orig_ip_bytes']
        packet['resp_pkts'] = connection['resp_pkts']
        packet['resp_ip_bytes'] = connection['resp_ip_bytes']
        packet['tunnel_parents'] = list(connection['tunnel_parents']) if connection['tunnel_parents'] else None

        # Verifica el valor de 'proto' y asigna True/False a 'tcp' y 'udp'
        if packet['proto'] == 'TCP':
            packet['tcp'] = True
            packet['udp'] = False
        elif packet['proto'] == 'UDP':
            packet['tcp'] = False
            packet['udp'] = True
        else:
            packet['tcp'] = False
            packet['udp'] = False

        # Eliminar la columna 'proto'
        packet.pop('proto', None)


keys_to_remove = ['history', 'label', 'detailed-label', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes', 'tunnel_parents', 'local_resp', 'local_orig']  # Lista de claves que quieres eliminar

for features in packet_features:
    if features:
        for key in keys_to_remove:
            features.pop(key, None) 

# Especifica las nuevas columnas en el archivo CSV
fieldnames = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
    'conn_state', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tcp', 'udp'
]


# Escribir las características de los paquetes en un archivo CSV
write_to_csv(packet_features)


