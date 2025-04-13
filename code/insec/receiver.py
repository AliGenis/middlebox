import socket, os
import struct
import argparse

def start_udp_listener(encoding):
    # Raw socket for TTL extraction
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    # Bind the socket to the port
    server_address = ( '', 8888)
    sock.bind(server_address)

    print("UDP listener started on port 8888")
    
    received_message = ""
    binary_buffer = ""

    # For binary decoding (example: TTL=64 => 0, TTL=128 => 1)
    TTL_ZERO = 64
    TTL_ONE = 128
    BITS_PER_CHAR = 8
    prev_ttl = -1
    # Regular socket for sending UDP acknowledgments (to be sure)
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        packet, addr = sock.recvfrom(4096)
        
        # IP header
        ip_header = packet[:20]

        # Unpack IP header (20 bytes)
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # TTL is the 6th element in IP header
        ttl = iph[5]

        sender_ip = socket.inet_ntoa(iph[8])

        # UDP header
        udp_header = packet[20:28]
        udph = struct.unpack('!HHHH', udp_header)
        source_port = udph[0]
        
        # Data from UDP packet
        udp_length = udph[2]
        data = packet[28:28+udp_length]

        try:
            decoded_data = data.decode()
        except UnicodeDecodeError:
            decoded_data = "<Non-text payload>"

        print(f"Packet from {addr[0]}:{udph[0]} with TTL={ttl}, Payload='{decoded_data}'")

        # Reconstruct covert message
        if encoding == 'ascii':
            if 32 <= ttl <= 126: # Printable ascii range
                char = chr(ttl)
                received_message += char
                print(f"Decoded character: '{char}' -> Current Message: '{received_message}'")
            else:
                print(f"TTL {ttl} not a printable ASCII character.")

        elif encoding == 'binary':
            if ttl == TTL_ZERO:
                binary_buffer += '0'
            elif ttl == TTL_ONE:
                binary_buffer += '1'
            else:
                print(f"Unexpected TTL={ttl} for binary encoding, skipped.")
                continue

            # Convert every 8 bits into a char
            if len(binary_buffer) >= BITS_PER_CHAR:
                byte = binary_buffer[:BITS_PER_CHAR]
                binary_buffer = binary_buffer[BITS_PER_CHAR:]
                char = chr(int(byte, 2))
                received_message += char
                print(f"Binary Decoded char '{char}' from bits '{byte}' → Message so far: '{received_message}'")
        
        elif encoding == 'diff':
            if prev_ttl == -1 and 32 <= ttl <= 126:
                char = chr(ttl)
                received_message += char
                prev_ttl = ttl
                print(f"Decoded character: '{char}' -> Current Message: '{received_message}'")
            elif prev_ttl != -1:
                char = chr(abs(ttl - prev_ttl))
                received_message += char
                prev_ttl = ttl
                print(f"Decoded character: '{char}' -> Current Message: '{received_message}'")
            else:
                print(f"First TTL {ttl} not a printable ASCII character.")



        ack_message = "Hi SecureNet!".encode()
        ack_sock.sendto(ack_message, (sender_ip, source_port))
        print(f"Sent ACK to {sender_ip}:{source_port}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TTL-based covert channel receiver')
    parser.add_argument('--encoding', type=str, choices=['ascii', 'binary', 'diff'], default='ascii', help='Encoding used by sender')
    args = parser.parse_args()

    start_udp_listener(encoding=args.encoding)
