import os
import socket
import time
import argparse
import random

def encode_message_to_ttl(message, encoding='ascii'):
    """
    Encodes the given message to a sequence of TTL values.

    encoding='ascii' sets each character's ascii code as TTL.
    encoding='binary' encodes each bit with fixed TTL values.
    encoding='diff' uses differential encoding:
        - The first character is encoded directly as its ascii value.
        - For each subsequent character, calculate two candidate TTLs:
            candidate_add = previous_ttl + ascii_val
            candidate_sub = previous_ttl - ascii_val
        - If both candidates are within the valid TTL range (1 to 255),
          choose between them with equal probability.
        - If only one candidate is valid, that candidate is used.
        - Since printable ascii ranges from 32 to 126 it is guaranteed
          have at least one suitable candidate.
    """
    ttl_values = []
    
    if encoding == 'ascii':
        for char in message:
            ttl = ord(char)
            if ttl < 1 or ttl > 255:
                raise ValueError(f"Character '{char}' has invalid TTL value {ttl}")
            ttl_values.append(ttl)
    
    elif encoding == 'binary':
        # Fixed TTL values for bits
        TTL_ZERO = 64
        TTL_ONE = 128
        for char in message:
            bits = format(ord(char), '08b')
            for bit in bits:
                ttl_values.append(TTL_ONE if bit == '1' else TTL_ZERO)
    
    elif encoding == 'diff':
        if not message:
            return ttl_values
        
        first_ttl = ord(message[0])
        if first_ttl < 1 or first_ttl > 255:
            raise ValueError(f"Character '{message[0]}' has invalid TTL value {first_ttl}")
        ttl_values.append(first_ttl)
        previous_ttl = first_ttl
        
        for char in message[1:]:
            ascii_val = ord(char)

            candidate_add = previous_ttl + ascii_val
            candidate_sub = previous_ttl - ascii_val
            
            valid_add = (candidate_add <= 255)
            valid_sub = (candidate_sub >= 1)
            
            if valid_add and valid_sub:
                if random.random() < 0.5:
                    previous_ttl = candidate_add
                else:
                    previous_ttl = candidate_sub
            elif valid_add:
                previous_ttl = candidate_add
            elif valid_sub:
                previous_ttl = candidate_sub
            else:
                # Not possible
                raise ValueError(f"Cannot encode character '{char}' with ASCII {ascii_val} from previous TTL {previous_ttl}")
            
            ttl_values.append(previous_ttl)
    
    return ttl_values

def udp_sender(ttl_list):
    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    message = "Hello, InSecureNet!"

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        rtt_times = []

        for ttl in ttl_list:

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            # Send message to the server
            sock.sendto(message.encode(), (host, port))
            print(f"Message sent to {host}:{port}")
            start_time = time.time()

            # Receive response from the server
            response, server = sock.recvfrom(4096)
            end_time = time.time()
            rtt = end_time - start_time
            rtt_times.append(rtt)
            print(f"Response from server: {response.decode()} RTT: {rtt}")

            # Sleep for 1 second
            time.sleep(1)

        print(rtt_times)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--message', type=str, default='Hello', help='Secret message to encode')
    parser.add_argument('--encoding', type=str, choices=['ascii', 'binary', 'diff'], default='ascii', help='Encoding method')

    args = parser.parse_args()

    print(f"Encoding message '{args.message}' using '{args.encoding}' encoding...")
    ttl_list = encode_message_to_ttl(args.message, args.encoding)
    print(f"TTL sequence: {ttl_list}")
    udp_sender(ttl_list)