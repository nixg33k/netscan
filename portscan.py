import socket
import threading
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor

def TCP_connect(ip, port_number, delay):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(delay)
            result = sock.connect_ex((ip, port_number))
            if result == 0:
                return port_number, 'Listening'
            else:
                return port_number, ''
    except Exception as e:
        return port_number, str(e)

def scan_ports(host_ip, delay):
    print()
    count = 0
    ports = range(1000)  # Reduced from 10,000 to common ports
    
    t1 = datetime.now()
    newt1 = time.time()

    with ThreadPoolExecutor(max_workers=500) as executor:
        futures = [executor.submit(TCP_connect, host_ip, port, delay) for port in ports]
        
        results = []
        for future in futures:
            try:
                result = future.result(timeout=delay)
                if result[1] == 'Listening':
                    results.append(result)
                    count += 1
            except Exception as e:
                pass
    t2 = datetime.now()
    newt2 = time.time()
    total = t2 - t1

    ms = (newt2 - newt1) * 1000
    print(f'Port Scanning Completed in: {ms:.2f} milliseconds')
    
    if not results:
        print("No open ports")
    else:
        for port, status in sorted(results, key=lambda x: x[0]):
            if status == 'Listening':
                print(f"{port}: {status}")
    print(f"Total ports found open: {count}")

if __name__ == "__main__":
    host = input("Enter target IP or hostname: ")
    delay = int(input("Enter timeout in seconds: "))
    scan_ports(host, delay)
