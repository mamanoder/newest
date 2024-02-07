def start_scan(program_port = 8888):
    open_ports = []
    threads = []
    num = 20
    if program_port == None:
        program_port = 999999
    for port in range(1, 65535 - num, num):
        if port > program_port or port+20 < program_port:
            print(f"Port {port} to port {port+20}")
            # scan_thread = Thread(target=scan_ports, args=(port, ip, result_text, open_ports, num, is_GUI))
            # threads.append(scan_thread)
        else:
            print(f"Port {port} is")
            need = program_port - port -1
            new_port = port + need + 2
            # scan_thread = Thread(target=scan_ports, args=(port, ip, result_text, open_ports, need, is_GUI))
            num = num - need - 1
            print(f"scan from {port} to {port + need} and from {new_port} to {new_port+num}")
            # scan_thread2 = Thread(target=scan_ports, args=(port, ip, result_text, open_ports, num, is_GUI))
            # threads.append(scan_thread)
            # scan_thread2.start()
start_scan()