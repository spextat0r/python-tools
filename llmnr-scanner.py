import concurrent.futures
import netifaces as ni
import socket, errno
import dns.message
import ipaddress
import dns.query
import readline
import argparse
import random
import sys

color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_reset = '\033[0m'

def is_port_in_use(port, local_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.bind((local_ip, port))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            return True
        else:
            # something else raised the socket.error exception
            print(e)
            return True

    s.close()
    return False

def send_llmnr_query(host, local_ip, debug):
    try:
        # Build the PTR query
        question = 'in-addr.arpa'
        split_address = host.split('.')
        split_address.reverse()
        question = '.'.join(split_address) + '.' + question

        src_port = random.randrange(15000,50000)
        ipiu = is_port_in_use(src_port, local_ip)
        while ipiu:
            src_port = random.randrange(15000, 50000)
            ipiu = is_port_in_use(src_port)

        if debug:
            print('Sending Query for: {} from {}:{}'.format(host, local_ip, src_port))

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN)
        response = dns.query.udp(query, '224.0.0.252', port=5355, timeout=3, source=local_ip, source_port=src_port)

        if response.answer:
            print('Host: {}\nLLMNR Response: {}\n'.format(host,response.answer[0].to_text()))
            return host, response.answer[0].to_text()
        else:
            return host, None
    except Exception as e:
        if debug:
            print('Host: {}\nLLMNR Response: {}\n'.format(host, str(e)))
        return host, str(e)


def parse_hosts_file(hosts_file):
    hosts = []
    try:
        with open(hosts_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    if '/' in line:
                        # Assuming CIDR notation
                        network = ipaddress.ip_network(line, strict=False)
                        hosts.extend(str(ip) for ip in network.hosts())
                    else:
                        hosts.append(line)
        return hosts
    except FileNotFoundError:
        print('The given file does not exist')
        sys.exit(1)


def scan_hosts(hosts, output_file, local_ip, threads, debug):

    with open(output_file, "w") as log_file:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for host in hosts:
                futures.append(executor.submit(send_llmnr_query, host, local_ip, debug))
            for future in concurrent.futures.as_completed(futures):
                host, result = future.result()
                log_file.write(f"Host: {host}\n")
                if result:
                    log_file.write(f"LLMNR response: {result}\n\n")
                else:
                    log_file.write("No LLMNR response\n\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check if hosts are running LLMNR.") # argparse
    parser.add_argument("hosts_file", help="Path to a file containing hosts, either as individual IPs or in CIDR notation.")
    parser.add_argument('-ip', action='store', help='Your local ip or interface')
    parser.add_argument("-o", "--output_file", default="llmnr_scan_log.txt", help="Output file name.")
    parser.add_argument('-t', '--threads', action='store', default=5, type=int, help='Number of threads to use (Default=5)')
    parser.add_argument('-debug', action='store_true', help='Enable debugging')
    args = parser.parse_args()

    hosts = parse_hosts_file(args.hosts_file) # get out hosts from the specified hosts_file

    if args.ip is not None:  # did they give us the local ip in the command line
        local_ip = args.ip
        ifaces = ni.interfaces()
        iface_ips = []

        for face in ifaces: # get all interface ips
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        try:  # check to see if the interface has an ip
            if local_ip in ifaces: # if the given ip is one of our interfaces
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr']) # get the ip address of the interface
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:
                print("local IP => {}\n".format(local_ip))
            else:
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)
    else:
        # print local interfaces and ips
        print("")
        ifaces = ni.interfaces()
        iface_ips = []

        for face in ifaces: # get all interface ips
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        for face in ifaces:
            try:  # check to see if the interface has an ip
                print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ")

        # lets you enter eth0 as the ip
        try:  # check to see if the interface has an ip
            if local_ip in ifaces:
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:
                print("local IP => {}\n".format(local_ip))
            else:
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)


    scan_hosts(hosts, args.output_file, local_ip, args.threads, args.debug)
