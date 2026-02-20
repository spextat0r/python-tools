# Designed and tested with python 3.11.8 on Kali Linux 6.6.9 also works on python 3.11.6, and 3.12.0 on Kali Linux 6.3.0 and Windows 10 Pro 10.0.19045
# windows interface selection gives guids instead of names for some reason??? Still gives the correct ip tho

import concurrent.futures
import socket, errno
import ipaddress
import binascii
import readline
import argparse
import random
import sys
import os
import re


try:
    import netifaces as ni
except ModuleNotFoundError:
    print('Error: You need to install netifaces\nInstall with "pip3 install netifaces" or "python3 -m pip install netifaces"')
    sys.exit(1)

try:
    import pandas as pd
except ModuleNotFoundError:
    print('Error: You need to install pandas\nInstall with "pip3 install pandas" or "python3 -m pip install pandas"')
    sys.exit(1)

try:
    import dns.message
    import dns.query
except ModuleNotFoundError:
    print('Error: You need to install dnspython\nInstall with "pip3 install dnspython" or "python3 -m pip install dnspython"')
    sys.exit(1)

try:
    import openpyxl # weird dependency for pandas that did not install when I tested a clean python distro and installed pandas but pandas needs it sooo
except ModuleNotFoundError:
    print('Error: You need to install openpyxl\nInstall with "pip3 install openpyxl" or "python3 -m pip install openpyxl"')
    sys.exit(1)


# colors
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_reset = '\033[0m'
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)


logo =r"""
 _____            __  __ _      __                 
/__   \_ __ __ _ / _|/ _(_) ___/ _\ ___ __ _ _ __  
  / /\/ '__/ _` | |_| |_| |/ __\ \ / __/ _` | '_ \ 
 / /  | | | (_| |  _|  _| | (___\ \ (_| (_| | | | |
 \/   |_|  \__,_|_| |_| |_|\___\__/\___\__,_|_| |_|

"""

def llmnr_log(ip, hostname):
    with open('llmnr.hosts', 'a') as f:
        f.write('{} {}\n'.format(ip, hostname))
        f.close()


def mdns_log(ip, hostname):
    with open('mdns.hosts', 'a') as f:
        f.write('{} {}\n'.format(ip, hostname))
        f.close()


def netbios_log(ip, hostname):
    with open('netbios.hosts', 'a') as f:
        f.write('{} {}\n'.format(ip, hostname))
        f.close()

def read_hosts(file_name):
    try:
        with open(file_name, 'r') as file:
            hosts = file.read().strip().split('\n')
        return hosts
    except FileNotFoundError:
        return ['']

def output_xlsx(outfile):
    ILLEGAL_CHARACTERS_RE = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')
    # the code below adds an xlsx file because someone wanted it added
    # Read the host files for each protocol
    llmnr_hosts = read_hosts('llmnr.hosts')
    mdns_hosts = read_hosts('mdns.hosts')
    netbios_hosts = read_hosts('netbios.hosts')

    # Find the longest list to ensure the DataFrame is fully populated without missing values
    max_length = max(len(llmnr_hosts), len(mdns_hosts), len(netbios_hosts))

    # Extend shorter lists with empty strings to match the longest list
    llmnr_hosts.extend([''] * (max_length - len(llmnr_hosts)))
    mdns_hosts.extend([''] * (max_length - len(mdns_hosts)))
    netbios_hosts.extend([''] * (max_length - len(netbios_hosts)))

    # Create a DataFrame
    df = pd.DataFrame({
        'LLMNR': llmnr_hosts,
        'NetBIOS': netbios_hosts,
        'mDNS': mdns_hosts
    })
    df = df.map(lambda x: ILLEGAL_CHARACTERS_RE.sub('', x) if isinstance(x, str) else x)
    # Save to an Excel file
    df.to_excel('{}.xlsx'.format(outfile), index=False)


def is_port_in_use(port, local_ip):  # function to check if a port is in use
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


def send_mdns_query(host, local_ip, timeout, debug):
    try:
        question = 'in-addr.arpa'
        split_address = host.split('.')
        split_address.reverse()
        question = '.'.join(split_address) + '.' + question  # this changes the ip to a reversed form so 10.1.20.3 goes to 3.20.1.10.in-addr.arpa

        src_port = random.randrange(15000, 50000)  # get a random port
        ipiu = is_port_in_use(src_port, local_ip)
        while ipiu:  # ensure the port is not in use
            src_port = random.randrange(15000, 50000)
            ipiu = is_port_in_use(src_port)

        if debug:  # debug prints
            print('Sending MDNS Query for: {}:5353 from {}:{}'.format(host, local_ip, src_port))

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN)  # make our dns query
        response = dns.query.udp(query, host, port=5353, timeout=timeout, source=local_ip, source_port=src_port)  # send the query

        if response.answer:  # if the query came back then there is mdns in the environment
            try:
                if response.answer[0].to_text().split(' ')[4].endswith('.'):
                    mdns_log(host, ''.join(response.answer[0].to_text().split(' ')[4].rsplit('.local.', 1)))  # log the host ip
                else:
                    mdns_log(host, response.answer[0].to_text().split(' ')[4])
            except IndexError:
                mdns_log(host, '')

            if debug:  # if we are debugging give the actual mdns response
                return 'MDNS Response: {}\n'.format(response.answer[0].to_text())
            else:  # otherwise just return yes
                return 'MDNS:'.ljust(10) + '{}YES{}\n'.format(color_RED, color_reset)
        else:  # if we did not get a response then mdns is closed
            return 'MDNS:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)
    except Exception as e:  # an exception occurred
        if debug:  # if were debugging give verbose error
            return 'MDNS Response: {}\n'.format(str(e))
        else:  # otherwise it is likely that mdns is closed
            return 'MDNS:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)


def send_llmnr_query(host, local_ip, timeout, debug):
    try:
        # Build the PTR query
        question = 'in-addr.arpa'
        split_address = host.split('.')
        split_address.reverse()
        question = '.'.join(split_address) + '.' + question  # this changes the ip to a reversed form so 10.1.20.3 goes to 3.20.1.10.in-addr.arpa

        src_port = random.randrange(15000, 50000)  # get a random port for src
        ipiu = is_port_in_use(src_port, local_ip)
        while ipiu:  # ensure the port is not in use
            src_port = random.randrange(15000, 50000)
            ipiu = is_port_in_use(src_port)

        if debug:  # verbose debugging
            print('Sending LLMNR Query for: {}:5355 from {}:{}'.format(host, local_ip, src_port))

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN)  # make our dns query
        response = dns.query.udp(query, '224.0.0.252', port=5355, timeout=timeout, source=local_ip, source_port=src_port)  # send the dns query to the victim

        if response.answer:  # if we got a response llmnr is present on the host
            try:
                if response.answer[0].to_text().split(' ')[4].endswith('.'):
                    llmnr_log(host, ''.join(response.answer[0].to_text().split(' ')[4].rsplit('.', 1)))  # log the host ip
                else:
                    llmnr_log(host, response.answer[0].to_text().split(' ')[4])
            except IndexError:
                llmnr_log(host, '')
            if debug:  # if we are debugging give the actual llmnr response
                return 'LLMNR Response: {}\n'.format(response.answer[0].to_text())
            else:  # if were not debugging just return yes
                return 'LLMNR:'.ljust(10) + '{}YES{}\n'.format(color_RED, color_reset)
        else:  # if no response was given then llmnr is closed
            return 'LLMNR:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)
    except Exception as e:  # we got an error
        if debug:  # if were debugging give the actual error
            return 'LLMNR Response: {}\n'.format(str(e))
        else:  # otherwise just return no as llmnr is likely closed
            return 'LLMNR:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)


def netbios_scan(host, timeout, debug):  # scan for netbios using nbtscan
    # NetBIOS-NS packet structure: Transaction ID, Flags, Questions, Answer RRs, Authority RRs, Additional RRs, Name, Type, Class, TTL, Length, Number of names
    message = b'\x00\x00' + b'\x00\x10' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00' + b'\x00\x21' + b'\x00\x01'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # make a socket connection with out message
    sock.settimeout(timeout)

    try:
        sock.sendto(message, (host, 137))
        data = sock.recvfrom(1024)
        data = data[0]  # we are returned a list and the first item is the actual response
    except socket.timeout:  # if we hit the timeout then the host is likely not running netbios
        sock.close()
        if debug:  # verbose output
            return f"Timeout during communication with {host}\n"
        else:
            return '{}NO{}\n'.format(color_GRE, color_reset)

    except Exception as e:  # if we get a generic error
        sock.close()
        if debug:  # verbose output
            return f"Error during communication: {e}\n"
        else:
            return '{}NO{}\n'.format(color_GRE, color_reset)

    else:
        sock.close()  # close the socket connection

        # Parse response
        if len(data) < 57:  # Basic validation
            output = "Invalid response length\n"

        if debug:
            print(data)

        posdata = []
        # The NetBIOS Name
        try:  # try to decode with ascii if that fails try utf-8 otherwise return an error
            try: # dumb way to be smart since each pos starts at 57 and is 15 bytes in length with 3 for padding we add 18 and do the next, check for msbrowse and workgroup then find the longest
                pos1 = data[57:57 + 15].decode('ascii').strip()
                if '__MSBROWSE__' not in pos1 and 'WORKGROUP' not in pos1:
                    posdata.append(pos1)
            except Exception:
                pos1 = None

            try:
                pos2 = data[75:75 + 15].decode('ascii').strip()
                if '__MSBROWSE__' not in pos2 and 'WORKGROUP' not in pos2:
                    posdata.append(pos2)
            except Exception:
                pos2 = None

            try:
                pos3 = data[93:93 + 15].decode('ascii').strip()
                if '__MSBROWSE__' not in pos3 and 'WORKGROUP' not in pos3:
                    posdata.append(pos3)
            except Exception:
                pos3 = None

            netbiosname = max(posdata, key=len)

        except UnicodeDecodeError:  # try a different decoding if ascii fails

            posdata = []
            # The NetBIOS Name
            try:  # try to decode with ascii if that fails try utf-8 otherwise return an error
                try: # dumb way to be smart since each pos starts at 57 and is 15 bytes in length with 3 for padding we add 18 and do the next, check for msbrowse and workgroup then find the longest
                    pos1 = data[57:57 + 15].decode('utf-8').strip()
                    if '__MSBROWSE__' not in pos1 and 'WORKGROUP' not in pos1:
                        posdata.append(pos1)
                except Exception:
                    pos1 = None

                try:
                    pos2 = data[75:75 + 15].decode('utf-8').strip()
                    if '__MSBROWSE__' not in pos2 and 'WORKGROUP' not in pos2:
                        posdata.append(pos2)
                except Exception:
                    pos2 = None

                try:
                    pos3 = data[93:93 + 15].decode('utf-8').strip()
                    if '__MSBROWSE__' not in pos3 and 'WORKGROUP' not in pos3:
                        posdata.append(pos3)
                except Exception:
                    pos3 = None

                netbiosname = max(posdata, key=len)

            except UnicodeDecodeError:
                netbiosname = 'Failed to decode'
            except Exception as e:
                netbiosname = 'Unable to parse due to: {}'.format(str(e))
        except Exception as e:
            netbiosname = 'Unable to parse due to: {}'.format(str(e))

        # MAC address starts at byte 57+15+2=74, 6 bytes long
        try:
            macaddress = binascii.hexlify(data[74:80]).decode('ascii')
            macaddress_formatted = ':'.join(macaddress[i:i + 2] for i in range(0, len(macaddress), 2))
        except UnicodeDecodeError:
            try:  # try to decode with ascii if that fails try utf-8 otherwise return an error
                macaddress = binascii.hexlify(data[74:80]).decode('utf-8')
                macaddress_formatted = ':'.join(macaddress[i:i + 2] for i in range(0, len(macaddress), 2))
            except UnicodeDecodeError:
                macaddress_formatted = 'Failed to decode'
            except Exception:
                netbiosname = 'Unable to parse'
        except Exception:
            netbiosname = 'Unable to parse'

        if debug:
            output = f"NetBIOS Name: '{netbiosname}'" + f" MAC Address: '{macaddress_formatted}'\n"
        else:
            output = '{}YES{}\n'.format(color_RED, color_reset)

        netbios_log(host, netbiosname)
        return output


def mt_execute(host, local_ip, timeout, debug):  # allows for multithreading

    out_data = ''  # initialize our string
    out_data += 'Host: {}\n'.format(host)  # print the host ip
    out_data += send_llmnr_query(host, local_ip, timeout, debug)  # check llmnr
    out_data += 'NetBIOS:'.ljust(10) + '{}'.format(netbios_scan(host, timeout, debug))  # check netbios
    out_data += send_mdns_query(host, local_ip, timeout, debug)  # check mdns
    return out_data


def parse_hosts_file(hosts_file):  # parse our host file
    hosts = []
    if os.path.isfile(hosts_file): # ensure the file exists otherwise try it as if they passed an ip or cidr to the command line
        try:
            with open(hosts_file, 'r') as file: # read the file
                for line in file:
                    line = line.strip()
                    if line:
                        if '/' in line: # this is so we can have cidr and ips in the same file
                            # Assuming CIDR notation
                            network = ipaddress.ip_network(line, strict=False) # black magic
                            hosts.extend(str(ip) for ip in network.hosts())
                        else:
                            hosts.append(line)
                file.close()
            hosts = list(set(hosts)) # unique the hosts
            return hosts
        except FileNotFoundError:
            print('The given file does not exist')
            sys.exit(1)
    else:
        try:
            if '/' in hosts_file:
                # Assuming CIDR notation
                network = ipaddress.ip_network(hosts_file, strict=False)
                hosts.extend(str(ip) for ip in network.hosts())
            else:
                hosts.append(hosts_file)
        except Exception as e:
            print(e)
            print('Error: there is something wrong with the ip you gave')
            sys.exit(1)
        hosts = list(set(hosts))  # unique the hosts
        return hosts


def scan_hosts(hosts, output_file, local_ip, threads, timeout, debug):  # scan our hosts with multithreading

    with open(output_file, "w") as log_file:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for host in hosts:
                if host != local_ip:  # ensure we dont scan ourself
                    futures.append(executor.submit(mt_execute, host, local_ip, timeout, debug))
            count = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                print(result)
                log_file.write(result + '\n')
                if count % threads == 0:  # print the completion percentage
                    print('{} {} Complete\n'.format(gold_plus, (str(round((count / len(futures)) * 100, 2)) + '%').ljust(6)))
                count += 1


def check_write_perms():  # checks if we can write to the location that our logs end up to ensure there are no errors
    try:
        with open('test_xzngfejwoeigj11jw', 'w') as f:
            f.write('1')
            f.close()
    except PermissionError:
        print('Permission Error you likely just need to run this as sudo')
        sys.exit(1)
    else:
        os.remove('test_xzngfejwoeigj11jw')


if __name__ == "__main__":

    if os.name == 'nt':
        os.system('')
    print(logo)
    parser = argparse.ArgumentParser(description="Check if hosts are running LLMNR.")  # argparse
    parser.add_argument("hosts_file", help="Path to a file containing hosts, either as individual IPs or in CIDR notation. You can also just put an ip or cidr range here ex 10.10.10.10")
    parser.add_argument('-ip', action='store', help='Your local ip or interface')
    parser.add_argument("-o", "--output_file", default="scan_log.txt", help="Output file name for the log and xlsx file. (Default=scan_log.txt)")
    parser.add_argument('-t', '--threads', action='store', default=5, type=int, help='Number of threads to use. (Default=5)')
    parser.add_argument('-timeout', action='store', default=3, type=int, help='Timeout for each test in seconds. (Default=3)')
    parser.add_argument('-debug', action='store_true', help='Enable debugging')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    hosts = parse_hosts_file(args.hosts_file)  # get out hosts from the specified hosts_file

    check_write_perms() # ensure the tool can write its log files to the current path

    if os.path.isfile('llmnr.hosts') or os.path.isfile('mdns.hosts') or os.path.isfile('netbios.hosts') or os.path.isfile(args.output_file) or os.path.isfile(args.output_file + '.xlsx'):
        yon = input('[!] WARNING: The log files from a previous scan are present and this WILL add them to the current scans output I HIGHLY recommend removing them Y/n: ')
        if yon.lower() == 'y':
            files_to_remove = ['llmnr.hosts', 'mdns.hosts', 'netbios.hosts', args.output_file, args.output_file + '.xlsx']
            for file in files_to_remove:
                try:
                    os.remove(file)
                    print('Removed {}'.format(file))
                except Exception:
                    continue

    if args.ip is not None:  # did they give us the local ip in the command line
        local_ip = args.ip
        ifaces = ni.interfaces()
        iface_ips = []

        for face in ifaces:  # get all interface ips
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        try:  # check to see if the interface has an ip
            if local_ip in ifaces:  # if the given ip is one of our interfaces eg. eth0 ,ensp01
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])  # get the ip address of the interface
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips: # if they gave us an ip address for -ip eg 10.10.10.10 this ensures that it is our IP were binding to
                print("local IP => {}\n".format(local_ip))
            else: # if they gave us something incorrect/weird
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc: # if the given interface has no ip we end up here
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)
    else: # no -ip in args
        # print local interfaces and ips
        ifaces = ni.interfaces() # get all interfaces
        iface_ips = []

        for face in ifaces:  # get the ip for each interface that has one
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        for face in ifaces:
            try:  # check to see if the interface has an ip
                print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr'])) # print(interface:      IP)
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ") # what do they want for their interface

        # lets you enter eth0 as the ip
        try:  # check to see if the interface has an ip
            if local_ip in ifaces: # if they gave us an interface eg eth0 or ensp01 ensure its ours
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips: # if they gave us an ip ensure its ours
                print("local IP => {}\n".format(local_ip))
            else: # if they gave us something incorrect/weird
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc: # if they give an interface that has no IP we end up here
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)

    print('Total Target Hosts: {}\n'.format(len(hosts)))

    scan_hosts(hosts, args.output_file, local_ip, args.threads, args.timeout, args.debug) # scan em
    output_xlsx(args.output_file) # give an excel sheet
