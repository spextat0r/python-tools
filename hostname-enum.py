# this tool attempts to get a hostname from an IP using several methods that work for most hosts in a Windows environment.

from impacket.smbconnection import SMBConnection
import concurrent.futures
import netifaces as ni
import dns.message
import dns.query
import ipaddress
import readline
import argparse
import sys, os
import logging
import socket


def get_local_ip(i=None):
    if i is not None:  # did they give us the local ip in the command line
        local_ip = i
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
            elif local_ip in iface_ips:  # if they gave us an ip address for -ip eg 10.10.10.10 this ensures that it is our IP were binding to
                print("local IP => {}\n".format(local_ip))
            else:  # if they gave us something incorrect/weird
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:  # if the given interface has no ip we end up here
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)
    else:  # no -ip in args
        # print local interfaces and ips
        ifaces = ni.interfaces()  # get all interfaces
        iface_ips = []

        for face in ifaces:  # get the ip for each interface that has one
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        for face in ifaces:
            try:  # check to see if the interface has an ip
                print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))  # print(interface:      IP)
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ")  # what do they want for their interface

        # lets you enter eth0 as the ip
        try:  # check to see if the interface has an ip
            if local_ip in ifaces:  # if they gave us an interface eg eth0 or ensp01 ensure its ours
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:  # if they gave us an ip ensure its ours
                print("local IP => {}\n".format(local_ip))
            else:  # if they gave us something incorrect/weird
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:  # if they give an interface that has no IP we end up here
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)

    return local_ip


def get_smb_hostname(target_ip):
    try:
        conn = SMBConnection(target_ip, target_ip, sess_port=445) # connect over smb
        conn.login("", "") # login (this will give a STATUS_ACCESS_DENIED error but is required idk why)
    except Exception as e:
        pass

    try:
        hostname = conn.getServerName() # get the hostname
    except Exception:
        return None

    try:
        conn.logoff() # logoff is probably not necessary but who knows
    except Exception as e:
        pass

    return hostname


def send_mdns_query(host, local_ip):
    try:
        question = 'in-addr.arpa'
        split_address = host.split('.')
        split_address.reverse()
        question = '.'.join(split_address) + '.' + question  # this changes the ip to a reversed form so 10.1.20.3 goes to 3.20.1.10.in-addr.arpa

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN)  # make our dns query
        response = dns.query.udp(query, host, port=5353, timeout=3, source=local_ip)  # send the query

        if response.answer:  # if the query came back then there is mdns in the environment
            try:
                if response.answer[0].to_text().split(' ')[4].endswith('.'):
                    return ''.join(response.answer[0].to_text().split(' ')[4].rsplit('.local.', 1)) # log the host ip
                else:
                    return response.answer[0].to_text().split(' ')[4]
            except IndexError:
                return None

        else:
            return None

    except Exception:
        return None


def send_llmnr_query(host, local_ip):
    try:
        # Build the PTR query
        question = 'in-addr.arpa'
        split_address = host.split('.')
        split_address.reverse()
        question = '.'.join(split_address) + '.' + question  # this changes the ip to a reversed form so 10.1.20.3 goes to 3.20.1.10.in-addr.arpa

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN)  # make our dns query
        response = dns.query.udp(query, '224.0.0.252', port=5355, timeout=3, source=local_ip)  # send the dns query to the victim

        if response.answer:  # if we got a response llmnr is present on the host
            try:
                if response.answer[0].to_text().split(' ')[4].endswith('.'):
                    return ''.join(response.answer[0].to_text().split(' ')[4].rsplit('.', 1))
                else:
                    return response.answer[0].to_text().split(' ')[4]
            except IndexError:
                return None

    except Exception as e:  # we got an error
       return None


def netbios_scan(host):  # scan for netbios using nbtscan
    # NetBIOS-NS packet structure: Transaction ID, Flags, Questions, Answer RRs, Authority RRs, Additional RRs, Name, Type, Class, TTL, Length, Number of names
    message = b'\x00\x00' + b'\x00\x10' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00' + b'\x00\x21' + b'\x00\x01'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # make a socket connection with out message
    sock.settimeout(3)

    try:
        sock.sendto(message, (host, 137))
        data = sock.recvfrom(1024)
        data = data[0]  # we are returned a list and the first item is the actual response
    except socket.timeout:  # if we hit the timeout then the host is likely not running netbios
        sock.close()
        return None

    except Exception as e:  # if we get a generic error
        sock.close()
        return None

    else:
        sock.close()  # close the socket connection

        # Parse response
        if len(data) < 57:  # Basic validation
            return None

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

            return max(posdata, key=len)

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

                return max(posdata, key=len)

            except UnicodeDecodeError:
                return None
            except Exception as e:
                return None
        except Exception as e:
            return None

    return None


def mt_execute(target_ip, local_ip): # multithreading
    # this function is where we do most of the stuff for getting the hostname
    try:
        hostname = socket.gethostbyaddr(target_ip)  # try to get hostname through dns
        if hostname[0] != '' and hostname is not None and hostname != ' ':
            #print(f'{target_ip} {hostname}')
            return f'{target_ip} {hostname}'
    except Exception:
        pass

    hostname = get_smb_hostname(target_ip)  # try to get hostname from smb
    if hostname != 'NONE' and hostname is not None and hostname != '' and hostname != ' ':
        #print(f'{target_ip} {hostname}')
        return f'{target_ip} {hostname}'

    hostname = netbios_scan(target_ip) # try and get hostname via netbios
    if hostname is not None and hostname != '' and hostname != ' ':
        #print(f'{target_ip} {hostname}')
        return f'{target_ip} {hostname}'

    hostname = send_mdns_query(target_ip, local_ip) # try to get hostname via mdns
    if hostname is not None and hostname != '' and hostname != ' ':
        #print(f'{target_ip} {hostname}')
        return f'{target_ip} {hostname}'

    hostname = send_llmnr_query(target_ip, local_ip) # get hostname via llmnr
    if hostname is not None and hostname != '' and hostname != ' ':
        #print(f'{target_ip} {hostname}')
        return f'{target_ip} {hostname}'

    #print(f'{target_ip} N/A')
    return f'{target_ip} N/A'


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

        return hosts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="get that hostname")
    parser.add_argument('target', action='store', help='target ip as a file, ip, or cidr: 10.10.10.10, fileofips, 10.20.1.0/24 any of the 3')
    parser.add_argument('-t', '--threads', action='store', default=5, type=int, help='Number of threads to use. (Default=5)')
    parser.add_argument('-i', action='store', help='Your local ip or interface')


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    local_ip = get_local_ip(options.i) # get our localip
    hosts = parse_hosts_file(options.target) # get our targetlist
    with concurrent.futures.ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = []
        for host in hosts:
            if host != local_ip:  # ensure we dont scan ourself
                futures.append(executor.submit(mt_execute, host, local_ip))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            print(result)
