# This tool abuses the responses that an ADCS server with web enrollment enabled gives to detect it.
import concurrent.futures
import ipaddress
import requests
import argparse
import sys, os
import time

# colors
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_reset = '\033[0m'
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)
green_plus = '{}[+]{}'.format(color_GRE, color_reset)

# cidrs
classA = ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0"))
classB = ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0"))
classC = ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0"))

def get_ip_class(ipaddr):

    if ipaddr in classA:
        return 'A'
    elif ipaddr in classB:
        return 'B'
    elif ipaddr in classC:
        return 'C'
    else:
        return 'public'

def convert_dashnot_to_ips(inp): # takes string input

    inp = inp.replace(' ', '') # handle the case where a user gives us a - notation ip like "10.10.10.10 - 10.10.20.10"
    tmp = inp.split('-') # split the start and end ips assuming input is "10.10.10.10-10.10.20.10" formatted
    try: # attempt to convert the ips into ipaddress.IPv4Address object if they gave bad input itll error here and we just return blank
        start_ip = ipaddress.IPv4Address(tmp[0])
        end_ip = ipaddress.IPv4Address(tmp[1])
    except ipaddress.AddressValueError:
        print('There is an issue with the ipaddress you gave {}'.format(inp))
        return []
    except Exception as e:
        print(e)
        return []

    if get_ip_class(start_ip) != get_ip_class(end_ip): # ensure the IPs are from the same cidr class
        print('The Start and end IPs are from different IP classes {}'.format(inp))
        return []

    if end_ip < start_ip: # ensure the end ip is bigger than the start ip
        print('EndIP is smaller than StartIP {}'.format(inp))
        return []

    # Generate all IP addresses in the range
    current_ip = start_ip
    ip_list = []

    while current_ip <= end_ip: # get a full list of ips
        ip_list.append(str(current_ip))
        current_ip += 1

    return ip_list

def parse_hosts_file(hosts_file):  # parse our host file
    hosts = []
    if os.path.isfile(hosts_file): # ensure the file exists otherwise try it as if they passed an ip or cidr to the command line
        try:
            with open(hosts_file, 'r') as file: # read the file
                for line in file:
                    line = line.strip()
                    if line:
                        try:
                            if '/' in line: # this is so we can have cidr and ips in the same file
                                # Assuming CIDR notation
                                network = ipaddress.ip_network(line, strict=False) # black magic
                                hosts.extend(str(ip) for ip in network.hosts())
                            elif '-' in line: # allow dash notation
                                iplist = convert_dashnot_to_ips(line)
                                if iplist != [] and len(iplist) > 0: # ensure the list is not empty if it is we had an error
                                    for ip in iplist: # append ips to the hosts list
                                        hosts.append(ip)
                                else:
                                    sys.exit(1)
                            else:
                                hosts.append(line)
                        except Exception as e:
                            print(e)
                            print('Error: there is something wrong with the ip in the file line="{}"'.format(line))
                            sys.exit(1)
                file.close()
            hosts = list(set(hosts)) # unique the hosts
            return hosts
        except FileNotFoundError:
            print('The given file does not exist "{}"'.format(hosts_file))
            sys.exit(1)
    else:
        try:
            if '/' in hosts_file:
                # Assuming CIDR notation
                network = ipaddress.ip_network(hosts_file, strict=False)
                hosts.extend(str(ip) for ip in network.hosts())
            elif '-' in hosts_file: # allow dash notation
                iplist = convert_dashnot_to_ips(hosts_file)
                if iplist != [] and len(iplist) > 0: # ensure the list is not empty if it is we had an error
                    for ip in iplist: # append ips to the hosts list
                        hosts.append(ip)
                else:
                    sys.exit(1)
            else:
                hosts.append(hosts_file)
        except Exception as e:
            print(e)
            print('Error: there is something wrong with the ip you gave "{}"'.format(hosts_file))
            sys.exit(1)
        hosts = list(set(hosts))  # unique the hosts
        return hosts

def scan_for_adcs(ip_to_scan):
    try:
        dat = requests.get(f'http://{ip_to_scan}/certsrv/', timeout=4) # make curl request
        dat.close()
    except Exception as e:
        return 1
    # if we get a 401 with the correct body string were on the right track
    if dat.status_code == 401 and dat.content.decode().find("Access is denied due to invalid credentials.") != -1:
        if 'WWW-Authenticate' in dat.headers: # if the headers have www-authenticate its almost certain
            if dat.headers['WWW-Authenticate'] == 'NTLM' or dat.headers['WWW-Authenticate'] == 'Kerberos':
                print(f'{gold_plus} ESC8 likely for: {ip_to_scan}')
                return 2
        else:
            print(f'{green_plus} ADCS Web Enrollment likely for: {ip_to_scan}')
            return 0
    return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Detect ADCS without credentials", formatter_class=argparse.RawTextHelpFormatter, epilog='Accepted IP formats\nSingle: 10.10.10.10\nCidr: 10.10.10.0/24\nSubnet: 10.10.10.0/255.255.255.0\nLine: 10.10.10.0-10.10.11.255')
    parser.add_argument("scope_file", help="Path to a file containing the full scope can be 1 ip per line or 1 cidr per line")
    parser.add_argument("-t", default=20, help="Threads to use Default=20")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    print(f'{green_plus} Parsing Scope...')
    scope = parse_hosts_file(options.scope_file)  # parse scope file
    print(f'{green_plus} Scope contains {str(len(scope))} IPs')

    with concurrent.futures.ThreadPoolExecutor(max_workers=options.t) as executor:
        futures = []
        results = []
        for ip in scope:
            futures.append(executor.submit(scan_for_adcs, ip))

        count = 0
        last_printed = 0
        start_time = time.time()
        total = len(futures)

        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            count += 1

            percent = int((count / total) * 100)

            if percent >= last_printed + 10:  # every 10%
                elapsed = time.time() - start_time # get elapsed time to make an ETA
                rate = count / elapsed if elapsed > 0 else 0
                remaining = total - count
                eta = remaining / rate if rate > 0 else 0

                eta_str = time.strftime('%H:%M:%S', time.gmtime(eta))

                print(f'{gold_plus} {percent}% Complete | ETA: {eta_str}')
                last_printed = percent

        if 2 in results:
            print(f'{green_plus} Located {results.count(2)} instances of ADCS with ESC8')

        if 0 in results:
            print(f'{green_plus} Located {results.count(0)} instances of ADCS without ESC8')

        if 2 not in results and 0 not in results:
            print('Unable to locate ADCS')
