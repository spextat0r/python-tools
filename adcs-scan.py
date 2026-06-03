from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpch import RPC_PROXY_INVALID_RPC_PORT_ERR, RPC_PROXY_CONN_A1_0X6BA_ERR, RPC_PROXY_CONN_A1_404_ERR, RPC_PROXY_RPC_OUT_DATA_404_ERR
from impacket import uuid

from urllib3.exceptions import InsecureRequestWarning
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
color_BLU = '\033[94m'
color_reset = '\033[0m'
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)
green_plus = '{}[+]{}'.format(color_GRE, color_reset)
blue_plus = '{}[+]{}'.format(color_BLU, color_reset)

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


def convert_dashnot_to_ips(inp):  # takes string input

    inp = inp.replace(' ', '')  # handle the case where a user gives us a - notation ip like "10.10.10.10 - 10.10.20.10"
    tmp = inp.split('-')  # split the start and end ips assuming input is "10.10.10.10-10.10.20.10" formatted
    try:  # attempt to convert the ips into ipaddress.IPv4Address object if they gave bad input itll error here and we just return blank
        start_ip = ipaddress.IPv4Address(tmp[0])
        end_ip = ipaddress.IPv4Address(tmp[1])
    except ipaddress.AddressValueError:
        print('There is an issue with the ipaddress you gave {}'.format(inp))
        return []
    except Exception as e:
        print(e)
        return []

    if get_ip_class(start_ip) != get_ip_class(end_ip):  # ensure the IPs are from the same cidr class
        print('The Start and end IPs are from different IP classes {}'.format(inp))
        return []

    if end_ip < start_ip:  # ensure the end ip is bigger than the start ip
        print('EndIP is smaller than StartIP {}'.format(inp))
        return []

    # Generate all IP addresses in the range
    current_ip = start_ip
    ip_list = []

    while current_ip <= end_ip:  # get a full list of ips
        ip_list.append(str(current_ip))
        current_ip += 1

    return ip_list


def parse_hosts_file(hosts_file):  # parse our host file
    hosts = []
    if os.path.isfile(hosts_file):  # ensure the file exists otherwise try it as if they passed an ip or cidr to the command line
        try:
            with open(hosts_file, 'r') as file:  # read the file
                for line in file:
                    line = line.strip()
                    if line:
                        try:
                            if '/' in line:  # this is so we can have cidr and ips in the same file
                                # Assuming CIDR notation
                                network = ipaddress.ip_network(line, strict=False)  # black magic
                                hosts.extend(str(ip) for ip in network.hosts())
                            elif '-' in line:  # allow dash notation
                                iplist = convert_dashnot_to_ips(line)
                                if iplist != [] and len(
                                        iplist) > 0:  # ensure the list is not empty if it is we had an error
                                    for ip in iplist:  # append ips to the hosts list
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
            hosts = list(set(hosts))  # unique the hosts
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
            elif '-' in hosts_file:  # allow dash notation
                iplist = convert_dashnot_to_ips(hosts_file)
                if iplist != [] and len(iplist) > 0:  # ensure the list is not empty if it is we had an error
                    for ip in iplist:  # append ips to the hosts list
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


def tof(indat):
    if indat == 'Unsure':
        indat = f'{color_YELL}Unsure{color_reset}'
        return indat

    if indat:
        indat = f'{color_GRE}True{color_reset}'
    else:
        indat = f'{color_RED}False{color_reset}'

    return indat


def clu(indat):
    if indat == 'Certain':
        indat = f'{color_GRE}Certain{color_reset}'
    elif indat == 'Likely':
        indat = f'{color_YELL}Likely{color_reset}'
    elif indat.find('/') != -1:
        indat = f'{color_YELL}{indat}{color_reset}'
    else:
        indat = f'{color_RED}Unknown{color_reset}'
    return indat


def scan_for_adcs(ip_to_scan, debug, timeout):
    rpc_adcs = False
    http_adcs = False
    https_adcs = False
    http_esc8 = False
    https_esc8 = False
    rpc_confidence = 'Unknown'
    http_confidence = 'Unknown'
    https_confidence = 'Unknown'

    # check rpc
    KNOWN_PROTOCOLS = {
        135: {"bindstr": r"ncacn_ip_tcp:%s[135]"},
        139: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
        443: {"bindstr": r"ncacn_http:[593,RpcProxy=%s:443]"},
        445: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
        593: {"bindstr": r"ncacn_http:%s"}
    }

    port = 135.
    stringbinding = KNOWN_PROTOCOLS[port]["bindstr"] % ip_to_scan
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.setRemoteHost(ip_to_scan)
    rpctransport.set_connect_timeout(float(timeout))

    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        resp = epm.hept_lookup(None, dce=dce)
        dce.disconnect()
        entries = resp
        for entry in entries:
            tmpUUID = str(entry["tower"]["Floors"][0])

            if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                exename = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]

                if exename == "certsrv.exe":
                    rpc_adcs = True
                    rpc_confidence = 'Certain'

    except Exception as e:
        error_text = f"Protocol failed: {e}"
        if debug:
            print(error_text)

            if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text or \
                    RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or \
                    RPC_PROXY_CONN_A1_404_ERR in error_text or \
                    RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
                print("This usually means the target does not allow to connect to its epmapper using RpcProxy.")

    # check http
    try:
        dat = requests.get(f'http://{ip_to_scan}/certsrv/certfnsh.asp', allow_redirects=False, timeout=int(timeout))  # make curl request
        dat.close()
        # if we get a 401 with the correct body string were on the right track if we get a 403 its still probs adcs but esc8 is unlikely
        if (dat.status_code == 401 and dat.content.decode().find("Access is denied due to invalid credentials.") != -1) or (dat.status_code == 403 and dat.content.decode().find("You do not have permission to view this directory or page using the credentials that you supplied.") != -1):
            http_adcs = True
            http_confidence = 'Likely'
            if 'WWW-Authenticate' in dat.headers:  # if the headers have www-authenticate its almost certain
                if 'NTLM' in dat.headers['WWW-Authenticate'] or 'Kerberos' in dat.headers['WWW-Authenticate']:
                    http_esc8 = True
                    http_confidence = 'Certain'
                elif 'Negotiate' in dat.headers['WWW-Authenticate']:
                    http_esc8 = 'Unsure'
            else:
                dat = requests.get(f'http://{ip_to_scan}/ergrthiuerhuiergerfuheirg/', allow_redirects=False, timeout=int(timeout))  # make curl request
                dat.close()
                if (dat.status_code == 401 and dat.content.decode().find("Access is denied due to invalid credentials.") != -1) or (dat.status_code == 403 and dat.content.decode().find("You do not have permission to view this directory or page using the credentials that you supplied.") != -1):
                    http_confidence = 'Unknown'

    except Exception as e:
        if debug:
            print(f'Error: {e}')
        pass



    # check https
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        dat = requests.get(f'https://{ip_to_scan}/certsrv/certfnsh.asp', allow_redirects=False, verify=False, timeout=int(timeout))  # make curl request
        dat.close()
        # if we get a 401 with the correct body string were on the right track if we get a 403 its still probs adcs but esc8 is unlikely
        if (dat.status_code == 401 and dat.content.decode().find("Access is denied due to invalid credentials.") != -1) or (dat.status_code == 403 and dat.content.decode().find("You do not have permission to view this directory or page using the credentials that you supplied.") != -1):
            https_adcs = True
            https_confidence = 'Likely'
            if 'WWW-Authenticate' in dat.headers:  # if the headers have www-authenticate its almost certain
                if 'NTLM' in dat.headers['WWW-Authenticate'] or 'Kerberos' in dat.headers['WWW-Authenticate']:
                    https_esc8 = True
                    https_confidence = 'Certain'
                elif 'Negotiate' in dat.headers['WWW-Authenticate']:
                    https_esc8 = 'Unsure'
            else:
                dat = requests.get(f'https://{ip_to_scan}/ergrthiuerhuiergerfuheirg/', allow_redirects=False, verify=False, timeout=int(timeout))  # make curl request
                dat.close()
                if (dat.status_code == 401 and dat.content.decode().find("Access is denied due to invalid credentials.") != -1) or (dat.status_code == 403 and dat.content.decode().find("You do not have permission to view this directory or page using the credentials that you supplied.") != -1):
                    https_confidence = 'Unknown'

    except Exception as e:
        if debug:
            print(f'Error: {e}')
        pass

    # build out string with pretty colors
    if rpc_adcs or http_adcs or https_adcs:

        rpc_adcs = tof(rpc_adcs)
        rpc_confidence = clu(rpc_confidence)

        if https_adcs and http_adcs: # if both http and https
            http_pre = 'HTTP(S)'
        elif https_adcs: # if only https
            http_pre = 'HTTPS'
        else: # should only be http
            http_pre = 'HTTP'

        if http_adcs or https_adcs:
            httpt = True
        else:
            httpt = False

        if https_adcs and http_adcs: # if we have bot http and https and the confidences dont match smash em together
            if http_confidence != https_confidence:
                httpc = f'{http_confidence}/{https_confidence}'
            else:
                httpc = http_confidence
        elif https_adcs: # if only https
            httpc = https_confidence
        elif http_adcs: # if only http
            httpc = http_confidence
        else:
            httpc = f'got something weird??'


        if http_esc8 == True or https_esc8 == True:
            esc8 = True
        elif http_esc8 == False and https_esc8 == False:
            esc8 = False
        else:
            esc8 = 'Unsure'

        if debug:
            print(f'IP: {ip_to_scan}\nrpc_adcs: {rpc_adcs}\nrpc_confidence: {rpc_confidence}\nhttps_adcs: {http_adcs}\nhttp_confidence: {http_confidence}\nhttps_adcs: {https_adcs}\nhttps_confidence: {https_confidence}\nhttp_esc8: {http_esc8}\nhttps_esc8: {https_esc8}\nhttpt: {httpt}\nhttpc: {httpc}\nesc8: {esc8}')

        httpt = tof(httpt)
        httpc = clu(httpc)

        esc8 = tof(esc8)

        print_string = f'{blue_plus} CA:{ip_to_scan} RPC_Confirmation:{rpc_adcs} RPC_Confidence:{rpc_confidence} {http_pre}_Confirmation:{httpt} {http_pre}_Confidence:{httpc} ESC8:{esc8}'
        print(print_string)

    return 1


# TODO add rpc signing check for esc11 if possible
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Detect ADCS without credentials", formatter_class=argparse.RawTextHelpFormatter, epilog='Accepted IP formats\nSingle: 10.10.10.10\nCidr: 10.10.10.0/24\nSubnet: 10.10.10.0/255.255.255.0\nLine: 10.10.10.0-10.10.11.255\n\nPotential HTTP outputs\nHTTP_ means only an HTTP endpoint was found\nHTTPS_ means only an HTTPS endpoint was found\nHTTP(S)_ means both HTTP and HTTPS endpoints were found\nIf both endpoints are found and their confidences are different it will be formatted as http_confidence/https_confidence')
    parser.add_argument("scope_file", help="Path to a file containing the full scope can be 1 ip per line or 1 cidr per line")
    parser.add_argument("-t", action='store', type=int, default=20, help="Threads to use Default=20")
    parser.add_argument("-timeout", action='store', default=5, help="Time to wait before timeout Default=5")
    parser.add_argument("-debug", action='store_true', default=False, help="Turn on debugging")

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
            futures.append(executor.submit(scan_for_adcs, ip, options.debug, options.timeout))

        count = 0
        last_printed = 0
        start_time = time.time()
        total = len(futures)

        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            count += 1

            percent = int((count / total) * 100)

            if percent >= last_printed + 10:  # every 10%
                elapsed = time.time() - start_time  # get elapsed time to make an ETA
                rate = count / elapsed if elapsed > 0 else 0
                remaining = total - count
                eta = remaining / rate if rate > 0 else 0

                eta_str = time.strftime('%H:%M:%S', time.gmtime(eta))

                print(f'{gold_plus} {percent}% Complete | ETA: {eta_str}')
                last_printed = percent
