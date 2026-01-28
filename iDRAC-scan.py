from datetime import datetime
import http.client
import threading
import time
import ssl
from queue import Queue
import os, sys
import argparse
from argparse import RawTextHelpFormatter
import ipaddress
import json

statusUpdateFrequency = 2 # show every X seconds on screen the status
found = 0

cwd = os.path.abspath(os.path.dirname(__file__))

def timestampme():
    today = datetime.now()
    hour = today.strftime("%H")
    ltime = time.localtime(time.time())
    timestamp = '%s-%s-%s_%s-%s-%s' % (str(ltime.tm_mon).zfill(2), str(ltime.tm_mday).zfill(2),
                                       str(ltime.tm_year).zfill(2), str(hour).zfill(2), str(ltime.tm_min).zfill(2),
                                       str(ltime.tm_sec).zfill(2))
    return timestamp

def printnlog(printlogme, out):
    print(timestampme() + ' ' + printlogme)
    if out is not None:
        with open(out, 'a') as f:
            f.write(timestampme() + ' ' + printlogme + '\n')
            f.close()

def CheckServer(ipaddr):
    global found

    conn = http.client.HTTPSConnection(ipaddr, timeout=options.timeout, context=ssl._create_unverified_context()) # use for python 3.6+
    try:
        conn.request("GET", "/sysmgmt/2015/bmc/info")
        response = conn.getresponse()
        data = response.read().decode('utf-8')
        if response.status == 200:
            jsondata = json.loads(data)
            if jsondata["Attributes"]["FwVer"] is not None and jsondata["Attributes"]["BuildVersion"] is not None:
                if len(jsondata["Attributes"]["FwVer"]) > 2:
                    dumpdata(ipaddr, jsondata["Attributes"]["FwVer"], jsondata["Attributes"]["BuildVersion"])
                    found = found + 1
    except Exception as e:
        #print(e)
        pass

def worker():
    while True:
        ipaddr = q.get()
        CheckServer(ipaddr)
        q.task_done()


def WaitCompletion():
    totalQ = q.qsize()
    lastpercent = 0
    while (q.qsize() > 0):
        if (round(((totalQ - q.qsize()) * 100) / totalQ, 1) != lastpercent):
            printnlog(f"{round(((totalQ - q.qsize()) * 100) / totalQ, 1)}% - found: {found}",options.output)
            lastpercent = round(((totalQ - q.qsize()) * 100) / totalQ, 1)
        time.sleep(statusUpdateFrequency)

    q.join()

    printnlog("Done scanning", options.output)
    printnlog("total found: " + str(found), options.output)

def dumpdata(hostip, version, buildver):

    # determine idrac9 major version (probably correct)
    if version.split('.')[0] == '1': # 1.x = iDRAC 6
        idrac_major = '6'
    elif version.split('.')[0] == '2':
        if version.split('.')[1] < '30': # 2.0-2.29 = iDRAC 7
            idrac_major = '7'
        else: # 2.30-3.99 = iDRAC8
            idrac_major = '8'
    elif version.split('.')[0] >= '4': # >= 4= iDRAC 9
        idrac_major = '9'
    else:
        idrac_major = '??'


    printnlog(hostip + " - iDRAC" + idrac_major + " " + version + "." + buildver, options.output)

# so we only need to define them once
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

def pub_or_priv(ipaddress_to_check):
    return "Private" if (ipaddress.ip_address(ipaddress_to_check).is_private) else "Public"

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
                                try: # validate that this is a real ip
                                    test = ipaddress.ip_address(line)
                                    hosts.append(line)
                                except ValueError:
                                    print('Invalid IP address detected from scope skipping: {}'.format(line))
                                    sys.exit(1)
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
                try: # validate that this is a real ip
                    test = ipaddress.ip_address(hosts_file)
                    hosts.append(hosts_file)
                except ValueError:
                    print('Invalid IP address detected from scope skipping: {}'.format(hosts_file))
                    sys.exit(1)
        except Exception as e:
            print(e)
            print('Error: there is something wrong with the ip you gave "{}"'.format(hosts_file))
            sys.exit(1)
        hosts = list(set(hosts))  # unique the hosts
        return hosts

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description='',epilog='Input File Format:\n\n10.0.0.1\n10.0.0.5\n10.0.0.6\n10.200.13.12', formatter_class=RawTextHelpFormatter)

    parser.add_argument('-o', '--output', action='store', help='Output file')
    parser.add_argument('-i', '--input', action='store', required=True, help='File that holds ips 1 per line or just the ip')
    parser.add_argument('-t', '--threads', action='store', default=30, help='Maximum threads Default=30')
    parser.add_argument('--timeout', action='store', default=5, help='Timeout for each connection Default=5')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    printnlog('Tool is starting...', options.output)
    print('Parsing Scope...')
    data = parse_hosts_file(options.input) # parse scope file

    private = False
    public = False
    for ip in data: # check if there are public and private ips in the scope
        if pub_or_priv(ip) == 'Private':
            private = True
        else:
            public = True

    if public and private:
        print('WARNING: Your scope contains both public and private IP addresses')

    print('Total Hosts: {}'.format(len(data)))


    printnlog('Scanner client started...', options.output)
    lock = threading.Lock()
    q = Queue()

    for i in range(options.threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    for item in data:
        q.put(item)

    WaitCompletion()

    printnlog('Done', options.output)
