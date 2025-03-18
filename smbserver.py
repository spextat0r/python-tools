# This tool creates a samba smb share that can be used for exfiltrating data / hosting files. It is not meant to replace impacket's smbserver.py, however
# theirs has issues running binaries as administrator and random disconnects that samba just does not have
# REQUIRES SAMBA TO BE INSTALLED

import os
import sys
import errno
import string
import random
import socket
import argparse
import readline
import subprocess
import netifaces as ni

cwd = os.path.abspath(os.path.dirname(__file__))
###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = '{}[+]{}'.format(color_GRE, color_reset)
red_minus = '{}[-]{}'.format(color_RED, color_reset)
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)

def setup_share(local_ip, share_name=None, share_user=None, share_pass=None, share_group=None):

    share_name = ''.join(random.choices(string.ascii_lowercase, k=20)) if share_name is None else share_name
    share_user = ''.join(random.choices(string.ascii_lowercase, k=10)) if share_user is None else share_user
    share_pass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=35)) if share_pass is None else share_pass
    share_group = ''.join(random.choices(string.ascii_lowercase, k=10)) if share_group is None else share_group

    print('\n[Generating share]')
    # making the directory
    print(f'{green_plus} Creating the share folder')
    os.system('sudo mkdir /var/tmp/' + share_name)

    # smb.conf edits
    data = """[{}]
    path = /var/tmp/{}
    public = no
    force user = {}
    force group = {}
    browseable = yes
    create mask = 0664
    force create mode = 0664
    directory mask = 0775
    force directory mode = 0775
    read only = no
    comment = The share
    """.format(share_name, share_name, share_user, share_group)

    # copy old smb.conf file so its safe
    print(f'{green_plus} Backing up the smb.conf file')
    os.system(f'sudo cp /etc/samba/smb.conf {cwd}/')
    print(f'{green_plus} Making modifications')
    with open('/etc/samba/smb.conf', 'a') as f:
        f.write(data)
        f.close()

    # create the user for the share
    # generate the group
    print(f'{green_plus} Creating the group: {share_group}')
    os.system(f'sudo groupadd --system {share_group}')
    # make the user
    print(f'{green_plus} Creating the user: {share_user}')
    os.system(f'sudo useradd --system --no-create-home --group {share_group} -s /bin/false {share_user}')
    # give the user access to the share folder
    print(f'{green_plus} Giving the user rights')
    os.system(f'sudo chown -R {share_user}:{share_group} /var/tmp/{share_name}')
    # expand access to the group
    print(f'{green_plus} Giving the group rights')
    os.system(f'sudo chmod -R g+w /var/tmp/{share_name}')
    # create the smbusers password
    print(f'{green_plus} Editing the SMB password')
    proc = subprocess.Popen(['sudo', 'smbpasswd', '-a', '-s', share_user], stdin=subprocess.PIPE)
    proc.communicate(input=share_pass.encode() + '\n'.encode() + share_pass.encode() + '\n'.encode())
    # restart the smb service
    print(f'{color_BLU}[+]{color_reset} Restarting the SMB service')
    os.system('sudo systemctl restart smbd')

    print('\n[Share Info]')
    print(f'Share Location: /var/tmp/{share_name}')
    print(f'Share User: {share_user}')
    print(f'Share Pass: {share_pass}')
    print(f'Share Group: {share_group}')
    print()
    print('The network Share can be mounted on Windows with the command below:')
    print(f'net use Q: \\\\{local_ip}\\{share_name} /user:{share_user} {share_pass}')

    return share_user, share_group, share_name

def port445_check(interface_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((interface_ip, 445))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            print(f'{red_minus} Port 445 is already in use')
            sys.exit(0)
        else:
            # something else raised the socket.error exception
            print(str(e))

    sock.close()

if __name__ == '__main__':
    if sys.platform != 'linux':
        print('[!] This program is Linux only')
        sys.exit(1)

    if os.geteuid() != 0:
        print('[!] Must be run as sudo')
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help=True, description='All arguments are optional',)
    parser.add_argument('-sharename', action='store', help='Set the name of the attacker share Default=random')
    parser.add_argument('-shareuser', action='store', help='Set the username of the user for the share Default=random')
    parser.add_argument('-sharepassword', action='store', help='Set the password for shareuser Default=random')
    parser.add_argument('-sharegroup', action='store', help='Set the group for shareuser Default=random')
    parser.add_argument('-ip', action='store', help='Your machines IP/interface you want this to run on')

    options = parser.parse_args()

    print('\nPro Tip: if you are getting "Access Denied" when trying to run an exe on Windows that is hosted on the share just chmod 777 the file\n')

    # all of this is just to ensure they give a valid interface lot o logic
    if options.ip is not None:  # did they give us the local ip in the command line
        local_ip = options.ip
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
    else:  # no -ip in options
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

    # ensure port 445 is not in use
    port445_check(local_ip)

    share_user, share_group, share_name = setup_share(local_ip, options.sharename, options.shareuser, options.sharepassword, options.sharegroup)

    X = input('\nPress Enter to Exit')

    print('\n{}[-]{} Cleaning up please wait'.format(color_BLU, color_reset))

    try:
        os.system('sudo systemctl stop smbd')
        print(green_plus + ' Stopped the smbd service')
    except BaseException as e:
        pass

    try:
        os.system('sudo cp ' + cwd + '/smb.conf /etc/samba/smb.conf')
        print(green_plus + ' Cleaned up the smb.conf file')
    except BaseException as e:
        pass

    try:
        os.system('sudo rm ' + cwd + '/smb.conf')
    except BaseException as e:
        pass

    try:
        os.system('sudo userdel ' + share_user)
        print(green_plus + ' Removed the user: ' + share_user)
    except BaseException as e:
        pass

    try:
        os.system('sudo groupdel ' + share_group)
        print(green_plus + ' Removed the group: ' + share_group)
    except BaseException as e:
        pass

    try:
        os.system('sudo mv /var/tmp/{} {}'.format(share_name, cwd))
        print(green_plus + ' Share folder is now in {}/{}'.format(cwd, share_name))
    except BaseException as e:
        pass

    print('{}[-]{} Cleanup completed! If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
    sys.exit(0)
