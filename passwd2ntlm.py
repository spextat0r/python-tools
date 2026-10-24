#!/usr/bin/env python3
import sys, os
try:
    from passlib.hash import nthash
except BaseException:
    print('Missing passlib imstall with pip3 install passlib')
    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv or '-help' in sys.argv: # input checking
        print('Usage: python3 passwd2ntlm.py \'password\'')
        print('Usage: python3 passwd2ntlm.py password_file.txt')
        print('NOTE: the password file must be 1 password per line')
        sys.exit(0)

    if os.path.isfile(sys.argv[1]): # check if password is a file
        with open(sys.argv[1], 'r') as f: # read passwords from file into an array named dat should be ['passwd1\n', 'paddwd2\n', 'goodpassword\n']
            dat = f.readlines()
            f.close()

        print('password:nthash')
        for password in dat: # iterate through the dat array
            print('{}:{}'.format(password[:len(password)-1], nthash.hash(password[:len(password)-1]))) # convert the 'passwd\n' to 'passwd' and make it an nt hash
    else:
        print('password:nthash')
        print('{}:{}'.format(sys.argv[1], nthash.hash(sys.argv[1])))
