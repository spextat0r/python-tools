#!/usr/bin/env python3
# Userlist generator that uses SecLists

import argparse
import string
import sys
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="Generates a large list of usernames for kerbrute")
    parser.add_argument('-mode', action='store', default='0', choices=['0', '1', '2', '3'], help='Select which type of username you want 0=First.Last 1==FirstletterLast 2=FirstletterMILast 3=ALL')
    parser.add_argument('-o', default='./usernames.txt', action='store', help='File to output your usernames to. Deafult=./usernames.txt')
    parser.add_argument('-inf', action='store', default='/usr/share/wordlists/seclists/Usernames/Names/names.txt', help='File of firstnames Default=/usr/share/wordlists/seclists/Usernames/Names/names.txt')
    parser.add_argument('-il', action='store', default='/usr/share/wordlists/seclists/Usernames/Names/familynames-usa-top1000.txt', help='File of lastnames Default=/usr/share/wordlists/seclists/Usernames/Names/familynames-usa-top1000.txt')

    if len(sys.argv) == 1:
        parser.print_help()
        print('mode 0 requires firstname and lastname')
        print('mode 1 requires lastname')
        print('mode 2 requires firstname and lastname')
        print('mode 3 requires firstname and lastname')
        sys.exit(1)

    options = parser.parse_args()

    lastnames = []
    firstnames = []
    lastnames_cleand = []
    firstnames_cleaned = []
    lowercase_letters = list(string.ascii_lowercase)
    with open(options.inf, 'r') as f:
        firstnames = f.readlines()
        f.close()

    with open(options.il, 'r') as f:
        lastnames = f.readlines()
        f.close()

    for sub in firstnames:
        firstnames_cleaned.append(sub.replace('\n', '').lower())

    for sub in lastnames:
        lastnames_cleand.append(sub.replace('\n', '').lower())

    with open(options.o, 'a') as f:
        if options.mode == '0' or options.mode == '3':
            for name in firstnames_cleaned:
                for lname in lastnames_cleand:
                    f.write(name + "." + lname + "\n")

        if options.mode == '1' or options.mode == '3':
            for lname in lastnames_cleand:
                for letter in lowercase_letters:
                    f.write(letter + lname + "\n")

        if options.mode == '2' or options.mode == '3':
            for lname in lastnames_cleand:
                for char in lowercase_letters:
                    for letter in lowercase_letters:
                        f.write(letter + char + lname + "\n")

        f.close()

    if options.mode == '3':
        if sys.platform == 'linux':
            os.system('cat {} | sort -u > {}cleaned'.format(options.o, options.o))
            os.system('rm {}'.format(options.o))
            os.system('mv {}cleaned {}'.format(options.o, options.o))
        else:
            print('WARNING this file is not uniq please sort and unique it')
