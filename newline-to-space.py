#!/usr/bin/env python3
import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('file', action='store', type=str, help='The file to parse')
	parser.add_argument('-of', action='store', type=str, default='newline-to-spaceout.txt', help='File to output to. Default=./newline-to-spaceout.txt')
	options = parser.parse_args()


	with open(options.file, 'r') as f:
	    dat = f.read()
	    f.close()

	dat1 = ' '.join(dat.splitlines())

	with open(options.of, 'w') as f:
	    f.writelines(dat1)
	    f.close()
