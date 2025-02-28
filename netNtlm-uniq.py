import argparse, sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(epilog="This can also be done using a one liner made by c@b0053\ncat hashfile | grep -v '\$' | sort -u -t ':' -k 1,2")
    parser.add_argument('file', action='store', type=str, help='The file to parse')
    parser.add_argument('-of', action='store', type=str, default='netNtlm-uniqout.txt', help='File to output to. Default=./netNtlm-uniqout.txt')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    data = []

    with open(options.file, 'r') as f:
        data = f.readlines()
        f.close()

    uniq_data = []
    uniq_data_full = []
    for item in data:
        if item.split("::")[0] not in uniq_data and item.split("::")[0].find('$') == -1:
            uniq_data_full.append(item)
            uniq_data.append(item.split("::")[0])

    with open(options.of, 'w') as f:
        for thing in uniq_data_full:
            f.write(thing)
