import argparse
import sys

try:
  from ibm_db import connect
except ImportError:
  print("Error: you dont have ibm_db installed you can install it with python3 -m pip install ibm_db")
  sys.exit(1)

parser = argparse.ArgumentParser(add_help=True, description="")
parser.add_argument('-dbname', action='store', required=True, help='Name of the database to try SUPER IMPORTANT PUT THIS IN SINGLE QUOTES')
parser.add_argument('-hostname', action='store', required=True, help='IP of the database server')
parser.add_argument('-port', action='store', required=True, help='Port on the remote host')
parser.add_argument('-username', action='store', required=True, help='username to try')
parser.add_argument('-password', action='store', required=True, help='password to try')
options = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
    

try:

    connection = connect('DATABASE='+options.dbname+';'
                        'HOSTNAME='+options.hostname+';'
                        'PORT='+options.port+';'
                        'PROTOCOL=TCPIP;'
                        'UID='+options.username+';'
                        'PWD='+options.password+';', '', '')
except Exception as e:
    print(e)
    
    if str(e).find('A communication error has been detected. Communication protocol being used: "TCP/IP".  Communication API being used: "SOCKETS".') != -1:
        print("There is likely no IBMDB2 database on that ip/port")
    elif str(e).find('is not a valid database name') != -1:
        print("There is a database but you got the name of it wrong")
    elif str(e).find('The database directory cannot be found on the indicated file system') != -1:
        print("There is a database and you got the name of the database right")
