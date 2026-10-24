#!/usr/bin/env python3
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from requests import ConnectionError
import concurrent.futures
import requests
import argparse
import sys

def sig_check(response_text):

    signatures = {
        # needs to be
        # signature:what it is
        'S1-ro-xs-xs-test': 'S',
        'URL=/aca/index.html': 'AXIS Camera',
        'window.location.pathname=\'camera/index.html\'': 'AXIS Camera',
        '; URL=/camera/index.html"':'Axis Camera',
        'src=js/iLO.js': 'HP ILO',
        'iLOGlobal.topPage = me.topPage;': 'HP ILO',
        'URL=\'/ui\'': 'VMWARE',
        '/internalLib/SNC': 'Sony Network Camera',
        'nmbl-gui/config/environment': 'HPE Nimble Storage',
        'nmblOemName': 'HPE Nimble Storage',
        'Cisco IP Phone': 'Cisco IP Phone',
        'Cisco Unified IP Phone': 'Cisco Unified IP Phone',
        '<div id="pgm-theatre-staging-div">': 'HP Printer', # not overly sure about this signature
        '<div ng-view=': 'Wisenet', # not overly sure about this signature
        'url =\'/webui':'Cisco Device Login Page',
        'netbotz':'Netbotz Camera',
        'location.hostname+pt+redirect_suffix':'QNAP NAS',
        'url = url + \'&bj4=\' + md5(url.split(\'?\')[1]);':'Netgear Device',
        '/bannercontents.txt':'Crestron Login Page',
        'webpackJsonpquickconnect=this.webpackJsonpquickconnect':'Solstice Quick Connect',
        '../index.htm?clientIpAddr=':'Univision IP Camera Login',
        'document.location.replace(\'./home/monitoring.cgi':'Samsung Network Camera'
    }
    # Keys = item:
    # values = :item
    sig_keys = signatures.keys()

    for key in sig_keys:
        if response_text.find(key) != -1:
            return ' Title: ' + signatures[key]

    return ''

def get_title(response_text):
    if len(response_text) < 5:
        return ' Blank Page'
    if response_text.lower().find('<title') == -1: # if there is no title to the page check if we have a signature for it
        return sig_check(response_text)
    if sig_check(response_text) != '': # go off of signature first
        return sig_check(response_text)
    tmp = response_text[response_text.lower().find('<title'):]
    if len(tmp[tmp.find('>') + 1:tmp.lower().find('</title>')]) < 2: # if the webpage gives a blank title check if we have a signature for it
        return sig_check(response_text)
    tmp1 = ' Title: ' + tmp[tmp.find('>') + 1:tmp.lower().find('</title>')] # if we dont have a signature but there is a title that is longer than 2 chars return this
    tmp1 = tmp1.replace('\n', '')
    return tmp1


def https_chk(target):
    try:
        x = requests.get('https://{}'.format(target), timeout=5, verify=False)  # make an https request
        if options.i is not None:
            if str(x.status_code) not in options.i:
                print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))
                if options.o is not None:
                    with open(options.o, 'a') as f:
                        f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                        f.close()
        else:
            print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))
            if options.o is not None:
                with open(options.o, 'a') as f:
                    f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                    f.close()

    except KeyboardInterrupt:
        sys.exit(1)
    except BaseException as e:
        if options.se:
            if str(e).find('Max retries exceeded with url') != -1:
                print('Host {} is not alive'.format(target))
            else:
                print('Host {} returned an error {}'.format(target, e))
        if options.debug:
            import traceback

            traceback.print_exc()
        pass

def mt_execute(target):
    try:
        if len(target) > 0:
            x = requests.get('http://{}'.format(target), timeout=5)  # make an http request

            if x.status_code == 400:
                https_chk(target)
                return

            if options.i is not None:
                if str(x.status_code) not in options.i:  # check if our response is a code designated to be ignroed
                    print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))  # print our output
                    if options.o is not None:
                        with open(options.o, 'a') as f:  # if options.o then save the target
                            f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                            f.close()
            else:
                print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))
                if options.o is not None:
                    with open(options.o, 'a') as f:
                        f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                        f.close()
    except KeyboardInterrupt:
        sys.exit(1)
    except requests.exceptions.ConnectionError:  # if the server is running https we should get this
        https_chk(target)
    except ConnectionResetError:
        https_chk(target)
    except BaseException as e:
        if options.se:
            if str(e).find('Max retries exceeded with url') != -1:
                print('Host {} is not alive'.format(target))
            else:
                print('Host {} returned an error {}'.format(target, e))
        if options.debug:
            import traceback

            traceback.print_exc()
            return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('inputfile', action='store', help='list of ips to check can be formatted as IP or IP:PORT one per line')
    parser.add_argument('-i', action='store', help='Status codes to ignore list seperated by a comma eg 404,503,200')
    parser.add_argument('-o', action='store', help='output file')
    parser.add_argument('-debug', action='store_true', help='Turn on debugging')
    parser.add_argument('-se', action='store_false', help='Skip any errors from printing')
    parser.add_argument('-threads', action='store', default=5, type=int, help='Threads to use for multithreading Default=5')

    # Suppress only the single warning from urllib3 needed.
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    with open(options.inputfile, 'r') as f:  # read our inputfile
        dat = f.read()
        f.close()

    target_list = dat.split('\n')  # split it into a list

    if options.i is not None:  # if they gave us an options.i lets make it a list the split function does not cause issues if there is no comma it will just appear as 1 string in the list
        options.i = options.i.split(',')
    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        for target in target_list:
            executor.submit(mt_execute, target)
