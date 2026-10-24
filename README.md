# python-tools

## Install with pipx

pipx installs all the tools and their dependencies in one isolated environment. Each script becomes a command with the same name, for example `slowspray.py`.

Prerequisites:

- `pipx`
- A C compiler and the Python headers. The `netifaces` dependency has no prebuilt wheel for new Python versions, so pip compiles it. On Debian or Kali, run `sudo apt install build-essential python3-dev`.

To install the tools, run this command:

```bash
pipx install git+https://github.com/spextat0r/python-tools.git
```

To install from a local clone, run `pipx install .` in the clone directory. To update the tools, run `pipx upgrade python-tools`.

Some tools must run as root. The `sudo` command does not search `~/.local/bin`, so give `sudo` the full path of the command:

```bash
sudo "$(command -v slowspray.py)" -h
```

`secretsdumpplus.py`, `relayxdump.py`, and `smbserver.py` write their output to the directory that contains the script. After a pipx install, this directory is `python-tools/bin` in the pipx venvs directory. The `pipx list` command shows the venvs directory.

## slowspray.py

slowspray is a Python tool using Impacket to password spray a Windows Domain with a delay to evade being blocked by defenses.

## secretsdumpplus.py

secretsdumpplus is a fork of Impacket's secretsdump.py example to include multithreading and the ability to target more than one machine at a time outputting files to a default loot directory.

## netNtlm-uniq.py

netNtlm-uniq works the same as the uniq command in bash, however it is designed to be used for netNTLMv1 and v2 hashes that are salted.

## gen-userlist.py

gen-userlist is a tool that requires SecLists to be downloaded. gen-userlist will use the list of firstnames and lastnames within SecLists to create an extremely large list of potential usernames in common formats that enterprises use. This can be comnined with Kerbrute's userenum to get a list of valid usernames that can be password sprayed.

## difforsame.py

difforsame is a slightly more helpful version of the diff command.

## newline-to-space.py

newline-to-space - self expanatory.

## ibm_db2-connect.py

ibm_db2-connect is a tool to connect to IBMDB2 servers. I have setup a server and checked some of the outputs to try and determine what output goes to what case. Its not perfect but it should save you some time setting your own server up which is a pain.

## userenum.py

userenum will interact with the Kerberos service on a domain controller to see if a username exists.

## smbexec-multi.py

smbexec-multi will execute a command on multiple machines at once (non interactive) but it will get the commands output.

## wwwchk.py

wwwchk is a tool that will take a list of IPs or IP:Ports and see if they are hosting a webpage there printing the response code. This is useful if you are needing to check a lot of IPs and need to filter out undesirable response codes like 404 and 403 quickly. 

## relayxdump.py

relayxdump.py is a tool to be used in conjunction with ntlmrelayx.py from impacket to dump SAM and LSA Secrets from any relays that you have admin to This requires either crackmapexec to be installed or for you to point the tool to a secretsdump.py file with impacket installed.

## llmnr-scanner.py

llmnr-scanner.py is a tool that will check a remote host to see if it is allowing LLMNR traffic that may make it vulnerable to network poisoning attacks. Note you need to be on a close subnet to the host does not need to be the same one but enough distance and it seems to fail.

## trafficscan.py

this tool does the same as llmnr-scanner.py but includes checks for mdns and netbios. It only requires the python imports it uses and python.

## hostname-enum.py

This tool tries to get a hostname given an ip, cidr, or file of ips/cidrs using a few methods other than nslookup since that is hit or miss at best.
