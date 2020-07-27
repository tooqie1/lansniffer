import subprocess as subp
from multiprocessing.pool import ThreadPool
import ipaddress as net
import re
from string import ascii_letters

class Netscanner():

    @staticmethod
    def arp_command():
        process = subp.Popen(["arp", "-a"], stdout=subp.PIPE)
        output = str(process.communicate())
        return output

    @staticmethod
    def ping_obj(host):
        process = subp.Popen(["ping", "-n", "1", host], stdout=subp.PIPE)
        streamdata = process.communicate()
        if not 'Reply from {}'.format(host) in str(streamdata):
            return False
        else:
            print(f'Response from {host} received.')
            return True

    def get_interface_subnet(self):
        output = self.arp_command()
        interface = re.search('................ *-', output)[0].replace(':', '').replace(' ', '').replace('-', '')
        for i in ascii_letters:
            interface = interface.replace(i, '')
        interface = interface.rpartition('.')[0] + '.0/'
        return interface

    def arp_dump(self):
        ipx = []
        print('\n| ARP Cache dump')
        output = self.arp_command()

        findip = re.findall('............... +..-..-..-..-..-..', output)
        for item in findip:
            clean = item.replace('e\\r\\n', '').replace('r\\n', '').replace('\\n', '').replace('\\', '')
            ips = re.findall('.+ ', clean)
            for item in ips:
                cleanedip = item.replace(' ', '').replace('n','')
                ipx.append(cleanedip)

        maclist = re.findall('..-..-..-..-..-..', output)
        findmac = ['ff-ff-ff-ff-ff-ff', '01-00-5e-00-00-16']
        if findmac[0] in maclist:
            indx = maclist.index(findmac[0])
        else:
            indx = maclist.index(findmac[1])
        stopatbc = maclist[:indx]

        x = -1
        for obj in stopatbc:
            x += 1
            print(f'IP {ipx[x]} has a MAC of {stopatbc[x].replace("-", ":")}')

    def main(self):
        netaddr = input(f'\nPlease enter a Subnet!'
                        f'\nIf none entered, main interface will be used.'
                        f'\n')
        if netaddr == '':
            netaddr = self.get_interface_subnet()
        subaddr = input(f'\nPlease enter a Mask!'
                        f'\nDefault mask is CIDR 24')
        if subaddr == '':
            subaddr = '24'
        network = netaddr + subaddr

        HOSTLIST = [str(item) for item in net.ip_network(network).hosts()]
        print('\n| Pinging...')
        pool = ThreadPool(254).imap(self.ping_obj, HOSTLIST)
        for item in pool:
            pass

    def __init__(self):
        try:
            self.main()
            self.arp_dump()
        except Exception:
            print('\n!Something went wrong!')

while True:
    Netscanner()

# use re.search to find subnet of main interface and set that as target subnet
# ask for IP that user is searching for (or a list)
# map IP variables to MAC variables
# if MAC of IP is found in ARP Dump output then print (device is online)
