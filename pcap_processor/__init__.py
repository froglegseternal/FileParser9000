class aarg():
    def __init__(self, dic):
        self.verbose = False
        self.debug = False
        self.data = False
        self.dhcp = False
        self.dns = False
        self.gquic = False
        self.http = False
        self.icmp = False
        self.igmp = False
        self.imf = False
        self.mdns = False
        self.ntp = False
        self.smtp = False
        self.xml = False
        self.arp = False
        self.ethernet = False
        self.frame = False
        self.ipdata = False
        self.tcp = False
        self.tls = False
        self.udp = False
        self.checks = False
        self.ctf = False
        for i in dic:
            self.__dict__[i] = dic[i]


args = aarg({"http":True,"frame":True,"data":True,"file":"/home/froglegs/Documents/pico/allpackets.json"})

"""
arser = argparse.ArgumentParser()
    parser.add_argument('-i', '--file', help='Path to the input file', required=True)
    parser.add_argument('-v', '--verbose', help="Whether to print requested information verbosely", action="store_true")
    parser.add_argument('--debug', help='Whether to print debug information', action='store_true')

    parser.add_argument('--data', help='Whether to print extraneous data information', action='store_true')
    parser.add_argument('--dhcp', help='Whether to print DHCP information', action='store_true')
    parser.add_argument('--dns', help='Whether to print DNS information', action='store_true')
    parser.add_argument('--gquic', help='Whether to print GQUIC information', action='store_true')
    parser.add_argument('--http', help='Whether to print the http data', action='store_true')
    parser.add_argument('--icmp', help='Whether to print ICMP information', action='store_true')
    parser.add_argument('--igmp', help='Whether to print IGMP information', action='store_true')
    parser.add_argument('--imf', help='Whether to print IMF information', action='store_true')
    parser.add_argument('--mdns', help='Whether to print MDNS information', action='store_true')
    parser.add_argument('--ntp', help='Whether to print NTP information', action='store_true')
    parser.add_argument('--smtp', help='Whether to print SMTP information', action='store_true')
    parser.add_argument('--xml', help='Whether to print XML information', action='store_true')

    parser.add_argument('--arp', help='Whether to print ARP information', action='store_true')
    parser.add_argument('--ethernet', help='Whether to print ethernet information', action="store_true")
    parser.add_argument('--frame', help='Whether to print frame metadata', action='store_true')
    parser.add_argument('--ipdata', help='Whether to print IP Data information', action='store_true')
    parser.add_argument('--tcp', help='Whether to print TCP information', action='store_true')
    parser.add_argument('--tls', help='Whether to print TLS information', action='store_true')
    parser.add_argument('--udp', help='Whether to print UDP information', action='store_true')

    parser.add_argument('--checks', help='Whether to attempt to validate every field is a correct value', action='store_true')
    parser.add_argument('--ctf', help='Whether to attempt to solve the current CTF problem', action='store_true')
"""
