import threading
from socket import *
from optparse import OptionParser
import nmap
import time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m' # Add this color for reseting back the color.

banner = r"""{}{}
 ____   __   ____  ____        ____   ___   __   __ _
(  _ \ /  \ (  _ \(_  _)      / ___) / __) / _\ (  ( \
 ) __/(  O ) )   /  )(        \___ \( (__ /    \/    /
(__)   \__/ (__\_) (__)       (____/ \___)\_/\_/\_)__)
==========================================================
""".format(bcolors.OKGREEN,bcolors.BOLD,bcolors.WARNING,bcolors.OKBLUE,bcolors.ENDC)

class Scan():
    def osScan(self, ipaddr, openPorts):
        print "+++++++++++++++++++++++++++++++++++++++++++++[!] Wait till OS detection is completed [!]+++++++++++++++++++++++++++++++++++++++++++++++++++++         "
        nm = nmap.PortScanner()
        if not openPorts:
            print "No open port has been detected by the range provided"
            return
        arguments = '-O -p ' + str(openPorts[0]) + ' '
        for i in range(1, 65535):
            if i not in openPorts:
                arguments = arguments + str(i)
                break
        response = nm.scan(ipaddr, arguments=arguments)
        cpe = ""
        if len(response['scan'][ipaddr]['osmatch'][0]['osclass']) > 1:
            cpe = response['scan'][ipaddr]['osmatch'][0]['osclass'][1]['cpe'][0]
        else:
            cpe = response['scan'][ipaddr]['osmatch'][0]['osclass'][0]['cpe'][0]
        print "[+] Address : "  + ipaddr
        print "[+] OS family : " + response['scan'][ipaddr]['osmatch'][0]['osclass'][0]['osfamily']
        print "[+] cpe : " + cpe
        print "[+] Detection accuray : " + response['scan'][ipaddr]['osmatch'][0]['osclass'][0]['accuracy']

        print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

    def serviceScan(self, ipaddr, ports):
        for port in ports:
            nm = nmap.PortScanner()
            response = nm.scan(ipaddr, arguments='-sV -T 4 -p ' + str(port))
            print "[+] Port number : " + str(port)
            print "[+] Its service : " + response['scan'][ipaddr]['tcp'][port]['product']
            print "[+] Its version : " + response['scan'][ipaddr]['tcp'][port]['version']
            print "[+] Its name : " + response['scan'][ipaddr]['tcp'][port]['name']
            print "------------------------------------------------------"


class ip():
    #lock = threading.Semaphore(value=1000)
    openPorts = []
    def __init__(self, option):
        self.option = option
        self.initialize_variable()
        self.multithread(self.ipaddr)
        if self.option.osDetection:
            self.scan = Scan()
            self.scan.osScan(self.ipaddr, self.openPorts)
    def initialize_variable(self):

        self.verbose = False
        # This switch is to be used when the port number is defined.
        # to display if the designated port is closed or not.


        print banner
        # This function is for initializing the necessary command arguments and automate default values when one is empty
        # For target argument, the default value is 'Localhost' ('127.0.0.1')
        # As for port range, I think it's just necessary to scan from port 20 to 1024

        # Generate a list and assign it to self.portrange

        if self.option.target:
            if self.option.target[0].isdigit():
                self.ipaddr = self.option.target
            elif self.option.target[0].isalpha():
                addr = (self.option.target)
                if 'http://' in addr: addr = addr.strip('http://')
                self.ipaddr = self.resolve(addr)

        elif not self.option.target:
            print "\n[!] --target argument is not supplied, default value (localhost) is taken"
            self.ipaddr = '127.0.0.1'

        if self.option.portrange:
            if '-' in self.option.portrange:
                self.lowRange = int(self.option.portrange.split('-')[0])
                self.highRange = int(self.option.portrange.split('-')[1])
            else:
                self.lowRange = int(self.option.portrange)
                self.highRange = ""

        elif not self.option.portrange:
            print("[!] --portrange argument is not supplied, default value (20-1024) is taken\n")
            self.highRange = 1024
            self.lowRange = 20

        if self.option.maximunSocket:
            self.lock = threading.Semaphore(int(self.option.maximunSocket))
        else:
            self.lock = threading.Semaphore(1000)



    def resolve(self, host):
        # Get website and translate it to IP address
        # Using very low level socket module
        print("[+] Target argument received website address")
        print("[+] Resolving website address to ip address")
        try:
            ip = gethostbyname(host)
        except gaierror:
            print(bcolors.WARNING+"[!] Error resolving website to ip, please get ip address manually"+bcolors.ENDC)
            exit()
        else:
            #print((bcolors.OKBLUE+"[+] %s = %s"+bcolors.ENDC) % (host, ip))
            print("{}[+] {} = {}".format(bcolors.OKBLUE,host,ip,bcolors.ENDC))
            return ip


    def scan(self,ipaddr,port, timeOut):
        # Accepts ipaddress parameter, and port to scan is accepted as port(type=int)
        # Only prints when the port is OPEN
        # Or set your own error message to display with "else" code block
        #print("[.] Scanning %s : %s" % (ipaddr,port))
        setdefaulttimeout(timeOut)
        s = socket(AF_INET,SOCK_STREAM)
        status = s.connect_ex((ipaddr,port))
        if (status == 0):
            print("[+] =[\033[91m{:^6}\033[0m]= Port Open".format(port))
            self.openPorts.append(port)

        else:
            if self.verbose:
                print("{}[+]=[{}]= Port closed{}".format(bcolors.FAIL, port, bcolors.ENDC))
            elif not self.verbose:
                pass
        s.close()
        self.lock.release()
        return


    def online(self,ip):
        """ Check if target is online using nmap -sP probe """
        # -sP probe could be blocked. Check for common ports.
        # there could be solution with socket module.
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments='-sP')
            result = nm[ip].state()
            if not result:
                result = nm['scan'][ip].state()
        except KeyError:
            pass
        else:
            if result == 'up':
                return True
            else:
                return False

    def multithread(self,ipaddr):
        #detectionFlag = False
        # Handles port scanning operation with multi-threading
        try:
            # Check if the target is online or offline first.
            if self.online(ipaddr):
                print("[~] Target : "+bcolors.HEADER+"%s"%ipaddr+bcolors.ENDC)

                if not self.highRange:
                    t = threading.Thread(target=self.scan,args=(ipaddr, self.lowRange, 1)).start()
                    return

                if self.highRange > 10000:
                    for i in range(self.lowRange, 10001):
                        self.lock.acquire()
                        threading.Thread(target=self.scan,args=(ipaddr, int(i), 1)).start()
                    for j in range(10001, self.highRange + 1):
                        self.lock.acquire()
                        threading.Thread(target=self.scan,args=(ipaddr, int(j), 2)).start()
                else:
                    for j in range(self.lowRange, self.highRange):
                        self.lock.acquire()
                        threading.Thread(target=self.scan,args=(ipaddr, int(j), 1)).start()


            elif not self.online(ipaddr):
                print("[!] Target IP is offline, or blocking nmap -sP probe")

        except KeyboardInterrupt:
            print("[~] Process stopped as TERMINATE Signal received")

    def bannergrab(self,ipaddr,port):
        s = socket()
        s.connect_ex((ipaddr,port))
        s.send('GET HTTP/1.1 \r\n')

        response = s.recv(1024)
        time.sleep(3)
        if response:
            pass
        print "[Banner Information]\n%s" % response

def parseArgs():

    parser = OptionParser()

    parser.add_option("-t","--target",dest="target",
    help="IP Address to scan",metavar="127.0.0.1")

    parser.add_option("-p","--port range",dest="portrange",
    help="Port Range to scan separated with -",metavar="5-300 or 80")

    parser.add_option("-o","--os", action='store_true', default=False, dest='osDetection', help="Target OS scan")

    parser.add_option("-s","--service", action='store_true', default=False, dest='serviceScan', help="Target service scan")

    parser.add_option("-n", dest='maximunSocket', type="string", help="Maximum number of open sockets")


    return parser

def main():
    parser = parseArgs()
    (option, args) = parser.parse_args()
    scan = Scan()
    app = ip(option)


    if option.serviceScan:
        scan.serviceScan(app.ipaddr, app.openPorts)

if __name__ == '__main__':
    main()
