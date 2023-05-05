import scapy.all as scapy
import optparse

def scan(ip):
    tcp_request = scapy.ARP(pdst=ip)
    broadast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broad = broadast/tcp_request
    ans = scapy.srp(arp_request_broad, timeout=1, verbose=False)[0]
    print("------------------------------------------------\nIP\t\t\t Mac Address\n------------------------------------------------")
    data={each[1].psrc:each[1].hwsrc for each in ans }
    return data
    
        
def print_result(ans):
    for key,val in ans.items():
        print(key,"\t\t",val)   

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP target/ IP ranges")
    (options, arguments) = parser.parse_args()
    print_result(scan(options.target))