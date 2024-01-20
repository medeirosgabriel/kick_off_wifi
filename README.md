# Wifi Kick Off
## References
- ### [GitHub adreafioraldi](https://gist.github.com/andreafioraldi/9f8a9e23a363c069b3dd61e56897f4c0)
- ### [geeksforgeeks](https://gist.github.com/andreafioraldi/9f8a9e23a363c069b3dd61e56897f4c0)
## Goal: remove devices that are on the same wifi network
## Strategy: ARP Spoofing
## Libraries:
- ### Scapy


## How ARP Spoofing works:

```
packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=target_ip, hwdst=target_mac)
```
### The code represents:
```
{
     'op': 2, # ARP operation type (2 for ARP response)
     'psrc': gateway_ip, # Source IP address (gateway IP)
     'hwsrc': '12:34:56:78:9A:BC',# Source MAC address (MAC of the device sending the packet)
     'pdst': target_ip, # Destination IP address (target device IP)
     'hwdst': target_mac # Target MAC address (target device MAC)
}
```

### Here is how a computer interprets this information when receiving this ARP packet:

- Type of Operation (op): The value 2 indicates an ARP response. In other words, the device is responding to a previous ARP request.
- Source IP Address (psrc): Indicates the IP address of the device sending the packet. In this case, it is the IP of the gateway (router).
- Source MAC Address (hwsrc): Specifies the MAC address of the device sending the packet. In this example, it is '12:34:56:78:9A:BC'.
- Destination IP Address (pdst): Indicates the IP address of the target device to which the ARP packet is being sent.
- Destination MAC Address (hwdst): Specifies the MAC address of the target device. In this example, it is the MAC of the target device.

### Upon receiving this ARP packet, the target device (with the IP address target_ip) would update its ARP table with the information provided. This means that the device would now associate the IP address gateway_ip with the MAC address '12:34:56:78:9A:BC' in its ARP table.


