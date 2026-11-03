from scapy.layers.inet import IP,ICMP,TCP,UDP
from scapy.layers.l2 import Ether,ARP
from scapy.sendrecv import sr1,srp,sniff,sr
from scapy.all import * 
import psutil 
import time



def ping_on_host(_ip_address:str):
    '''ping'''
    packet = IP(dst=_ip_address)/ICMP() #! ICMP messagess must be encapsulated in IP packets 
    packet.show()
    response = sr1(packet,timeout=2,verbose=1)
    print(response)


def arp_host_discovery(delay:int, network:str = "192.168.1.0/24")->list[dict]:
    '''ARP scan a network, identifying devices'''
        #!creating an arp packet 
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=network)
    packet = ether/arp
    ans, uans = srp(packet,iface="en0",verbose=1,timeout=delay) #! timeout means how much time to wait after the last packet has been sent, returns a tuple of list 

    print("Inactive devices/No responses: ")
    uans.show()
    print()

    print("Active devices: ") #! much clearer in my opinoin  showing arp request and reply 
    ans.show()
        #!access ans list which contains send and receive, we want to show the received part 
    lst = []
    for i in ans: # ! contains two things, sent and received, we only want to access receive 
        info_dict = {"IP":i[1].psrc,"MAC":i[1].hwsrc}
        lst.append(info_dict)
    return lst

def convert(bytes):
    for char in ["","K","M","G","T","P"]: # ! the unit is associated with the value in every iteration, it gets larger as the iteration goes up 
        if bytes < 1024:
            return f"{bytes:.2f} {char}B/s"
        
        bytes /= 1024 #!each iteration reduces the number and changes the unit 

def bandwidth_monitoring(delay:int)->None:
    '''monitor how many bytes and packets are the network
    \n receiving and sending'''
    try:
        current_stats = psutil.net_io_counters()
        cbr, cbs = current_stats.bytes_recv,current_stats.bytes_sent

        time.sleep(delay)

        later_stat = psutil.net_io_counters()
        nbr, nbs = later_stat.bytes_recv, later_stat.bytes_sent

        upload = nbs - cbs #diff in sent
        download = nbr - cbr # diff in getting/downloading 

        print("\nSpeed difference")
        print(f"Upload:{convert(upload)}, Download:{convert(download)}")

        #!bytes transferred

        print(f"Bytes sent: {convert(nbs)}")
        print(f"Bytes received: {convert(nbr)}")
        print(f"Packets Sent: {later_stat.packets_sent} packets")
        print(f"Packets received: {later_stat.packets_recv} packets")

    except psutil.TimeoutExpired as tm:
        print("Timeout")
        raise 


def packet_sniffing(pkt_limit = 10,netiface = None, filter_packet = None,verboseornot=False):
    """packets sniffing, packet_limit , interface and packet type
        \n are optiional parameters"""
    #sniff initialization,maximum flexibility 
    try:
        if verboseornot == True:
            print(f"Capturing {pkt_limit} packets in VERBOSE mode...\n")
            sniff(iface=netiface,
                prn = lambda x:x.show(),
                count=pkt_limit,
                filter=filter_packet,
                store=0
            )    
        else:
            print(f"Capturing {pkt_limit} packets in SUMMARY mode...\n")
            #! More neat and precise summary than the default 
            def key_info_extract(packet):
                #! going down the rabbit hole, accessing a particular part of a packet and perform checking
                #! check if the packet contains IP layer, who is in 
                if IP in packet: 
                    protocol = "Unknown"
                    info = ""
                
                    if TCP in packet: #! check if TCP layer exists within the IP packet , who is in 
                        protocol = "TCP" #!L3
                        info = f"Port {packet[TCP].sport} -> {packet[TCP].dport}" #! Accessinf the IP layer from this packet,access source and deatination 
                    elif UDP in packet: #! keep checking if UDP layer exists within the IP packet , who is in 
                        protocol = "UDP" #!L3
                        info = f"Port {packet[UDP].sport} -> {packet[UDP].dport}"
                    
                    elif ICMP in packet: #!keep checking  if ICMPn layer exists within the IP packet , who is in 
                        protocol = "ICMP" #!L3 
                        info = f"Type {packet[ICMP].type}"
                    
                    print(f"{protocol:<6} {packet[IP].src:<15} -> {packet[IP].dst:<15} {info }")

                elif ARP in packet: #! work at layer 2, encapsulated within Ethernet , no IP 
                    print(f"ARP  {packet[ARP].psrc} -> {packet[ARP].pdst}")


            sniff(iface=netiface,
                prn = key_info_extract,
                count=pkt_limit,
                filter=filter_packet,
                store=0
            )

        print("Capture completed...")
    

    except Exception as e:
        print("Error occured during captture",e)

def netiface_status_display():
    '''Display network interface statistics'''
    all_interfaces = get_if_list()
    print(f"\nTotal interface: {len(all_interfaces)}")
    for i, interface in enumerate(all_interfaces,1):
                print(f"\n{i}:{interface}")
    print()

    print("===NETWORK INTERFACE STATUS===")

    for interface_name,interface_obj in conf.ifaces.items(): #! a dict like object 
        if "UP" in interface_obj.flags:
            status = "🟢UP"
        else:
            status = "🔴DOWN"
        print(f"\nInterface: {interface_name}")
        print(f" Status: {status}")


        if hasattr(interface_obj,"ip") and interface_obj.ip: #! check if the object contain such attribute and actually has an ip 
            print(f" IP: {interface_obj.ip}")
        else:
            print(f"IP: Not assigned/Not in use/No active connections") #! some interfaces are up but there is no active connections 

        if hasattr(interface_obj,"mac") and interface_obj.mac:
            print(f"MAC: {interface_obj.mac}")
    print()
    print("===Routing information===")
    print(conf.route)


    
    
def scan_all():
    #create a well rounded ui for user experience
    # i want the user to execute all functions, show everything   
    while True:
        print("""███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
""")
        #!reconsier the usecases, honstly i would like to just execute everything sequently (will change)
        print("\n Available Functions:\n")
        print("  1. Ping Host - Check if a host is reachable")
        print("  2. ARP Scan - Find all devices on network")
        print("  3. Bandwidth Monitor - Track upload/download speeds")
        print("  4. Packet Sniffer - Capture and analyze packets")
        print("  5. Network Info - Show interface status and routing")
        print("\n  q to  Quit")
        try:
            choice = input("Enter a number: ").strip().lower()

            if choice == "1":
                ip = input("\nEnter ip address: ")
                ping_on_host(ip)
            elif choice == "2":
                arptime = int(input("Enter time delay: "))
                arp_network = input("Enter network address: ")
                print(arp_host_discovery(arptime,arp_network))
            elif choice == "3":
                bwtime = int(input("Enter time delay: "))
                bandwidth_monitoring(bwtime)

            elif choice == "4":
                pkl = int(input("Enter the number of packets to show: "))
                iterface = input("Enter network interface: ")
                ptype = input("Enter packet type to filter: ")
                packet_sniffing(pkl,iterface,ptype,verboseornot=True)
            
            elif choice == "5":
                netiface_status_display()

            elif choice == "q":
                print("Terminated,bye")
                break
            
            else:
                print("Invalid choice, Only 1 to 5 or q")
    
        
        except ValueError as v:
            print("Invalid value",v)
        
        except Exception as e:
            print("Error occured: ",e)
        
        
if __name__ == "__main__":
    scan_all()


            




        