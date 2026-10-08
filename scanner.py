import nmap as nm
import json
from scapy.all import ARP, Ether, srp

print("=====Network Asset Discovery v0.1=====")

print("""
Welcome to Network asset discovery v0.1!

Ability: Gets information about the network address.

""")

checkAddress = input("Network Address/Subnet/CIDR: ")

# Request an ARP!
print()

print("====ARP Scan====")
RequestARP = ARP(pdst=checkAddress)
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = broadcast / RequestARP

a,b = srp(packet, timeout=2, verbose=False)

macAddress = ""
for sent, received in a:
    macAddress = received.hwsrc
    print(f"IP: {received.psrc}, MAC: {received.hwsrc}")

print()

print("====ICMP Scan====")

scanner = nm.PortScanner()
scanner.scan(hosts=checkAddress, arguments="-sn")

hosts = scanner.all_hosts()

resultsinJson = []


for i in hosts:
    portLists = []
    print(f"Address: {i}")
    print(f"State: {scanner[i].state()}")
    print("\n")
    print("Analyzing results...")

    print()
    if scanner[i].state() == "up":
        results = scanner.scan(hosts=checkAddress, arguments="-sS -sV -O")
        ports = results['scan'][i]['tcp']
        print("Port", "Service", "Status", "Version")
        print("====================================")
        for j in ports:
            p = ""
            if ports[j]['version'] == "":
                p = "Undetected"
            else:
                p = ports[j]['version']
            print(j, "  " + ports[j]['name'], ports[j]['state'], p)
            if p == "Undetected":
                dataPorts = {"Port":j, "Service":ports[j]['name']}
            else:
                dataPorts = {"Port":j, "Service":ports[j]['name'], "Version":p}
            portLists.append(dataPorts)
        print()
        print(f"OS used: {results['scan'][i]['osmatch'][0]['name']}")
    else:
        print("The network seems down. Please check your device.")
        break
    if macAddress == "":
        basicInfo = {"ip":i, "Status":scanner[i].state(), "Open_Ports":portLists, "OS":results['scan'][i]['osmatch'][0]['name']}
    else:
        basicInfo = {"ip":i, "mac":macAddress, "Status":scanner[i].state(), "Open_Ports":portLists, "OS":results['scan'][i]['osmatch'][0]['name']}
    resultsinJson.append(basicInfo)
    print()

r = json.dumps(resultsinJson, indent=4)

with open("results.json", "w") as f:
    f.write(r)
    print("File is saved in JSON within the current directory.")


