from scapy.all import *
import csv,json
import joblib
import netifaces
import sys,os
import subprocess,requests
import urllib3
from scapy.all import sniff, rdpcap, DNS, IP, UDP, TCP,DNSRR
import pandas as pd
from pymisp import PyMISP
import dns.resolver
from string import ascii_letters, digits
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from scipy.stats import entropy
import dns.exception
from dotenv import load_dotenv
import threading
import time


#headers = {'Authorization': 'a050b96276f0646d380048e886dc9288'}

load_dotenv()
"""_________________________________________________MISP_________________________________________________"""



def check_domain(domain):
    # url or IP address of MISP instance
    MISP_URL = os.environ.get("MISP_URL")
    # your API authentication key, generated using your MISP instance
    MISP_KEY = os.environ.get("MISP_KEY")
    # create MISP instance to interact with using Python methods
    misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False)
    http = urllib3.PoolManager()
    response = misp.search(value=domain)
    if response:
        print("--- Matching Event ---")
        print(f"Event ID: {response[0]['Event']['id']}")
        print(f"Event Info: {response[0]['Event']['info']}")
        print(f"Date Added: {response[0]['Event']['date']}")
        print(f"Tags: {response[0]['Event']['date']}")
        for tag in response[0]['Event']['Tag']:
            print(f"- {tag['name']}")
        print("-" * 20)
        return True
    else:
        print(f"The domain {domain} is not in MISP")
        return False
    


"_________________________________________________CONVERT TO CSV_________________________________________________"

def save_to_csv(filename, data):

    f = open(filename,'a+')
    with f:
        writer = csv.writer(f)
        for row in data:
            writer.writerow(row[1])



"_________________________________________________CONVERT TO JSON________________________________________________"
def save_to_json(rows,filename):

    donnees_json = json.dumps(rows, indent=4)  # Convertir la liste en une chaîne JSON
        # Écrire les données au format JSON dans un fichier
    with open(filename, "a+") as fichier_json:
        fichier_json.write(donnees_json)     



"///////////////////////////////////////////////////MODEL/////////////////////////////////////////////////////////////"
def make_prediction (len,size_avg,size_stdev,throughput):
    url = 'http://127.0.0.1:8000/predict'  # l'URL de l'endpoint
    data = {
        "len": len,
        "size_avg": size_avg ,
        "size_stdev":size_stdev
            }
    response = requests.post(url, json=data)
    if response.status_code == 200:
        print("Réponse reçue : ", response.json())  # Afficher la réponse JSON
    else:
        print("Erreur : ", response.status_code)    
    
    
"____________________________________________________FIN MODEL_________________________________________________________"


    


def check_NXDOMAIN(domain):
    resolver = dns.resolver.Resolver()
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
    try:
        for record_type in record_types:
            answers = resolver.resolve(domain, record_type)
    except dns.resolver.NoAnswer:
        print(f"No records found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"NXDOMAIN: The DNS query name does not exist: {domain}")
        return True
    except dns.exception.Timeout:
        print (domain)
        print("DNS query timed out")
    except dns.exception.DNSException as e:
        print(f"DNS query failed: {e}")
    return False





def validate_fqdn(fqdn):

    """Évaluation de la taille des requêtes et des réponses"""

    # Vérification de la longueur totale
    if len(fqdn) > 255:
        return False
    # Vérification de la longueur des labels
    labels = fqdn.split('.')
    for label in labels:
        if len(label) > 63:
            return False
       
    # Vérification des caractères autorisés dans chaque label
    label_regex = re.compile(r'^[a-z0-9-]{1,63}$', re.IGNORECASE)
    """re.IGNORECASE est utilisé pour rendre le modèle insensible à la casse"""

    for label in labels:
        if not label_regex.match(label):
            return False
    return True
def get_valid_path():
    for i in range(3):
        file = input("Enter the path of your pcap file: ").strip()
        if os.path.exists(file):
            return file
        else:
            print("The file doesn't exist. Please check the path.")
            if i < 2:
                print(f"You have {2 - i } attempts remaining.")
            else:
                print("You've used all your attempts. Exiting program.")
                exit()

def get_valid_port ():
   
    port_number= input ("Please choose a port number: ").strip()
    if port_number not in ['53','443','853']:
        port_number= input ("Please choose a port number for dns: ").strip()
    return(port_number)

        
def answers(packet,ancount,):
    if DNSRR in packet:
        ant =[]
        for i in range(ancount):
            for answer in packet[DNS].an:
                ant.append({
                    'rrname': answer.rrname.decode(),
                    'type': answer.type,
                    'rclass':packet[DNS].an.rclass,
                    'ttl': answer.ttl,
                    'rdlen': answer.rdlen,
                    'rdata': answer.rdata,
                })
                df1 = pd.DataFrame(ant)
        else :
            ant='NAN'
        return ant
def nsanswers (packet, nscount):
        if DNSRR in packet:
            nst = []
            for i in range (nscount):
                nst.append({
                    'rrname': packet[DNS].ns.rrname.decode(),
                    'type': packet[DNS].ns.type,
                    'ttl': packet[DNS].ns.ttl,                    
                    'rclass':packet[DNS].ns.rclass
                    })
                df2= pd.DataFrame(nst)
        else:
                nst='NAN'
        return nst
def list_interfaces():

    iface = []
    interfaces = netifaces.interfaces()
    for i in interfaces:
        iface.append(i)
    return iface

def get_ip_address(domain):

    try:
        ip_address = socket.gethostbyname(domain)
       
    except socket.gaierror:
        ip_address='n/a'
    return ip_address

    

dns_lengths=[]
def calculate_length_without_tld(request):
 # Retirer le point final si présent
    request = request.rstrip('.')

    parts = request.split('.')
    if request.endswith('.'):
        # Vérifier si le domaine a plus de deux parties
        if len(parts) > 2:
        # Joindre toutes les parties sauf les deux dernières
            return len('.'.join(parts[:-2]))
            # Si le domaine a exactement deux parties, retourner la longueur de la première partie
        elif len(parts) == 2:
            return len == 0
    # Sinon, retourner la longueur du domaine
    return len('.'.join(parts[:-2]))
    

# Calculer la taille moyenne des requêtes DNS
def calculate_average_size(lengths):
    if lengths:
        average_size = sum(lengths) / len(lengths)
        return average_size
    else:
        return 0
def handle_packet(packet):
    rows=[]
    if DNS in packet and IP in packet:
        protocol = None
        data_len = None
        nst = []
        ant =[]
        data_len = len(packet[UDP].payload) if  UDP in packet else len(packet[TCP].payload) if TCP in packet else 'N/A'
        src_port = packet[UDP].sport if UDP in packet else packet[TCP].sport if TCP in packet else 'N/A'
        dst_port = packet[UDP].dport if UDP in packet else packet[TCP].dport if TCP in packet else 'N/A'
    
        protocol= 'UDP'if  UDP in packet else 'TCP' if TCP in packet else 'N/A'
        query = packet[DNS].qd.qname.decode() if packet[DNS].qd else 'N/A'
        qr_flag = packet[DNS].qr
        qr_type = 'Query' if qr_flag == 0 else 'Response'
        nscount = packet[DNS].nscount
        ancount = packet[DNS].ancount
        qtype = packet[DNS].qd.qtype
        qclass= packet[DNS].qd.qclass
        nst=nsanswers(packet,nscount)
        ant=answers(packet,ancount) 
        length_without_tld=calculate_length_without_tld(query)

        average_size=calculate_average_size(dns_lengths)
        #throughput=calculate_throughput(query)
        #print (throughput)
        #model=make_prediction(1,1,1,1)
        #get_ip_address(query)
        if validate_fqdn(query) == True or check_NXDOMAIN (query) == True or check_domain(query) == True:
            attack=True      
            # Lancer script2.py dans un thread séparé
            thread = threading.Thread(target=launch_script2, args=(packet[IP].dst, packet[IP].src, query, protocol, src_port, dst_port))
            thread.start()
        else:
            attack=False 
      
               
        # Ajouter les nouvelles informations au DataFrame
        rows.append ({
            'attack': attack ,
            'Source IP': packet[IP].src,
            'Destination IP': packet[IP].dst,
            'Source Port': src_port,
            'Destination Port': packet[IP].dport,"dst_port"
            'misp response': check_domain(query) ,
            'Query': query,
            'length_without_tld':length_without_tld if  packet.haslayer(DNS) and packet[DNS].qr == 0 else 'N/A',
            #'ip of thr query':ipadd,
            'average_size': average_size,
            'Protocol': protocol,
            'request_size': data_len,
            'QR Type': qr_type,
            'AA': packet[DNS].ancount,
            'TC': packet[DNS].tc,
            'RD': packet[DNS].rd,
            'RA': packet[DNS].ra,
            'Opcode': packet[DNS].opcode,
            'Autorotative': 'yes' if 'autorotation' in query.lower() else 'no', #1 si Autorotative et 0 sinon 
            'ns':nst,
            'qclass':qclass,
            'qtype':qtype,
            'an':ant,
            'qdcount':packet[DNS].qdcount,
            'nscount':nscount,
            'ancount':ancount,
            'arscunt':packet[DNS].arcount,
            'entropy_score': entropy(list(str(query).encode('utf-8')))
        })       
             
          
        json_filename= "json_file" + datetime.now().strftime('%Y-%m-%d') +'.json'
        save_to_json(rows, json_filename)

        filename = "output11.csv"
        #save_to_csv(filename, rows)
    return rows
    


# Verrou pour synchroniser l'accès à la variable attacker
lock = threading.Lock()

# Fonction pour lancer script2.py
'''def launch_script2(dst,src,query,protocol,src_port,dst_port):
    args=[dst,src,query,protocol,src_port,dst_port]
    global attacker
    subprocess.call(["python", "/home/osboxes/Downloads/pfe-main/test2.py"]+ args)'''
    

def launch_script2(dst, src, query, protocol, src_port, dst_port):
    args = [str(dst), str(src), str(query), str(protocol), str(src_port), str(dst_port)]
    subprocess.call(["python", "/home/osboxes/Downloads/pfe-main/test2.py"] + args)

        



def start_live_capture(interface, port):
    print(f"Écoute sur l'interface {interface}... (Appuyez sur Ctrl+C pour arrêter)")
   
    try:
        sniff(iface=interface, filter=f"udp port  {port} ", prn=handle_packet, store=False)
    except KeyboardInterrupt :
        print("\nCapture arrêtée par l'utilisateur.")




def script_launch (attack,args):
        # Appel du deuxième script en passant les arguments
        subprocess.call(["python", "/home/osboxes/Downloads/pfe-main/test2.py"] + args, shell=True)

def lanche_fastapi () :
    subprocess.run("python",'api.py',shell=True)



if __name__ == '__main__':
    start= time.time()
    #t=threading.Thread(target=lanche_fastapi).start()
    #script_launch('192.168.1.10','192.168.1.1','domine.com','UDP')
    data=[]
    if len(sys.argv) > 1:
        if os.path.exists(sys.argv[1]):
            port_number=get_valid_port()
            data = handle_packet(sys.argv[1])
        else:
            print("The file doesn't exist. Please check the path.")  
   
    else:
       
            mode= input ("Please choose to analyze a \n - pcap_file analysis :1\n - real_time analysis :2 \n")
            if mode== "pcap_file"or mode =='1':
                file_path = get_valid_path()
                port_number=get_valid_port()
                try:
                    print(f"Lecture du fichier {file_path}...")
                    packets = rdpcap(file_path)
                    for packet in packets:
                        handle_packet(packet)
                except FileNotFoundError:
                    print(f"Erreur : Le fichier {file_path} n'a pas été trouvé.")
                    exit()
                except Exception as e:
                    print(f"Une erreur est survenue lors de la lecture du fichier : {e}")
            elif mode =='real_time'or mode =='2':
                port_number= get_valid_port()
                interface = int(input(f"These are your interfaces: {list_interfaces()}. Please choose one of them.").strip())
                if 0 <= interface < len(list_interfaces()):
                    iface = list_interfaces()[interface-1]
                else:
                    iface = interface
                start_live_capture(iface,port_number)          
            else:
                print("Mode inconnu, veuillez choisir entre 'temps réel' et 'fichier'.")
                exit()
    end=time.time()
    temps=end-start
    print (temps)



