import threading
import os,sys
from elasticsearch import Elasticsearch
from datetime import datetime
import requests
import smtplib
from email.message import EmailMessage
from pymisp import PyMISP
import urllib3 
from dotenv import load_dotenv
from scapy.all import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



load_dotenv()


"""def creat_an_event ():
    # url or IP address of MISP instance
    URL = os.environ.get("MISP_URL")
    # your API authentication key, generated using your MISP instance
    KEY = os.environ.get("MISP_KEY")
    urllib3.disable_warnings()
    # create MISP instance to interact with using Python methods
    misp = PyMISP(URL, KEY, ssl=False, debug=False)
    endpoint='/events/add/'
    relative_pah= ''
    body={
        'info':'tessst',
        'thread_level_id':1,
        'distribution':0,
        'orgc_id':2,
        'threat_level_id':2
    }
    res =misp.direct_call (endpoint + relative_pah, body)
    print(res)
'''def creat_an_event ():
    endpoint='/events/edit/'
    relative_pah= ''
    body={
        'info':'tessst',
        'thread_level_id':1,
        'distribution':0
    }
    res =misp.direct_call (endpoint + relative_pah, body)
    print(res)'''"""
"""--------------------------------------------------------------------------------------------------------FW--------------------------------------------------------------------------------------------------------"""
def regle_de_filtrage ():
    ipdest_str = sys.argv[1]
    ipsrc_str = sys.argv[2]
    domaine = sys.argv[3]
    protocole = sys.argv[4]

    # Configuration de l'URL de l'API pfSense
    url = "https://192.168.20.1/api/v1/firewall/rule"
    headers = {
        "Authorization": "61646d696e 642d58b8535d2b22db92dfff0eb07f3d",
        "Content-Type": "application/json"
    }
    data = {
        "type": "block",  # "pass", "block" ou "reject"
        "interface": "lan",  # Interface sur laquelle la règle sera appliquée
        "ipprotocol": "inet",  # "inet" pour IPv4, "inet6" pour IPv6
        "protocol": protocole,  # Protocole utilisé
        "srcport": "53",  # Source de trafic
        "dst": ipdest_str ,  # Source de trafic
        "src": ipsrc_str,  # Source de trafic
        "dstport": any,  # Port de destination, par exemple "80" pour HTTP
        "descr": "add by script",  # Description facultative de la règle
    }
    # Envoyer une requête GET
    response = requests.post(url, headers=headers,data=data, verify=False)  # verify=False si certificat auto-signé

    http = urllib3.PoolManager()
    # Vérifier si la requête a réussi
    if response.status_code == 200:
        print("Réponse reçue avec succès !")
        data = response.json()
        print(data)
    else:
        print(f"Échec de la requête : Code d'état {response.status_code}")
        print("indexe:" ,response.text)     
"""///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////"""

"""-------------------------------------------------------------------------------------------------------MAIL-------------------------------------------------------------------------------------------------------"""


def send_mail():
    to_email = os.environ.get("to_email")
    from_email = os.environ.get("from_email")
    password = os.environ.get("email_password") 
    ipdest_str = sys.argv[1]
    ipsrc_str = sys.argv[2]
    domaine = sys.argv[3]
    msg = EmailMessage()
    msg.set_content ( f"""Cher administrateur,
                     
                     
Je tiens à vous informer qu'un incident de sécurité DNS a été détecté sur notre réseau. Les détails de l'incident sont les suivants :
                     
- Date et heure de détection :{time.strftime('%Y-%m-%d %H:%M:%S')}
- Adresse IP source : {ipsrc_str}
- Adresse IP destination : {ipdest_str}
- Domaine : {domaine}""" )


    msg['Subject'] = "Notification d'incident de sécurité DNS"
    msg['To'] = to_email
    msg['From'] = from_email

    try:
        server = smtplib.SMTP("smtp.office365.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
"""///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////"""

"""--------------------------------------------------------------------------------------------------------ELK--------------------------------------------------------------------------------------------------------"""
def create_daily_index():
    ipdest_str = sys.argv[1]
    ipsrc_str = sys.argv[2]
    domaine = sys.argv[3]
    # Informations d'identification
    username = 'elastic'
    password = 'elastic'
    # Connexion à Elasticsearch avec authentification
    es = Elasticsearch('http://192.168.20.10:9200', basic_auth=(username, password))

    # Vérification de la connexion
    print (es.ping())
    # Generate an index name with today's date
    index_name = 'script-' + datetime.now().strftime('%Y-%m-%d')
    # Define the index settings and mappings 
    settings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "data": {"type": "text"}
            }
        }
    }
    # Create index if it does not exist
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name, body=settings)
    # Index the document
    #es.index(index=index_name, document=document)
    log={
                "SRC_IP" : sys.argv[1],
                "DST_IP" : sys.argv[2],
                "request_date" :  datetime.now().isoformat() + 'Z',
                "request" :  sys.argv[3] ,
    }
    res = es.index(index=index_name, body=log)
 
"//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////"


if __name__ == '__main__':
    send_mail()
    #regle_de_filtrage() 
    create_daily_index() 
    

