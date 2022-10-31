# ACP.py

ACP.py is a python3 tool that allow you to exploit an MiTM between the router and the victim by using the ARP spoofing vulnerability. 


# Installation :
```
git clone https://github.com/PxS-DuoSec/ARP-Cache-poisoning.git
cd ARP-Cache-poisoning
pip3 install -r requirements.txt
```

# Usage :

![ACC](https://user-images.githubusercontent.com/95232318/164916552-0fd40079-3d02-40d6-9a75-dd3daf460582.png)


# Exemple :
![a](https://user-images.githubusercontent.com/95232318/164916932-6461aa9c-1379-4376-9812-79f45d0af798.png)


Open wireshark, then in the filter bar type ``ip.addr=$THE_VICTIM_IP``, and you will see all the trafic between the victim machine and the others machines.

# Informations :

- Written by : Presta 
- Language : Python3
