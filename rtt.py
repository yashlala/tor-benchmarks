import time
import sys

from stem import Signal
from stem.control import Controller
import requests

# signal TOR for a new connection 
def renew_tor_circuit(controller):
    controller.signal(Signal.NEWNYM)

def find_circuit_RTT(target_url): 
    with requests.Session() as session: 
        # Connect to TOR's default SOCKS port. 
        session.proxies = {'http':  'socks5://127.0.0.1:9050',
                           'https': 'socks5://127.0.0.1:9050'}

        response = session.head(target_url)
        assert response.ok
        return response.elapsed


if __name__ == '__main__': 
    controller =  Controller.from_port(port=tor_port)
    controller.authenticate()
    print(find_circuit_RTT('http://bbc.co.uk/'))
