import time
import sys

import requests

def find_RTT(target_url): 
    with requests.Session() as session: 
        # Connect to TOR's default SOCKS port. 
        session.proxies = {'http':  'socks5://127.0.0.1:9050',
                           'https': 'socks5://127.0.0.1:9050'}

        response = session.head(target_url)
        assert response.ok
        return response.elapsed


if __name__ == '__main__': 
    print(find_RTT('http://google.com/'))
