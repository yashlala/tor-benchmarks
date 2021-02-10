import io
import os.path
import itertools

import pandas as pd
import pycurl
import stem.control


# URL + HTTP resources we're fetching data from. 
URL = 'http://104.154.161.181:5003/'
URL_RESOURCES = [f'download{i}' for i in range(1, 6)]

# Data logging location. 
DATA_FILE = 'tor-benchmarks.csv'

# Fingerprint of the TOR exit node. 
# Currently set to: TorOrDie4privacyNET. 
# Based in US, IP addr: 104.244.73.43:443
EXIT_FINGERPRINT = '376DC7CAD597D3A4CBB651999CFAD0E77DC9AE8C'

# Local TOR proxy configuration. 
SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 10


def main(): 

    benchmark_data = []

    output_file = open('output.html', 'wb')
    query = pycurl.Curl()
    query.setopt(pycurl.URL, URL)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
    query.setopt(pycurl.WRITEFUNCTION, output_file.write)
    try:
        query.perform()
    except pycurl.error as exc:
        raise ConnectionError(f"Unable to reach {URL} ({exc})")
    output_file.close()

    benchmark_data.append((pd.Timestamp.now(), URL, '',
        query.getinfo(pycurl.TOTAL_TIME)))

    # Write data to our log file. 
    if os.path.isfile(DATA_FILE): 
        df = pd.read_csv(DATA_FILE)
    else: 
        df = pd.DataFrame(
                columns=['test_date', 'url', 'resource', 'transfer_time'])
    benchmark_df = pd.DataFrame(benchmark_data, 
            columns=['test_date', 'url', 'resource', 'transfer_time'])
    df = df.append(benchmark_df)
    df.to_csv(DATA_FILE, index=False)



def query(url, output_file):
    """Use pycurl to fetch a site using the tor proxy on the SOCKS_PORT.

    Parameters: 
        url: The url to fetch. 
        output_file: The file-like object to write the returned data to.
    Returns: 
        The total transfer time of the connection. 
    """

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
    query.setopt(pycurl.WRITEFUNCTION, output_file.write)

    try:
        query.perform()
    except pycurl.error as exc:
        raise ConnectionError(f"Unable to reach {url} ({exc})")

    return query.getinfo(pycurl.TOTAL_TIME)


def get_circuit_time(tor_controller, path):
    """Fetch a URL through the given relay path.

    Returns the total time taken by the request."""

    try:
        # Set up a new circuit, blocking until the circuit is set up. 
        circuit_id = tor_controller.new_circuit(path, await_build=True)

        def attach_stream(stream):
            if stream.status == 'NEW':
                tor_controller.attach_stream(stream.id, circuit_id)
        tor_controller.add_event_listener(attach_stream,
                stem.control.EventType.STREAM)
        tor_controller.set_conf('__LeaveStreamsUnattached', '1') 

        # Fetch page using the circuit. 
        output_file = open('/dev/null', 'wb')
        transfer_time = query(URL, output_file)
        output_file.close()

    finally:
        # Close the circuit, and undo our configuration changes. 
        tor_controller.remove_event_listener(attach_stream)
        tor_controller.reset_conf('__LeaveStreamsUnattached')
        tor_controller.close_circuit(circuit_id)

    return transfer_time


if __name__ == '__main__': 
    main()
