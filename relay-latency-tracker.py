import io
import itertools

import pycurl
import stem.control

# Exit node. 
# Currently set to: TorOrDie4privacyNET. 
# Based in US, IP addr: 104.244.73.43:443
EXIT_FINGERPRINT = '376DC7CAD597D3A4CBB651999CFAD0E77DC9AE8C'
SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 10
URL = 'https://google.com/'


def query(url, output_file):
    """Use pycurl to fetch a site using the tor proxy on the SOCKS_PORT.

    Parameters: 
        url: The url to fetch. Does not yet resolve raw IP addresses. 
        output_file: The file-like object to write the returned data to.
    Returned Values: 
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


def main(): 
    with stem.control.Controller.from_port() as controller:
        print('address,rtt')
        controller.authenticate()

        for relay in itertools.islice(controller.get_network_statuses(), 50): 
            rtt = get_circuit_time(controller, 
                    [relay.fingerprint, EXIT_FINGERPRINT])
            print(f'{relay.address},{rtt}')


if __name__ == '__main__': 
    main()
