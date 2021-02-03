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
# URL = "http://104.154.161.181/"

def query(url):
    """Use pycurl to fetch a site using the proxy on the SOCKS_PORT."""

    # Discard webpage output. Should be empty anyways. 
    output = open('/dev/null', 'wb')

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.NOBODY, True) # Send HTTP HEAD requests (no msg body).
    query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
    query.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
        query.perform()
    except pycurl.error as exc:
        raise ConnectionError(f"Unable to reach {url} ({exc})")

    return query.getinfo(pycurl.CONNECT_TIME)


def scan(controller, path):
    """Fetch a URL through the given relay path."""

    try:
        # Set up a new circuit, blocking until the circuit is set up. 
        circuit_id = controller.new_circuit(path, await_build=True)

        def attach_stream(stream):
            if stream.status == 'NEW':
                controller.attach_stream(stream.id, circuit_id)
        controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

        controller.set_conf('__LeaveStreamsUnattached', '1') 
        rtt = query(URL)
    finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')
        controller.close_circuit(circuit_id)

    return rtt


with stem.control.Controller.from_port() as controller:
    print('address,rtt')
    controller.authenticate()

    for relay in itertools.islice(controller.get_network_statuses(), 50): 
        rtt = scan(controller, [relay.fingerprint, EXIT_FINGERPRINT])
        print(f'{relay.address},{rtt}')
