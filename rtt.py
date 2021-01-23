import io
import time

import pycurl

import stem.control

# Static exit for us to make 2-hop circuits through. Picking aurora, a
# particularly beefy one...
#
#   https://metrics.torproject.org/rs.html#details/379FB450010D17078B3766C2273303C358C3A442

EXIT_FINGERPRINT = '379FB450010D17078B3766C2273303C358C3A442'

SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 30

def query_RTT(url):
    """Use pycurl to fetch a site using the proxy on the SOCKS_PORT."""

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

        return query.getinfo(pycurl.CONNECT_TIME)
    except pycurl.error as exc:
        raise ValueError(f"Unable to reach {url} ({exc})")


def scan(controller, path):
    """
    Fetch check.torproject.org through the given path of relays, providing back
    the time it took.
    """

    circuit_id = controller.new_circuit(path, await_build=True)

    def attach_stream(stream):
        if stream.status == 'NEW':
            controller.attach_stream(stream.id, circuit_id)
    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

    try:
        controller.set_conf('__LeaveStreamsUnattached', '1') 
        start_time = time.time()

        check_page = query('https://check.torproject.org/')

        if 'Congratulations. This browser is configured to use Tor.' not in check_page:
            raise ValueError("Request didn't have the right content")

        return time.time() - start_time
    finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')


    with stem.control.Controller.from_port() as controller:
        controller.authenticate()

    relay_fingerprints = [desc.fingerprint for desc in controller.get_network_statuses()]

    for fingerprint in relay_fingerprints:
        try:
            time_taken = scan(controller, [fingerprint, EXIT_FINGERPRINT])
        print('%s => %0.2f seconds' % (fingerprint, time_taken))
        except Exception as exc:
            print('%s => %s' % (fingerprint, exc))
