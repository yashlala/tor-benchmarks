import asyncio
import os.path
import timeit

from aiohttp_socks import ProxyConnector
import aiohttp
import pandas as pd
import stem.control


# CONSTANTS

# Fingerprint of the TOR exit node.
# Currently set to: TorOrDie4privacyNET.
# Based in US, IP addr: 104.244.73.43:443
EXIT_FINGERPRINT = '376DC7CAD597D3A4CBB651999CFAD0E77DC9AE8C'

# Data logging location.


def main():
    benchmark_data = []

    url = 'http://104.154.161.181:5003/'
    # HTTP resource name -> size in MB
    resources = {
            'download1': 100,
            'download2': 50,
            'download3': 33,
            'download4': 25,
            'download5': 20
        }

    for resource, size in resources.items(): 
        async def fetch_page(url): 
            # Set up an AIO-compatible wrapper around our SOCKS proxy. 
            connector = ProxyConnector.from_url('socks5://localhost:9050')

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    # "Block" until the response has been fully fetched. 
                    await response.text()
                    return response.ok

        async def fetch_page_ntimes(url, ntimes):
            for _ in range(ntimes): 
                await fetch_page(url)
            assert all(status_codes)

        resource_url = f'{url}{resource}' 
        ntimes_to_fetch = 100 // size

        print(f"Fetching '{resource_url}'")

        t1 = timeit.default_timer()
        asyncio.run(fetch_page_ntimes(resource_url, ntimes_to_fetch))
        t2 = timeit.default_timer()
        time_elapsed = t2 - t1

        print(f'Took {time_elapsed} seconds')

        benchmark_data.append((pd.Timestamp.now(), url, resource,
            ntimes_to_fetch, time_elapsed))

    # Append or write the data to our data file.
    data_file = 'tor-benchmarks.csv'
    csv_columns = ['test_date', 'url', 'resource', 'times_fetched', 'transfer_time']
    if os.path.isfile(data_file):
        df = pd.read_csv(data_file)
    else:
        df = pd.DataFrame(columns=csv_columns)
    df = df.append(pd.DataFrame(benchmark_data, columns=csv_columns))
    df.to_csv(data_file, index=False)




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
