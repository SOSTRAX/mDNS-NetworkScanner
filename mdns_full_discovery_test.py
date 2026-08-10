from zeroconf import (
    Zeroconf,
    ServiceBrowser,
    ServiceListener
)

import time
import socket


DISCOVERY_TIME = 10


class ServiceCollector(ServiceListener):

    def __init__(self, zeroconf):

        self.zeroconf = zeroconf

        self.services = {}

    def add_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self._process(
            service_type,
            name
        )

    def update_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self._process(
            service_type,
            name
        )

    def remove_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        pass

    def _process(
        self,
        service_type,
        name
    ):

        try:

            info = self.zeroconf.get_service_info(
                service_type,
                name,
                timeout=2000
            )

            if not info:
                return

            addresses = []

            for address in info.addresses:

                try:

                    addresses.append(
                        socket.inet_ntop(
                            socket.AF_INET,
                            address
                        )
                    )

                except Exception:

                    try:

                        addresses.append(
                            socket.inet_ntop(
                                socket.AF_INET6,
                                address
                            )
                        )

                    except Exception:
                        pass

            key = (
                info.server
                or name
            )

            if key not in self.services:

                self.services[key] = {
                    "hostname": (
                        info.server
                        or ""
                    ),
                    "addresses": set(),
                    "services": set()
                }

            self.services[key]["addresses"].update(
                addresses
            )

            self.services[key]["services"].add(
                service_type
            )

        except Exception:

            pass


class ServiceTypeCollector(ServiceListener):

    def __init__(self):

        self.service_types = set()

    def add_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self.service_types.add(name)

    def update_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        self.service_types.add(name)

    def remove_service(
        self,
        zeroconf,
        service_type,
        name
    ):

        pass


def main():

    print()
    print("================================")
    print("       mDNS Full Discovery")
    print("================================")
    print()

    print(
        "Discovering advertised mDNS service types..."
    )

    print(
        f"Waiting {DISCOVERY_TIME} seconds..."
    )

    print()

    zeroconf = Zeroconf()

    try:

        # ------------------------------------------------
        # Discover service types
        # ------------------------------------------------

        type_collector = (
            ServiceTypeCollector()
        )

        ServiceBrowser(
            zeroconf,
            "_services._dns-sd._udp.local.",
            listener=type_collector
        )

        time.sleep(
            DISCOVERY_TIME
        )

        service_types = sorted(
            type_collector.service_types
        )

        print(
            f"Service types found: "
            f"{len(service_types)}"
        )

        for service_type in service_types:

            print(
                f"  {service_type}"
            )

        print()

        # ------------------------------------------------
        # Browse every discovered service type
        # ------------------------------------------------

        collector = ServiceCollector(
            zeroconf
        )

        browsers = []

        for service_type in service_types:

            try:

                browser = ServiceBrowser(
                    zeroconf,
                    service_type,
                    listener=collector
                )

                browsers.append(
                    browser
                )

            except Exception:

                pass

        print(
            "Browsing discovered services..."
        )

        print(
            f"Waiting {DISCOVERY_TIME} seconds..."
        )

        print()

        time.sleep(
            DISCOVERY_TIME
        )

        # ------------------------------------------------
        # Display results
        # ------------------------------------------------

        print()
        print("--------------------------------")
        print("mDNS devices discovered")
        print("--------------------------------")
        print()

        if not collector.services:

            print(
                "No devices were resolved."
            )

        else:

            for key in sorted(
                collector.services
            ):

                device = collector.services[
                    key
                ]

                print(
                    f"Hostname: "
                    f"{device['hostname']}"
                )

                for address in sorted(
                    device["addresses"]
                ):

                    print(
                        f"  Address: "
                        f"{address}"
                    )

                print(
                    "  Services:"
                )

                for service in sorted(
                    device["services"]
                ):

                    print(
                        f"    {service}"
                    )

                print()

        print(
            f"Unique mDNS devices: "
            f"{len(collector.services)}"
        )

    finally:

        zeroconf.close()


if __name__ == "__main__":
    main()