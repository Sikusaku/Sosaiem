"""
Asking the router to let the world reach this node.

The network is only as sturdy as the number of machines that can accept
incoming connections. A home computer normally cannot: the router drops
anything it did not ask for, so home miners can talk *out* to a reachable node
but nobody can talk back *in*. That is why a young network leans on one or two
servers -- and why losing them takes everything down.

Most home routers will open a port if a program on the network politely asks,
using a protocol called UPnP. This module does the asking, with nothing but the
standard library so nobody has to install anything. Bitcoin Core has done the
same since its early days, and it is a large part of why thousands of ordinary
home machines are reachable rather than a handful of server operators.

It is a request, not a demand. Plenty of routers say no, or have UPnP switched
off, and some internet providers put their customers behind a second layer of
NAT that no amount of asking can get through. So this succeeds sometimes, not
always -- and the node is expected to carry on regardless.
"""

import re
import socket
import urllib.request
import urllib.parse

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
_WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
DESCRIPTION = "Sosaiem node"


def get_lan_ip():
    """This machine's address on the local network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))          # no packets are actually sent
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _discover(timeout=2.5):
    """Shout on the local network and collect any router that answers."""
    found = []
    for target in _WAN_SERVICES + ("upnp:rootdevice",):
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               f"ST: {target}\r\n\r\n").encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        try:
            s.sendto(msg, (SSDP_ADDR, SSDP_PORT))
            while True:
                try:
                    data, _ = s.recvfrom(65507)
                except socket.timeout:
                    break
                m = re.search(rb"LOCATION:\s*(\S+)", data, re.I)
                if m:
                    loc = m.group(1).decode(errors="ignore")
                    if loc not in found:
                        found.append(loc)
        except Exception:
            pass
        finally:
            s.close()
        if found:
            break
    return found


def _control_url(location, timeout=3):
    """Read the router's description and find where to send commands."""
    try:
        with urllib.request.urlopen(location, timeout=timeout) as r:
            xml = r.read().decode(errors="ignore")
    except Exception:
        return None, None
    for service in _WAN_SERVICES:
        idx = xml.find(service)
        if idx < 0:
            continue
        m = re.search(r"<controlURL>\s*([^<]+)\s*</controlURL>", xml[idx:], re.I)
        if not m:
            continue
        return urllib.parse.urljoin(location, m.group(1).strip()), service
    return None, None


def _soap(control_url, service, action, body, timeout=4):
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{service}">{body}</u:{action}></s:Body>'
        '</s:Envelope>').encode()
    req = urllib.request.Request(control_url, envelope, {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service}#{action}"',
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="ignore")


def open_port(port, lease_seconds=0):
    """
    Ask the router to forward `port` to this machine.

    Returns (ok, detail). Never raises -- a node that cannot open a port is
    still a perfectly good node, it just cannot host newcomers.
    """
    ip = get_lan_ip()
    if ip.startswith("127."):
        return False, "no local network address"
    for location in _discover():
        control, service = _control_url(location)
        if not control:
            continue
        body = (f"<NewRemoteHost></NewRemoteHost>"
                f"<NewExternalPort>{port}</NewExternalPort>"
                f"<NewProtocol>TCP</NewProtocol>"
                f"<NewInternalPort>{port}</NewInternalPort>"
                f"<NewInternalClient>{ip}</NewInternalClient>"
                f"<NewEnabled>1</NewEnabled>"
                f"<NewPortMappingDescription>{DESCRIPTION}</NewPortMappingDescription>"
                f"<NewLeaseDuration>{lease_seconds}</NewLeaseDuration>")
        try:
            _soap(control, service, "AddPortMapping", body)
            return True, f"router at {urllib.parse.urlparse(location).hostname}"
        except Exception as e:
            # some routers refuse a permanent lease but accept a temporary one
            if lease_seconds == 0:
                try:
                    _soap(control, service, "AddPortMapping",
                          body.replace("<NewLeaseDuration>0<",
                                       "<NewLeaseDuration>604800<"))
                    return True, f"router at {urllib.parse.urlparse(location).hostname} (7-day lease)"
                except Exception:
                    pass
            return False, f"router refused ({type(e).__name__})"
    return False, "no router answered -- UPnP is probably switched off"


def close_port(port):
    for location in _discover(timeout=1.5):
        control, service = _control_url(location)
        if not control:
            continue
        try:
            _soap(control, service, "DeletePortMapping",
                  "<NewRemoteHost></NewRemoteHost>"
                  f"<NewExternalPort>{port}</NewExternalPort>"
                  "<NewProtocol>TCP</NewProtocol>")
            return True
        except Exception:
            pass
    return False


def external_ip():
    """The address the rest of the internet sees, asked of the router itself."""
    for location in _discover(timeout=1.5):
        control, service = _control_url(location)
        if not control:
            continue
        try:
            xml = _soap(control, service, "GetExternalIPAddress", "")
            m = re.search(r"<NewExternalIPAddress>\s*([\d.]+)\s*<", xml)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None


if __name__ == "__main__":
    print("local address :", get_lan_ip())
    print("looking for a router that speaks UPnP\u2026")
    routers = _discover()
    print("routers found :", len(routers))
    for r in routers:
        print("   ", r)
    print("external IP   :", external_ip())
