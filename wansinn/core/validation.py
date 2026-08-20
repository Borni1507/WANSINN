import ipaddress
def validate_private_ipv4(ip):
  p=ipaddress.ip_address(ip)
  if p.version!=4 or not p.is_private: raise ValueError("Nur private IPv4-Adressen sind erlaubt.")
  return str(p)


def validate_probe_ipv4(value: str) -> str:
    """Validate an IPv4 address suitable as a health-check destination.

    Public IPv4 addresses are explicitly allowed here. Only unusable/special
    targets are rejected.
    """
    import ipaddress

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Ungültige IPv4-Adresse.") from exc

    if address.version != 4:
        raise ValueError("Nur IPv4-Adressen sind erlaubt.")
    if address.is_unspecified:
        raise ValueError("0.0.0.0 ist kein gültiges Health-Ziel.")
    if address.is_multicast:
        raise ValueError("Multicast-Adressen sind kein gültiges Health-Ziel.")
    if address.is_loopback:
        raise ValueError("Loopback-Adressen sind kein gültiges Health-Ziel.")
    if address.is_reserved:
        raise ValueError("Reservierte IPv4-Adressen sind kein gültiges Health-Ziel.")

    return str(address)


def validate_mac(value: str) -> str:
    import re
    value = value.strip().upper().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value):
        raise ValueError("Ungültige MAC-Adresse.")
    first = int(value.split(":")[0], 16)
    if first & 1:
        raise ValueError("Multicast-MAC-Adressen sind nicht als Gerät zulässig.")
    if value == "00:00:00:00:00:00":
        raise ValueError("Ungültige MAC-Adresse.")
    return value
