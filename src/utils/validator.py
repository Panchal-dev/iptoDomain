import re
import ipaddress

class IPValidator:
    @classmethod
    def is_valid_ip_or_cidr(cls, ip_or_cidr):
        try:
            ipaddress.ip_address(ip_or_cidr)
            return True
        except ValueError:
            try:
                ipaddress.ip_network(ip_or_cidr, strict=False)
                return True
            except ValueError:
                return False

    @staticmethod
    def filter_valid_ips(ips):
        return [ip for ip in ips if cls.is_valid_ip_or_cidr(ip)]