import dns.resolver
import dns.rdatatype
from typing import Optional
import logging

LOGGER = logging.getLogger(__name__)


my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['8.8.8.8']
DNS_RESOLVERS = ['8.8.8.8']
DNS_TIMEOUT = 10


def query_dns(query_name, query_type):
    # Send a dns query
    try:
        results = my_resolver.resolve(query_name, query_type)
        return list(results)
    except:
        return []

def check_dnssec(domain_name, record_type, domain=None):
    """Test to see if a DNSSEC record is valid and correct.

    Checks a domain for DNSSEC whether the domain has a record of type that is protected
    by DNSSEC or NXDOMAIN or NoAnswer that is protected by DNSSEC.

    TODO: Probably does not follow redirects (CNAMEs).  Should work on
    that in the future.
    """
    try:
        query = dns.message.make_query(domain_name, record_type, want_dnssec=True)
        for nameserver in DNS_RESOLVERS:
            response = dns.query.tcp(query, nameserver, timeout=DNS_TIMEOUT)
            if response is not None:
                if response.flags & dns.flags.AD:
                    return True
                else:
                    return False
    except Exception as error:
        print("[DNSSEC Fail]", domain, error)
        return None



class ExtendedProtocol:
    BIMI_SELECTORS = "default"

    @classmethod
    def get_bimi_record(cls, domain: str) -> Optional[str]:
        """
        Get BIMI DNS TXT record: <selector>._bimi.<domain> TXT v=BIMI1
        Returns the first valid BIMI DNS TXT Resource Record
        :return "v=BIMI1;l=https://vmc.digicert.com/045a6607-a6e6-42cf-aed8-e9c2aa26aae2.svg;a=https://vmc.digicert.com/045a6607-a6e6-42cf-aed8-e9c2aa26aae2.pem"
        """
        query = f"{cls.BIMI_SELECTORS}._bimi.{domain}"
        try:
            answers = query_dns(query, 'TXT')
            for rdata in answers:
                for string in rdata.strings:
                    if b"v=bimi1" in string.lower():
                        decoded_string = string.decode('utf-8')
                        return decoded_string
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            LOGGER.debug(f"No BIMI record found for {query}: {e}")
        return None

    @classmethod
    def get_mta_sts_record(cls, domain: str) -> Optional[str]:
        """
        Get MTA-STS DNS TXT record: _mta-sts.<domain> TXT v=STSv1
        Returns the first valid MTA-STS DNS TXT Resource Record
        :return "https://mta-sts.your-domain/.well-known/mta-sts.txt"
        """
        query = f"_mta-sts.{domain}"
        try:
            answers = query_dns(query, 'TXT')
            for rdata in answers:
                for string in rdata.strings:
                    if b"v=stsv1" in string.lower():
                        decoded_string = string.decode('utf-8')
                        return decoded_string
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            LOGGER.debug(f"No MTA-STS record found for {query}: {e}")
        return None

    @classmethod
    def get_tls_reporting_record(cls, domain: str) -> Optional[str]:
        """
        Get TLS Reporting DNS TXT record: _smtp._tls.<domain> TXT v=TLSRPTv1
        Returns the first valid TLS Reporting DNS TXT Resource Record
        :return "v=TLSRPTv1; rua=https://hermes.dgtl.hosting/api/webhooks/tlsrpt"
        """
        query = f"_smtp._tls.{domain}"
        try:
            answers = query_dns(query, 'TXT')
            for rdata in answers:
                for string in rdata.strings:
                    if b"v=tlsrptv1" in string.lower():
                        decoded_string = string.decode('utf-8')
                        return decoded_string
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            LOGGER.debug(f"No TLS Reporting record found for {query}: {e}")
        return None



if __name__ == '__main__':
    print(ExtendedProtocol.get_bimi_record("vecteezy.com"))
    print(ExtendedProtocol.get_tls_reporting_record("dgtl.hosting"))
    print(ExtendedProtocol.get_mta_sts_record("dgtl.hosting"))
