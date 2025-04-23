import dns.resolver

import verify

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


def resolve_mx(query_name):
    data = {}
    cur = []
    answers = query_dns(query_name, 'MX')
    if len(answers) == 0:
        return data
    for rdata in answers:
        exchange = str(rdata.exchange)
        entry = {
            "hostname": exchange if exchange == '.' else exchange.rstrip('.'),
            "priority": rdata.preference,
        }
        entry['25'] = {}
        entry['2525'] = {}
        tls_res, errors = verify.verify_mx(entry['hostname'], 25)
        entry['25']['tls_result'] = tls_res
        entry['25']['error'] = errors
        tls_res, errors = verify.verify_mx(entry['hostname'], 2525)
        entry['2525']['tls_result'] = tls_res
        entry['2525']['error'] = errors
        cur.append(entry)
    cur = sorted(cur, key=lambda x: int(x["priority"]))
    data['mx_record'] = sorted(cur, key=lambda k: k['priority'])
    data['is_dnssec_validated'] = check_dnssec(query_name, 'MX')
    return data


def mx(domain):
    '''
    Constructs a MX record for the given domain, and returns a dictionary of the results.
    '''
    data = resolve_mx(domain)
    return data


if __name__ == '__main__':
    print(mx("qq.com"))