import json
import argparse
import logging
import datetime
import os

import extended
import guess
import mx
from autoconfig import autoconfig
from autodiscover import autodiscover
from srv import srv
from buildin import buildin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOGGER = logging.getLogger(__name__)

SCAN_AUTOCONFIG = 1 << 0
SCAN_AUTODISCOVER = 1 << 1
SCAN_SRV = 1 << 2
SCAN_BUILDIN = 1 << 3
SCAN_GUESS_MAIL_SERVER = 1 << 4
SCAN_GUESS_WEBMAIL = 1 << 5
SCAN_MX = 1 << 6
SCAN_BIMI = 1 << 7
SCAN_MTA_STS = 1 << 8
SCAN_TLS_RPT = 1 << 9

SCAN_ALL = SCAN_AUTOCONFIG | SCAN_AUTODISCOVER | SCAN_SRV | SCAN_BUILDIN | SCAN_GUESS_MAIL_SERVER | SCAN_GUESS_WEBMAIL | SCAN_MX | SCAN_BIMI | SCAN_MTA_STS | SCAN_TLS_RPT


def doscan(mailaddress, domain, flag):
    """Perform email server configuration scan"""
    data = {
        "scan_info": {
            "email": mailaddress,
            "domain": domain,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "methods_used": []
        },
        "results": {}
    }

    if flag & SCAN_AUTOCONFIG:
        LOGGER.info(f"Scanning autoconfig for {domain}")
        data["scan_info"]["methods_used"].append("autoconfig")
        data["results"]["autoconfig"] = autoconfig(domain, mailaddress)
        LOGGER.info("Autoconfig scan completed")

    if flag & SCAN_AUTODISCOVER:
        LOGGER.info(f"Scanning autodiscover for {domain}")
        data["scan_info"]["methods_used"].append("autodiscover")
        data["results"]["autodiscover"] = autodiscover(domain, mailaddress)
        LOGGER.info("Autodiscover scan completed")

    if flag & SCAN_SRV:
        LOGGER.info(f"Scanning SRV records for {domain}")
        data["scan_info"]["methods_used"].append("srv")
        data["results"]["srv"] = srv(domain)
        LOGGER.info("SRV records scan completed")

    if flag & SCAN_BUILDIN:
        LOGGER.info(f"Looking up builtin provider list for {domain}")
        data["scan_info"]["methods_used"].append("buildin")
        data["results"]["buildin"] = buildin(domain)
        LOGGER.info("Builtin provider lookup completed")

    if flag & SCAN_GUESS_MAIL_SERVER:
        LOGGER.info(f"Starting mail server discovery for domain: {domain}")
        data["scan_info"]["methods_used"].append("guess_mail_server")
        data["results"]["guess_mail_server"] = guess.GuessMethod.guess_mail_servers(domain)
        LOGGER.info(f"Completed mail server discovery for domain: {domain}")

    if flag & SCAN_GUESS_WEBMAIL:
        LOGGER.info(f"Starting webmail discovery for domain: {domain}")
        data["scan_info"]["methods_used"].append("guess_webmail")
        data["results"]["guess_webmail"] = guess.GuessMethod.guess_webmail(domain)
        LOGGER.info(f"Completed webmail discovery for domain: {domain}")

    if flag & SCAN_MX:
        LOGGER.info(f"Starting MX records for domain: {domain}")
        data["scan_info"]["methods_used"].append("mx")
        data["results"]["mx"] = mx.mx(domain)
        LOGGER.info(f"Completed MX records for domain: {domain}")

    if flag & SCAN_BIMI:
        LOGGER.info(f"Scanning BIMI for {domain}")
        data["scan_info"]["methods_used"].append("bimi")
        data["results"]["bimi"] = extended.ExtendedProtocol.get_bimi_record(domain)
        LOGGER.info(f"Completed BIMI for domain: {domain}")

    if flag & SCAN_MTA_STS:
        LOGGER.info(f"Scanning MTA-STS for {domain}")
        data["scan_info"]["methods_used"].append("mta_sts")
        data["results"]["mta_sts"] = extended.ExtendedProtocol.get_mta_sts_record(domain)
        LOGGER.info(f"Completed MTA-STS for domain: {domain}")

    if flag & SCAN_TLS_RPT:
        LOGGER.info(f"Scanning TLS Reporting for {domain}")
        data["scan_info"]["methods_used"].append("tls_rpt")
        data["results"]["tls_rpt"] = extended.ExtendedProtocol.get_tls_reporting_record(domain)
        LOGGER.info(f"Completed TLS Reporting for domain: {domain}")

    return data


def save_json_output(data, filename):
    """Save data to JSON file"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        LOGGER.info(f"Results saved to {filename}")
        return True
    except Exception as e:
        LOGGER.error(f"Failed to save results to {filename}: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Email server configuration detection tool')
    parser.add_argument('-a', '--mailaddress', type=str, default="user@test.com", help='Email address to scan')
    parser.add_argument('-c', '--autoconfig', action='store_true', help='Look up autoconfig')
    parser.add_argument('-d', '--autodiscover', action='store_true', help='Look up autodiscover')
    parser.add_argument('-s', '--srv', action='store_true', help='Look up DNS SRV records')
    parser.add_argument('-b', '--buildin', action='store_true', help='Look up builtin provider list')
    parser.add_argument('-gm', '--guess_mailserver', action='store_true', help='Guess mail server configs')
    parser.add_argument('-gw', '--guess_webmail', action='store_true', help='Guess webmail url')
    parser.add_argument('-mx', '--mx', action='store_true', help='Look up DNS MX records')
    parser.add_argument('-bimi', '--bimi', action='store_true', help='Look up BIMI records')
    parser.add_argument('-mta', '--mta_sts', action='store_true', help='Look up MTA-STS records')
    parser.add_argument('-rpt', '--tls_rpt', action='store_true', help='Look up TLS-RPT records')
    parser.add_argument('-j', '--json-file', type=str, default="output.json", help='Save output to JSON file')

    args = parser.parse_args()

    # Validate email address
    email_parts = args.mailaddress.split("@")
    if len(email_parts) != 2:
        LOGGER.error(f"Invalid email address: {args.mailaddress}")
        return 1

    domain = email_parts[1]
    LOGGER.info(f"Starting scan for {args.mailaddress}")

    # Determine scan flags
    flag = 0
    if args.autoconfig:
        flag |= SCAN_AUTOCONFIG
    if args.autodiscover:
        flag |= SCAN_AUTODISCOVER
    if args.srv:
        flag |= SCAN_SRV
    if args.buildin:
        flag |= SCAN_BUILDIN
    if flag == 0:
        flag = SCAN_ALL

    # Perform scan
    result = doscan(args.mailaddress, domain, flag)

    # Handle output
    if args.json_file:
        save_json_output(result, args.json_file)
    else:
        print(json.dumps(result, indent=2, default=str))

    LOGGER.info("Scan completed successfully")
    return 0


if __name__ == "__main__":
    exit(main())
