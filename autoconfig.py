
import logging
import xml.etree.ElementTree as ET
import tldextract
import json

import verify
from httpmethod import http_get, https_get
from srv import resolve_mx

LOGGER = logging.getLogger(__name__)


def extract_Provider_Domain(content):
    tree = ET.parse(content)
    root_element = tree.getroot()
    domain_set = set()
    # Extract displayName, incomingServer, and outgoingServer information
    email_provider = root_element.find("emailProvider")
    email_provider_id = email_provider.get("id")
    domains = email_provider.findall("domain")
    if domains:
        for one in domains:
            domain = one.text
            domain_set.add(domain)
    return email_provider_id, domain_set


def parse_autoconfig(content):
    '''
    parse a xml into autoconfig struct

    :param content: xml form content
    :return: autoconfig struct
             if error happened, return a "extract_error"
    '''
    data = {}
    try:
        tree = ET.parse(content)
    except ET.ParseError as e:
        # print("XML parse fail.")
        data['extract_error'] = "XML parse fail."
        return data
    root_element = tree.getroot()
    email_provider_element = root_element.find("emailProvider")
    if email_provider_element is None:
        # print("XML format error.")
        data['extract_error'] = 'XML format error.'
        return data
    
    # email_provider = email_provider_element.get("id")
    # display_name = ""
    # # case-sensitive for "displayname"
    # if email_provider_element.find("displayName") is not None:
    #     display_name = email_provider_element.find("displayName").text
    
    incoming_servers = email_provider_element.findall("incomingServer")
    incoming_server_data = []
    # Order list.
    for incoming_server in incoming_servers:
        server_data = {
            "type": incoming_server.get("type"),
            "hostname": incoming_server.find("hostname").text,
            "port": incoming_server.find("port").text,
            "socketType": incoming_server.find("socketType").text,
            'authentication': incoming_server.find('authentication').text,
            # 'username': incoming_server.find('username').text
        }
        tls_res, error = verify.verify_mail_server(server_data['type'], server_data['hostname'],
                                                   server_data['port'], server_data['socketType'])
        server_data['tls_result'] = tls_res
        server_data['error'] = error
        incoming_server_data.append(server_data)

    outgoing_servers = email_provider_element.findall("outgoingServer")
    outgoing_server_data = []
    for outgoing_server in outgoing_servers:
        server_data = {
            "type": outgoing_server.get("type"),
            "hostname": outgoing_server.find("hostname").text,
            "port": outgoing_server.find("port").text,
            "socketType": outgoing_server.find("socketType").text,
            'authentication': outgoing_server.find('authentication').text,
            # 'username': outgoing_server.find('username').text
        }
        tls_res, error = verify.verify_mail_server(server_data['type'], server_data['hostname'],
                                                   server_data['port'], server_data['socketType'])
        server_data['tls_result'] = tls_res
        server_data['error'] = error
        outgoing_server_data.append(server_data)

    # Check for webmail information
    webmails = root_element.findall("webMail")
    webmail_data = []
    if webmails is not None:
        for webmail in webmails:
            xml_data = {
                "loginPageUrl": webmail.find("loginPage").get("url"),
                # 'username': webmail.find('loginPageInfo/username').text,
                # 'usernameField': webmail.find('loginPageInfo/usernameField').get('id'),
                # 'passwordField': webmail.find('loginPageInfo/passwordField').get('id'),
                # 'loginButton': webmail.find('loginPageInfo/loginButton').get('id')
            }
            webmail_data.append(xml_data)

    data = {"incomingServers": incoming_server_data, "outgoingServers": outgoing_server_data, "webMails": webmail_data}
    return data

def from_ISPDB(domain):
    url3 = f"https://autoconfig.thunderbird.net/v1.1/{domain}"
    cur = https_get(url3)
    if "xml" in cur:
        cur["config"] = parse_autoconfig(cur["xml"])
        del cur['xml']
    return cur

def autoconfig(domain, mailaddress):
    '''
    This tool also consider the back-off condition : query the mx record and then retrieve configurations

    :param domain: mail domain
    :param mailaddress:  mail address in form of username@domain
    :return: autoconfig result
    '''

    data = {}
    # step 1&2, we lookup the autoconfig file from the domain part of email address
    config_url1 = f"http://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={mailaddress}"
    config_url2 = f"http://{domain}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={mailaddress}"
    url_pool = [(config_url1, "autoconfig-url"), (config_url2, "well-known-url")]
    for url, alias in url_pool:
        data[alias] = {}
        # request from HTTP
        cur = http_get(url)
        if "xml" in cur:
            cur["config"] = parse_autoconfig(cur["xml"])
            del cur['xml']
        data[alias]["http_get"] = cur
        # upgrade to https
        url = url.replace("http://", "https://")
        cur = https_get(url)
        if "xml" in cur:
            cur["config"] = parse_autoconfig(cur["xml"])
            del cur['xml']
        data[alias]["https_get"] = cur

    # Note: In our paper, we consider the ISPDB to be a kind of "built-in provider list".
    # step 3, we lookup the autoconfig file from thunderbird ISPDB
    # data["ISPDB"] = from_ISPDB(domain)

    # step 4 lookup the mx record
    mxlist = resolve_mx(domain)
    if not mxlist:  # no mx record
        return data

    mxhostname = mxlist[0]["hostname"]
    backoff = {}
    data["Back-off"] = backoff
    backoff["MX_Hostname"] = mxhostname
    # E.g., mxhostname = mail.hosted.example.com
    # mxmaindomain = example.com
    # mxfulldomain = hosted.example.com
    mxmaindomain = tldextract.extract(mxhostname).registered_domain
    mxfulldomain = '.'.join(tldextract.extract(mxhostname).subdomain.split('.')[1:] + [tldextract.extract(mxhostname).registered_domain])
    if mxfulldomain == domain or mxfulldomain == '':
        return data
    backoff["mxfulldomain_domain"] = {}
    backoff["mxfulldomain_domain"]["request_domain"] = mxfulldomain
    url4 = f"https://autoconfig.{mxfulldomain}/mail/config-v1.1.xml?emailaddress={mailaddress}"
    cur = https_get(url4)
    if "xml" in cur:
        cur["config"] = parse_autoconfig(cur["xml"])
        del cur['xml']
    backoff["mxfulldomain_domain"]["https_get"] = cur
    # backoff["mxfulldomain_domain"]["ISPDB"] = from_ISPDB(mxfulldomain)

    if mxmaindomain == domain or mxfulldomain == mxmaindomain or mxmaindomain == '':
        return data
    backoff["mxmaindomain_domain"] = {}
    backoff["mxmaindomain_domain"]["request_domain"] = mxmaindomain
    url5 = f"https://autoconfig.{mxmaindomain}/mail/config-v1.1.xml?emailaddress={mailaddress}"
    cur = https_get(url5)
    if "xml" in cur:
        cur["config"] = parse_autoconfig(cur["xml"])
        del cur['xml']
    backoff["mxmaindomain_domain"]["https_get"] = cur
    # backoff["mxmaindomain_domain"]["ISPDB"] = from_ISPDB(mxmaindomain)
    return data