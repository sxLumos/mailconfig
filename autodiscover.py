
import xml.etree.ElementTree as ET
import logging
import json

import verify
from srv import resolve_srv
from httpmethod import http_get, https_get, http_post, https_post, get_redirect_post

LOGGER = logging.getLogger(__name__)


def autodiscover_srv(domain):
    '''
    We query the _autodiscover._tcp.{domain} SRV record to get the hostname

    :param domain: mail domain
    :return: ULR to get the autodiscover.xml
    '''
    try:
        res = resolve_srv(f"_autodiscover._tcp.{domain}")
        if not res or not res['srv_record']:
            return None
        try:
            if res['srv_record']:
                hostname = res['srv_record'][0]['hostname']
            else:
                return None
        except Exception as e:
            return None
        autodiscover_url = f"https://{hostname}/autodiscover/autodiscover.xml"
        return autodiscover_url
    except Exception:
        LOGGER.warning("Failed to resolve autodiscover SRV record")
        return None


def parse_autodiscover(content):
    '''
    Ref: https://msopenspecs.azureedge.net/files/MS-OXDSCLI/[MS-OXDSCLI].pdf

    parse a xml into autodiscover struct,

    :param content: xml form content
    :return: autodiscover struct
             if error happened, return a "extract_error"
    '''

    # Notes: namespace for different xml!
    def is_element_present(element, tag, namespace):
        return element.find(tag, namespace) is not None
    def get_element_text(element, tag, namespace, default=None):
        if is_element_present(element, tag, namespace):
            return element.find(tag, namespace).text
        else:
            return default
    
    data = {}
    try:
        tree = ET.parse(content)
    except ET.ParseError as e:
        # print("XML parse fail.")
        data['extract_error'] = "XML parse fail."
        return data
    
    namespace = {
        "ns1": "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006",
        "ns2": "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
    }
    root_element = tree.getroot()
    # Parse for error response.
    response_for_error = root_element.find("ns1:Response", namespace)
    if response_for_error:
        error_part = response_for_error.find("ns1:Error", namespace)
        if error_part:
            data['extract_error'] = error_part.find("ns1:Message", namespace).text
            return data
        else :
            data['extract_error'] = "xmns: http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006, message have an error"
            return data
    response = root_element.find("ns2:Response", namespace)
    account = response.find("ns2:Account", namespace)
    action = account.find("ns2:Action", namespace)
    protocols = account.findall("ns2:Protocol", namespace)
    
    incoming_server_data = []
    outgoing_server_data = []
    web_access_data = []
    if action.text == "redirectAddr":
        data["redirectAddr"] = account.find("ns2:RedirectAddr", namespace).text
    elif action.text == "redirectUrl":
        data["redirectUrl"] = account.find("ns2:RedirectUrl", namespace).text
    elif action.text == "settings":
        for protocol in protocols:
            if protocol.find("ns2:Type", namespace).text == "IMAP" or protocol.find("ns2:Type", namespace).text == "POP3":
                server_data = {
                    "type": protocol.find("ns2:Type", namespace).text,
                    "server": protocol.find("ns2:Server", namespace).text,
                    "port": protocol.find("ns2:Port", namespace).text,
                    "ssl": get_element_text(protocol, "ns2:SSL", namespace, "on"),
                    "encryption": get_element_text(protocol, "ns2:Encryption", namespace),
                    "spa": get_element_text(protocol, "ns2:SPA", namespace, "on"),
                    "ttl": get_element_text(protocol, "ns2:TTL", namespace, "1"),
                    "domainrequired": get_element_text(protocol, "ns2:DomainRequired", namespace)
                }

                if not server_data['port'].isdigit():
                    errors = ["Illegal port"]
                    server_data['tls_result'] = None
                    server_data['error'] = errors
                    incoming_server_data.append(server_data)
                else:
                    socketType = verify.get_autodiscover_socket_type(server_data['ssl'], server_data['encryption'], int(server_data['port']))
                    tls_res, error = verify.verify_mail_server(server_data['type'], server_data['server'],
                                                               server_data['port'], socketType)
                    server_data['tls_result'] = tls_res
                    server_data['error'] = error
                    incoming_server_data.append(server_data)
            if protocol.find("ns2:Type", namespace).text == "SMTP":
                server_data = {
                    "type": protocol.find("ns2:Type", namespace).text,
                    "server": protocol.find("ns2:Server", namespace).text,
                    "port": protocol.find("ns2:Port", namespace).text,
                    "ssl": get_element_text(protocol, "ns2:SSL", namespace, "on"),
                    "encryption": get_element_text(protocol, "ns2:Encryption", namespace),
                    "spa": get_element_text(protocol, "ns2:SPA", namespace, "on"),
                    "ttl": get_element_text(protocol, "ns2:TTL", namespace, "1"),
                    "domainrequired": get_element_text(protocol, "ns2:DomainRequired", namespace)
                }
                outgoing_server_data.append(server_data)
            # Notes: WEB is not considered in our scope.
            if protocol.find("ns2:Type", namespace).text == "WEB":
                if protocol.find("ns2:External", namespace):
                    server_data["External"] = {}
                    if protocol.find("ns2:External", namespace).find("ns2:OWAUrl", namespace):
                        server_data["External"]["OWAUrl"]["AuthenticationMethod"] = protocol.find("ns2:External", namespace).find("ns2:OWAUrl", namespace).get("AuthenticationMethod")
                        server_data["External"]["OWAUrl"]["URL"] = protocol.find("ns2:External", namespace).find("ns2:OWAUrl", namespace).text
                        web_access_data.append(server_data)
        data = {"incomingServers": incoming_server_data, "outgoingServers": outgoing_server_data, "web_access": web_access_data}
    return data


def config_from_redirect(url, mailaddress, max_redirects=10):
    '''
    Redirect found in the xml, we must use https post method, and cover the result got before
    In addition to the return structure of the HTTMethod, there is also Rediriect information

    :param url:     redirectUrl, specifies the URL of the server to use for a subsequent Autodiscover request;
    :param mailaddress:     redirectAddr, specifies the email address to use for a subsequent Autodiscover request;
    :param max_redirects:   maximum number of redircet times
    :return:    Redirect_from_xml: XML redirect history;
                Result: Configuration request result, "success" indicates success , while others indicate errors;
    '''
    # print(max_redirects)
    redirect_path = []
    for i in range(max_redirects):
        redirect_path.append({
            "url": url,
            "mailaddress": mailaddress
        })
        cur = https_post(url, mailaddress)
        # print(cur)
        if "xml" not in cur:  #fail in this step
            cur.update({"redirect_from_xml": redirect_path , "result" : "redirect meet a error, see in error"})
            return cur
        cur["config"] = parse_autodiscover(cur["xml"])
        if "extract_error" in cur["config"]:
            return {"redirect_from_xml": redirect_path , "result" : "error in xml : "+ cur["config"]["extract_error"]}
        if "redirectUrl" in cur["config"]:
            url = cur["config"]["redirectUrl"]
        elif "redirectAddr" in cur["config"]:
            mailaddress = cur["config"]["redirectAddr"]
        else:
            cur.update({"redirect_from_xml": redirect_path , "result" : "success"})
            return cur
        if (url,mailaddress) in redirect_path:    #meet a circle
            return {"redirect_from_xml": redirect_path, "result": "self redirect to : " + url + "with param" + mailaddress}
    return {"redirect_from_xml": redirect_path, "result": "Max redirects reached"}


def autodiscover(domain, mailaddress):
    '''
    Ref: https://msopenspecs.azureedge.net/files/MS-OXDISCO/%5bMS-OXDISCO%5d.pdf
    
    Besides, we also append lots of request methods to retrieve the configuration;

    :param domain: mail domain
    :param mailaddress:  mail address in form of username@domain
    :return: autodiscover result
    '''

    data = {}
    # Request from origin and prefix, including HTTP(s) GET and POST methods;
    url1 = f"http://{domain}/autodiscover/autodiscover.xml"
    url2 = f"http://autodiscover.{domain}/autodiscover/autodiscover.xml"
    url_pool =[(url1, "autodis-origin"), (url2, "autodis-prefix")]
    for url, alias in url_pool:
        data[alias] = {}
        # request from HTTP GET
        cur = http_get(url)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
            del cur['xml']
        data[alias]["http_get"] = cur

        # request from HTTP POST
        cur = http_post(url, mailaddress)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
            del cur['xml']
        data[alias]["http_post"] = cur

        # upgrade to https
        url = url.replace("http://", "https://")
        cur = https_get(url)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
            del cur['xml']
        data[alias]["https_get"] = cur

        cur = https_post(url,mailaddress)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
            del cur['xml']
        data[alias]["https_post"] = cur
    
    # Request from prefix, including HTTP GET for initial request and HTTP POST for redirect;
    url3 = f"http://autodiscover.{domain}/autodiscover/autodiscover.xml"  # Should prompt the user to warn them of the redirection.
    cur = get_redirect_post(url3, mailaddress)
    if "xml" in cur:
        cur["config"] = parse_autodiscover(cur["xml"])
        if "redirectUrl" in cur["config"]:
            cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
        elif "redirectAddr" in cur["config"]:
            cur.update(config_from_redirect(url3, cur["config"]["redirectAddr"]))
        del cur['xml']
    data['autodis-redirect'] = cur  
    
    # Retrieve Autodiscover URL from SRV record
    data['autodis-srv'] = {}
    url_from_srv = autodiscover_srv(domain)
    if url_from_srv:
        cur = https_post(url_from_srv, mailaddress)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url_from_srv, cur["config"]["redirectAddr"]))
            del cur['xml']
        data['autodis-srv'] = cur
    else:
        data['autodis-srv']['error'] =  'No SRV record'
    return data
