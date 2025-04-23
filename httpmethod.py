'''
use http/https get or post to get a xml string
interface: http_get, https_get, http_post, https_post, get_redirect_post
param a url, (a domain of mailserver)

return a dict,
error: some error happened, this error is a http(s) error
xml: a string in xml format
redirect: all redirect paths in http header, from person lookup url to final url get the xml

https_method return,
https_verified : is certificate can be verified

in get_redirect_post return
error: redirect not to a https url
'''

import io
import requests
import certifi
import logging

LOGGER = logging.getLogger(__name__)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 (Autoconfig Test)"
DEFAULT_TIMEOUT = 5

def process_respond(response):
    """Process HTTP response and return structured output"""
    re = {}
    content_type = response.headers.get("content-type", '').lower().split(';')[0]
    if response.status_code >= 200 and response.status_code < 300:
        if content_type == "text/xml" or content_type == "application/xml":
            # track the redirection.
            # if response.history:
            redict = {}
            for redirect in response.history:
                redict[redirect.url] = redirect.status_code
            redict[response.url] = response.status_code
            re["redirect"] = redict
            # print(response.text)
            xml_file = io.StringIO(response.text)
            # data[alias]['config_from_http'] = parse_autoconfig(xml_file)
            re["xml"] = xml_file
            # config_from_http = parse_autoconfig(xml_file)
            # if config_from_http:
            #     re["config"] = config_from_http
        else:
            re["error"] = f"Unexpected content type: {content_type}"
    else:
        re["error"] = f"HTTP {response.status_code}: {response.reason}"
    return re

def http_get(url):
    """Make HTTP GET request with retries"""
    LOGGER.info(f"Making HTTP GET request to {url}")
    # user_agent = "Mozilla/5.0"
    # request from HTTP
    re = {}
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': USER_AGENT})
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
    except Exception as e:
        LOGGER.error(f"HTTP GET request failed for {url}: {str(e)}")
        re["error"] = str(e)
    else:
        re.update(process_respond(response))
    return re

def https_get(url):
    """Make HTTPS GET request with retries"""
    LOGGER.info(f"Making HTTPS GET request to {url}")
    # user_agent = "Mozilla/5.0"
    #  request from HTTPS
    re = {}
    try:
        response = requests.get(url, verify=certifi.where(), timeout=DEFAULT_TIMEOUT, headers={'User-Agent': USER_AGENT})
        re["https_verified"] = True
    except requests.exceptions.SSLError:
        LOGGER.warning(f"SSL verification failed for {url}, retrying without verification")
        try:
            re["https_verified"] = False
            response = requests.get(url, verify=False, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': USER_AGENT})
        except requests.exceptions.SSLError:
            re["error"] = "SSL Connection Error"
            return re
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
        return re
    except Exception as e:
        re["error"] = str(e)
        return re
    re.update(process_respond(response))
    return re

# post need to set data, need domain
def http_post(url, mailaddress):
    """Make HTTP POST request with retries and proper error handling"""
    LOGGER.info(f"Making HTTP POST request to {url}")
    body = f"""<?xml version='1.0' encoding='utf-8'?>
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
            <EMailAddress>{mailaddress}</EMailAddress>
            <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>"""
    re = {}
    try:
        response = requests.post(url, data=body, timeout=DEFAULT_TIMEOUT, headers={"Content-Type": "text/xml; charset=utf-8", "User-Agent": USER_AGENT})
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
    except Exception as e:
        re["error"] = str(e)
    else:
        re.update(process_respond(response))
    return re

def https_post(url, mailaddress):
    """Make HTTPS POST request with retries and proper error handling"""
    LOGGER.info(f"Making HTTPS POST request to {url}")
    body = f"""<?xml version='1.0' encoding='utf-8'?>
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
            <EMailAddress>{mailaddress}</EMailAddress>
            <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>"""
    re = {}
    try:
        response = requests.post(url, data=body, timeout=DEFAULT_TIMEOUT, headers={"Content-Type": "text/xml; charset=utf-8", "User-Agent": USER_AGENT}, verify=certifi.where())
        re["https_verified"] = True
    except requests.exceptions.SSLError:
        try:
            re["https_verified"] = False
            response = requests.post(url, data=body, timeout=DEFAULT_TIMEOUT, headers={"Content-Type": "text/xml; charset=utf-8"}, verify=False)
        except requests.exceptions.SSLError:
            re["error"] = "SSL Connection Error"
            return re
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
        return re
    except Exception as e:
        re["error"] = str(e)
        return re
    re.update(process_respond(response))
    return re

def get_redirect_post(url, mailaddress):
    """
    this function will redict a http get method to a https post method to get a xml string
    """
    LOGGER.info(f"Making HTTP GET initial then HTTP POST to {url}")
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if not response.history:
            return {}

        redirect_chain = {}
        all_responses = list(response.history) + [response]
        for r in all_responses:
            if r.url.startswith("https://"):
                # Record all redirects to the current URL
                for prev_r in all_responses:
                    if prev_r.url == r.url:
                        break
                    redirect_chain[prev_r.url] = prev_r.status_code
                
                # Send POST request and return result
                post_result = https_post(r.url, mailaddress)
                result = {"redirect": redirect_chain}
                if "redirect" in post_result:
                    result["redirect"].update(post_result.pop("redirect"))
                result.update(post_result)
                return result
            else:
                # Record HTTP redirects
                redirect_chain[r.url] = r.status_code
                
        # If no HTTPS URL is encountered, return an empty dictionary
        return {}
        
    except requests.exceptions.RequestException:
        return {}
