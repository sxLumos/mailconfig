import logging
import threading
import socket
import requests
from typing import List, Dict, Union, Any

import verify

LOGGER = logging.getLogger(__name__)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 (Autoconfig Test)"
DEFAULT_TIMEOUT = 5


class GuessMethod:
    SMTP_PREFIX = ["smtp.", "smtps.", "mail.", "submission."]
    SMTP_PORT = [465, 587]
    IMAP_PREFIX = ["imap.", "imaps.", "mail.", "mx."]
    IMAP_PORT = [143, 993]
    POP_PREFIX = ["pop.", "pop3.", "pops.", "mail.", "mx."]
    POP_PORT = [110, 995]
    WEBMAIL_PREFIX = ["mail.", "webmail."]

    PORT_PROTOCOL: Dict[int, str] = {}
    CONFIGURATION_PORT_HOSTNAMES: Dict[int, List[str]] = {}

    @classmethod
    def _initialize(cls):
        """Initialize the configuration mappings."""
        try:
            # Initialize SMTP mail server info
            for port in cls.SMTP_PORT:
                cls.CONFIGURATION_PORT_HOSTNAMES[port] = cls.SMTP_PREFIX
                cls.PORT_PROTOCOL[port] = "SMTP"

            # Initialize IMAP mail server info
            for port in cls.IMAP_PORT:
                cls.CONFIGURATION_PORT_HOSTNAMES[port] = cls.IMAP_PREFIX
                cls.PORT_PROTOCOL[port] = "IMAP"

            # Initialize POP mail server info
            for port in cls.POP_PORT:
                cls.CONFIGURATION_PORT_HOSTNAMES[port] = cls.POP_PREFIX
                cls.PORT_PROTOCOL[port] = "POP"
        except Exception as e:
            LOGGER.error(f"Error initializing configuration: {str(e)}")
            raise

    @staticmethod
    def check_tcp_connection(hostname: str, port: int, timeout: float = 5.0) -> bool:
        """Check if a TCP connection can be established to the given hostname and port."""
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                LOGGER.debug(f"Successfully connected to {hostname}:{port}")
                return True
        except socket.timeout:
            LOGGER.warning(f"Connection timeout for {hostname}:{port}")
        except socket.gaierror:
            LOGGER.warning(f"DNS resolution failed for {hostname}")
        except ConnectionRefusedError:
            LOGGER.debug(f"Connection refused for {hostname}:{port}")
        except OSError as e:
            LOGGER.warning(f"OS error occurred for {hostname}:{port}: {str(e)}")
        return False

    @staticmethod
    def check_webmail(url: str, timeout: float = 5.0) -> bool:
        """Check if a webmail URL is accessible."""
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            if response.status_code < 400:  # 2xx and 3xx status codes
                LOGGER.debug(f"Webmail accessible: {url} (Status: {response.status_code})")
                return True
            LOGGER.debug(f"Webmail returned error status: {url} (Status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            LOGGER.debug(f"Webmail connection failed for {url}: {str(e)}")
        return False

    @classmethod
    def guess_webmail(cls, domain: str, timeout: float = 5.0) -> List[str]:
        """Guess possible webmail URLs for the given domain."""
        results = []
        threads = []
        results_lock = threading.Lock()

        def worker(prefix: str):
            url = f"https://{prefix}{domain}/"
            # if cls.check_tcp_connection(prefix + domain, 443, timeout) and cls.check_webmail(url, timeout):
            if cls.check_tcp_connection(prefix + domain, 443, timeout):
                with results_lock:
                    results.append(url)

        try:
            for prefix in cls.WEBMAIL_PREFIX:
                thread = threading.Thread(
                    target=worker,
                    args=(prefix,),
                    name=f"WebmailCheck_{prefix}{domain}"
                )
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            return results

        except Exception as e:
            LOGGER.error(f"Error during webmail discovery: {str(e)}")
            return []

    @classmethod
    def guess_mail_servers(cls, domain: str, timeout: float = 5.0) -> Dict[
        Any, Dict[str, Union[bool, None, List[str]]]]:
        """Internal method to guess mail servers."""
        results = {}
        if not cls.CONFIGURATION_PORT_HOSTNAMES:
            try:
                cls._initialize()
            except Exception as e:
                LOGGER.error(f"Failed to initialize configuration: {str(e)}")
                return {}

        threads = []
        configs = []
        results_lock = threading.Lock()

        def worker(hostname: str, port: int):
            try:
                if cls.check_tcp_connection(hostname, port, timeout):
                    with results_lock:
                        configs.append(f"{hostname}:{port}")
            except Exception as e:
                LOGGER.error(f"Error in worker thread for {hostname}:{port}: {str(e)}")

        try:
            for port, prefixes in cls.CONFIGURATION_PORT_HOSTNAMES.items():
                for prefix in prefixes:
                    hostname = prefix + domain
                    thread = threading.Thread(
                        target=worker,
                        args=(hostname, port),
                        name=f"Check_{hostname}_{port}"
                    )
                    threads.append(thread)
                    thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            for config in configs:
                hostname, port = config.split(':')
                tls_res, errors = verify.verify_guess(hostname, port)
                results[config] = {'tls_result': tls_res,
                                   'error': errors}
            return results

        except Exception as e:
            LOGGER.error(f"Error during mail server discovery: {str(e)}")
            return {}


if __name__ == "__main__":
    # 可以在这里调整日志级别
    LOGGER.setLevel(logging.DEBUG)  # 设置为DEBUG可以看到更多详细信息
    domain = "163.com"
    timeout = 5.0
    # GuessMethod.check_webmail("https://mail.astrumserver.ru/", timeout)
    results_mail_servers = GuessMethod.guess_mail_servers(domain, timeout)
    print(results_mail_servers)
    results_webmail = GuessMethod.guess_webmail(domain, timeout)
    print(results_webmail)
