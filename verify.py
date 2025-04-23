from typing import Tuple, Optional, List
import ssl
import socket

import smtplib, imaplib, poplib


mail_protocol = ['smtp', 'imap', 'pop']

# Protocol Mapping
PORT_TO_PROTOCOL = {
    "993": "imap",
    "143": "imap",
    "995": "pop3",
    "110": "pop3",
    "465": "smtp",
    "587": "smtp",
    "25": "smtp"
}

# SocketType Mapping
PORT_TO_SOCKETTYPE = {
    "993": "ssl",
    "995": "ssl",
    "465": "ssl",
    "143": "starttls",
    "110": "starttls",
    "587": "starttls",
    "25": "starttls"
}


def verify_mail_server(type: str, port: str, hostname: str, socketType: str) -> Tuple[Optional[bool], List[str]]:
    tls_res = None
    errors = []
    if type.lower() not in mail_protocol:
        errors.append("Unknown mail protocol")
    else:
        if socketType.lower() == "ssl":
            if not port.isdigit:
                errors.append("Illegal port")
            else:
                tls_res, error = verify_mail_server_certificate(hostname, int(port), type, "ssl")
                if error is not None:
                    errors.append(error)
        elif socketType.lower() == "starttls":
            if not port.isdigit:
                errors.append("Illegal port")
            else:
                tls_res, error = verify_mail_server_certificate(hostname, int(port), type, "starttls")
                if error is not None:
                    errors.append(error)
    return tls_res, errors


def get_autodiscover_socket_type(ssl: str, encryption: str, port: int) -> str:
    if encryption is None and ssl is None:
        return "unknown"

    if encryption is not None:
        encryption = encryption.lower()
        if encryption in ("ssl", "tls"):
            if port in (993, 995, 465):
                return "ssl"
            elif port in (143, 110, 587, 25):
                return "starttls"
            else:
                return "ssl"
        elif encryption == "none":
            return "plain"
        elif encryption == "auto":
            if port in (993, 995, 465):
                return "ssl"
            elif port in (143, 110, 587, 25):
                return "starttls"
            else:
                return "starttls"
        else:
            if ssl is None:
                return "unknown"
            ssl = ssl.lower()
            if ssl == "on":
                if port in (993, 995, 465):
                    return "ssl"
                elif port in (143, 110, 587, 25):
                    return "starttls"
                else:
                    return "ssl"
            elif ssl == "off":
                return "plain"
            else:
                return "unknown"
    else:  # encryption is None and ssl is not None
        ssl = ssl.lower()
        if ssl == "on":
            if port in (993, 995, 465):
                return "ssl"
            elif port in (143, 110, 587, 25):
                return "starttls"
            else:
                return "ssl"
        elif ssl == "off":
            return "plain"
        else:
            return "unknown"


def verify_srv(hostname: str, port: str, protocol: str) -> Tuple[Optional[bool], List[str]]:
    tls_res = None
    errors = []
    if port not in PORT_TO_SOCKETTYPE:
        errors.append("Illegal port")
        return tls_res, errors
    socketType = PORT_TO_SOCKETTYPE[port]
    if socketType.lower() == "ssl":
        tls_res, error = verify_mail_server_certificate(hostname, int(port), protocol, "starttls")
        if error is not None:
            errors.append(error)
    elif socketType.lower() == "starttls":
        tls_res, error = verify_mail_server_certificate(hostname, int(port), protocol, "starttls")
        if error is not None:
            errors.append(error)
    return tls_res, errors


def verify_mx(hostname: str, port: int) -> Tuple[Optional[bool], List[str]]:
    tls_res = None
    errors = []
    tls_res, error = verify_mail_server_certificate(hostname, int(port), "smtp", "starttls")
    if error is not None:
        errors.append(error)
    return tls_res, errors


def verify_guess(hostname: str, port: str) -> Tuple[Optional[bool], List[str]]:
    tls_res = None
    errors = []
    if port not in PORT_TO_PROTOCOL or port not in PORT_TO_SOCKETTYPE:
        errors.append("Illegal port")
        return tls_res, errors
    if PORT_TO_SOCKETTYPE[port] == "ssl":
        tls_res, error = verify_mail_server_certificate(hostname, int(port), PORT_TO_PROTOCOL[port], "ssl")
        if error is not None:
            errors.append(error)
    else:
        tls_res, error = verify_mail_server_certificate(hostname, int(port), PORT_TO_PROTOCOL[port], "starttls")
        if error is not None:
            errors.append(error)
    return tls_res, errors


def verify_server_certificate(
        hostname: str,
        port: int,
        timeout: int = 5
) -> Tuple[bool, Optional[str]]:
    """
    验证服务器证书是否可信
    :param hostname: 服务器主机名
    :param port: 端口号
    :param timeout: 连接超时(秒)
    :return: (是否可信, 错误信息/None)
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # 验证主机名是否匹配证书
                ssl.match_hostname(cert, hostname)
        return True, None
    except ssl.CertificateError as e:
        return False, f"Certificate is invalid: {e}"
    except ssl.SSLError as e:
        return False, f"SSL Error: {e}"
    except socket.timeout:
        return False, "Connection Timeout"
    except Exception as e:
        return False, f"Connection Error: {e}"


def verify_mail_server_certificate(
        hostname: str,
        port: int,
        protocol: str,
        socket_type: str
) -> Tuple[bool, Optional[str]]:
    """
    验证邮件服务器证书
    :param hostname: 服务器地址
    :param port: 端口号
    :param protocol: 协议(smtp/imap/pop3)
    :param socket_type: 加密类型(tls/starttls)
    :return: (是否可信, 错误信息/None)
    """
    if socket_type == "ssl":
        # 直接TLS连接
        return verify_server_certificate(hostname, port)
    elif socket_type == "starttls":
        # STARTTLS需要先建立普通连接再升级
        try:
            if protocol == "smtp":
                with smtplib.SMTP(hostname, port, timeout=5) as server:
                    server.starttls()
                    server.ehlo()
                    return True, None
            elif protocol == "imap":
                with imaplib.IMAP4(hostname, port) as server:
                    server.starttls()
                    return True, None
            elif protocol == "pop3":
                with poplib.POP3(hostname, port, timeout=5) as server:
                    server.stls()
                    return True, None
            else:
                return False, "Unsupported Protocol"
        except ssl.SSLError as e:
            return False, f"STARTTLS SSL Error: {e}"
        except Exception as e:
            return False, f"STARTTLS Error: {str(e)}"
    else:
        return False, "Unsupported Encryption Protocol"


if __name__ == '__main__':
    print(verify_mail_server_certificate("pop.zambianmusic.net", 110, "smtp", "starttls"))
