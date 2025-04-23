import logging
import subprocess

LOGGER = logging.getLogger(__name__)


def verify_with_openssl(hostname, port, protocol, starttls=False):
    """使用 openssl s_client 验证证书"""
    # 构造 openssl 命令
    cmd = [
        "openssl", "s_client",
        "-connect", f"{hostname}:{port}",
        "-servername", hostname,  # SNI 支持
        "-showcerts"
    ]

    # 添加 STARTTLS 参数（如果适用）
    if starttls:
        cmd.extend(["-starttls", protocol])

    # 执行命令并捕获输出
    try:
        result = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=5
        )

        if result.returncode != 0:
            LOGGER.error(
                f"{hostname}:{port}<{protocol}><starttls: {starttls}> 连接失败: {result.stderr if result.stderr else '无错误信息'}")
            return None

        return result.stdout
    except subprocess.TimeoutExpired:
        LOGGER.error(f"{hostname}:{port}<{protocol}><starttls: {starttls}> OpenSSL 连接超时")
    except subprocess.CalledProcessError as e:
        LOGGER.error(f"{hostname}:{port}<{protocol}><starttls: {starttls}> OpenSSL 命令执行失败: {e}")
    except Exception as e:
        LOGGER.error(f"{hostname}:{port}<{protocol}><starttls: {starttls}> 发生意外错误: {e}")
    return None


if __name__ == '__main__':
    print(verify_with_openssl("imap.163.com", 993, "imap", False))
