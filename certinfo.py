import argparse
import socket
import sys
from datetime import datetime, timezone
import os
import platform
import tempfile
import subprocess
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pem
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from cryptography.hazmat.primitives import hashes



def get_cert_chain(host, port):
    """获取SSL证书链"""
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    # 启用不安全的重协商（绕过错误）
    context.set_options(SSL.OP_LEGACY_SERVER_CONNECT) #OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)  # 关键修改

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    connection = SSL.Connection(context, sock)
    connection.set_connect_state()
    connection.set_tlsext_host_name(host.encode())  # 设置SNI
    connection.do_handshake()

    cert_chain = connection.get_peer_cert_chain()
    connection.close()
    sock.close()
    return cert_chain



def get_system_ca_certs():
    """跨平台获取系统信任的根CA证书"""
    system = platform.system()
    certs = []
    
    try:
        if system == 'Linux':
            # Linux系统通常存储在/etc/ssl/certs
            ca_path = '/etc/ssl/certs'
            for filename in os.listdir(ca_path):
                filepath = os.path.join(ca_path, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'rb') as f:
                        for cert_pem in pem.parse(f.read()):
                            certs.append(x509.load_pem_x509_certificate(
                                cert_pem.as_bytes(), default_backend()))
        
        elif system == 'Windows':
            # 使用Windows证书存储（需要安装pywin32）
            try:
                import win32crypt
                import win32security
                
                store = win32crypt.CertOpenStore(
                    win32crypt.CERT_STORE_PROV_SYSTEM,
                    0,
                    None,
                    win32crypt.CERT_SYSTEM_STORE_CURRENT_USER,
                    "ROOT"
                )
                for cert in win32crypt.CertEnumCertificatesInStore(store):
                    der_bytes = bytes(cert[1])
                    certs.append(x509.load_der_x509_certificate(der_bytes, default_backend()))
                store.Close()
            
            except ImportError:
                # 回退到certutil命令
                with tempfile.TemporaryDirectory() as tmpdir:
                    output_file = os.path.join(tmpdir, 'certs.pem')
                    subprocess.run(
                        ['certutil', '-generateSSTFromWU', output_file],
                        check=True,
                        capture_output=True
                    )
                    with open(output_file, 'rb') as f:
                        for cert_pem in pem.parse(f.read()):
                            certs.append(x509.load_pem_x509_certificate(
                                cert_pem.as_bytes(), default_backend()))
        
        elif system == 'Darwin':  # macOS
            # 使用security命令导出证书
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = os.path.join(tmpdir, 'certs.pem')
                subprocess.run(
                    ['security', 'find-certificate', '-a', '-p',
                     '/System/Library/Keychains/SystemRootCertificates.keychain'],
                    check=True,
                    stdout=open(output_file, 'wb'),
                    stderr=subprocess.PIPE
                )
                with open(output_file, 'rb') as f:
                    for cert_pem in pem.parse(f.read()):
                        certs.append(x509.load_pem_x509_certificate(
                            cert_pem.as_bytes(), default_backend()))
        
        #print(f"已加载 {len(certs)} 个系统根证书")
        return certs
    
    except Exception as e:
        print(f"系统CA加载失败: {e}")
        return []




def load_trusted_certs(args):
    """加载信任的根CA证书"""
    trusted_certs = []
    if args.ca_file:
        with open(args.ca_file, 'rb') as f:
            for cert_pem in pem.parse(f.read()):
                trusted_certs.append(x509.load_pem_x509_certificate(
                    cert_pem.as_bytes(), default_backend()))
    elif args.ca_path:
        for filename in os.listdir(args.ca_path):
            filepath = os.path.join(args.ca_path, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    try:
                        for cert_pem in pem.parse(f.read()):
                            trusted_certs.append(x509.load_pem_x509_certificate(
                                cert_pem.as_bytes(), default_backend()))
                    except Exception as e:
                        print(f"忽略无法解析的文件 {filename}: {e}")

    # 2. 加载系统CA（如果未指定自定义CA）
    if not trusted_certs:
        trusted_certs = get_system_ca_certs()

    if not trusted_certs:
        import certifi
        with open(certifi.where(), 'rb') as f:
            for cert_pem in pem.parse(f.read()):
                trusted_certs.append(x509.load_pem_x509_certificate(
                    cert_pem.as_bytes(), default_backend()))
    return trusted_certs

def print_cert_info(cert, index):
    """打印证书详细信息"""
    # 新增指纹打印部分
    def format_fingerprint(fingerprint_bytes):
        """格式化指纹为冒号分隔的十六进制字符串"""
        return ":".join(f"{b:02x}" for b in fingerprint_bytes)
    

    print(f"\n{'='*30} 证书 {index} {'='*30}")
    print(f"主  体: {cert.subject.rfc4514_string()}")
    print(f"颁发者: {cert.issuer.rfc4514_string()}")
    print(f"序列号: {hex(cert.serial_number)}")

    # SHA-1 指纹
    sha1_fp = cert.fingerprint(hashes.SHA1())
    print(f"SHA-1 指纹: {format_fingerprint(sha1_fp)}")
    
    # SHA-256 指纹
    sha256_fp = cert.fingerprint(hashes.SHA256())
    print(f"SHA-256 指纹: {format_fingerprint(sha256_fp)}")
    print(f"有效期从: {cert.not_valid_before_utc}")
    print(f"有效期至: {cert.not_valid_after_utc}")
    print(f"签名算法: {cert.signature_algorithm_oid._name}")
    # 扩展信息
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        print(f"主题备用名称: {san.value.get_values_for_type(x509.DNSName)}")
    except x509.ExtensionNotFound:
        pass

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        print("密钥用途:", key_usage.value)
    except x509.ExtensionNotFound:
        pass

    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        print("基本约束:", basic_constraints.value)
    except x509.ExtensionNotFound:
        pass

    print(f"{'='*68}")

def verify_signature(child, parent):
    """通用签名验证方法"""
    try:
        parent_pubkey = parent.public_key()
        signature_algorithm = child.signature_hash_algorithm

        # 根据密钥类型选择验证方式
        if isinstance(parent_pubkey, RSAPublicKey):
            # RSA 需要padding参数
            parent_pubkey.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_algorithm
            )
        elif isinstance(parent_pubkey, EllipticCurvePublicKey):
            # ECC 不需要padding参数
            parent_pubkey.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(signature_algorithm)
            )
        else:
            print(f"不支持的密钥类型: {type(parent_pubkey).__name__}")
            return False
        
        return True
    except Exception as e:
        print(f"签名验证错误: {e}")
        return False

def verify_signature_removed(child, parent):
    """验证证书签名"""
    try:
        parent_pubkey = parent.public_key()
        parent_pubkey.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print(f"签名验证错误: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='SSL证书链验证工具')
    parser.add_argument('host', help='目标主机名')
    parser.add_argument('--port', type=int, default=443, help='端口号 (默认: 443)')
    parser.add_argument('--ca-file', help='信任的根CA证书文件')
    parser.add_argument('--ca-path', help='信任的根CA证书目录')
    args = parser.parse_args()

    try:
        openssl_certs = get_cert_chain(args.host, args.port)
    except Exception as e:
        print(f"连接错误: {e}")
        sys.exit(1)

    if not openssl_certs:
        print("未获取到任何证书")
        sys.exit(1)

    # 转换为cryptography证书对象
    crypto_certs = []
    for oc in openssl_certs:
        der = oc.to_cryptography().public_bytes(serialization.Encoding.DER)
        crypto_certs.append(x509.load_der_x509_certificate(der, default_backend()))

    # 打印证书信息
    for i, cert in enumerate(crypto_certs):
        print_cert_info(cert, i+1)

    # 加载信任的根CA
    trusted_certs = load_trusted_certs(args)

    # 验证证书链
    valid = True
    for i in range(len(crypto_certs)):
        cert = crypto_certs[i]
        now = datetime.now(timezone.utc)
        
        # 验证有效期
        if cert.not_valid_before_utc > now:
            print(f"证书 {i+1} 尚未生效")
            valid = False
        if cert.not_valid_after_utc < now:
            print(f"证书 {i+1} 已过期")
            valid = False

        # 验证签名（除顶层证书外）
        if i < len(crypto_certs)-1:
            if not verify_signature(cert, crypto_certs[i+1]):
                print(f"证书 {i+1} 签名验证失败")
                valid = False

    # 验证顶层证书
    top_cert = crypto_certs[-1]
    top_cert_verified = False
    root_trusted_cert_found = False
    for tc in trusted_certs:
        if top_cert.issuer == tc.subject:
            root_trusted_cert_found = True
            if verify_signature(top_cert,tc):
                top_cert_verified = True
                break;
            

    if not top_cert_verified:
        if not root_trusted_cert_found:
            print("\n根证书不在信任库中!")
        else:
            print("\n顶层证书验证失败!")

        valid = False

        for tc in trusted_certs:
            print(tc.subject)
            if tc.subject == top_cert.issuer :
                print("The root cert:")
                print_cert_info(top_cert,-1)
                print("The Trust cert:")
                print_cert_info(tc,-2)
                print("^^^^^^^^^^^^^^^^^^^^")
                print(tc.serial_number,top_cert.serial_number)
                print(tc.public_key().public_bytes( encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
                print(top_cert.public_key().public_bytes( encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
                print(verify_signature(top_cert,tc))

    else:
        print("\n顶层证书已被验证，所用本地可信证书：")
        print_cert_info(tc,"local")

    if valid:
        print("\n证书链验证成功!")
    else:
        print("\n证书链验证失败!")

if __name__ == '__main__':
    main()


