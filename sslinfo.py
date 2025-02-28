import ssl
import socket

def get_ssl_protocol_version(hostname, port=443):
    context = ssl.create_default_context()

    # 通过 Socket 连接到目标网站
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    
    try:
        conn.connect((hostname, port))
        ssl_info = conn.version()  # 获取 SSL/TLS 协议版本
        print(f"使用的 SSL/TLS 协议版本: {ssl_info}")
        
        # 检查协议版本是否为不安全的版本
        if ssl_info in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1_1']:
            print(f"警告：该网站使用了不安全的协议版本：{ssl_info}")
        else:
            print(f"该网站使用了安全的协议版本：{ssl_info}")
        
        # 检查是否启用了 Legacy Renegotiation（不安全的重新协商）
        # 根据 OpenSSL 的配置和 Python 的 ssl 模块，有些不安全的协商会被禁用
        try:
            context.set_ciphers('DEFAULT@SECLEVEL=1')  # 设置较低的安全级别，可能允许不安全的协商
            conn_renegotiate = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn_renegotiate.connect((hostname, port))
            print("该服务器启用了 Legacy Renegotiation（不安全的重新协商）")
        except ssl.SSLError as e:
            if "unsafe legacy renegotiation disabled" in str(e):
                print("该服务器禁用了 Legacy Renegotiation（安全）。")
            else:
                print(f"其他 SSL 错误：{e}")
    except ssl.SSLError as e:
        print(f"SSL 错误：{e}")
    finally:
        conn.close()

def main():
    hostname = input("请输入目标网站的主机名（例如 'www.google.com'）：")
    get_ssl_protocol_version(hostname)

if __name__ == "__main__":
    main()


