from dns_server import DNSServer


if __name__ == '__main__':
    server = DNSServer()
    server.start(port=53)
