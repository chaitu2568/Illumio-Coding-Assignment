import sys
import pandas as pd

class Firewall:

    def __init__(self, filepath = sys.argv[1]):
        self.main_df = pd.read_csv(filepath, names = ['direction', 'protocol', 'port', 'ip_address'])

    def accept_packet(self, direction, protocol, port, ip_address):

        df = self.main_df.loc[self.main_df['direction'] == direction]
        if df.empty:
            return False
        df = df.loc[self.main_df['protocol'] == protocol]
        if df.empty:
            return False
        df = df[df.port.apply((lambda x : self.portCheck(port, x)))]
        if df.empty:
            return False
        df =  df[df.ip_address.apply((lambda x : self.ipCheck(ip_address, x)))]
        if df.empty:
            return False

        return True

    def portCheck(self, port, mainPort):
        sepIndex = mainPort.find("-")
        if sepIndex == -1:
            mainPort = int(mainPort)
            return port == mainPort
        else:
            min_port = int(mainPort[:sepIndex])
            max_port = int(mainPort[sepIndex + 1:])
            return port >= min_port and port <= max_port


    def ipCheck(self, ip, mainIP):
        sepIndex = mainIP.find("-")
        if sepIndex == -1:
            return ip == mainIP
        else:
            min_ip = mainIP[:sepIndex]
            min_ip = int(min_ip.replace(".", ""))
            max_ip = mainIP[sepIndex + 1:]
            max_ip = int(max_ip.replace(".", ""))
            ip = int(ip.replace(".", ""))
            return ip >= min_ip and ip <= max_ip


if __name__ == "__main__":
    obj = Firewall()
    print(obj.accept_packet("inbound", "udp", 53, "192.168.2.1"))

