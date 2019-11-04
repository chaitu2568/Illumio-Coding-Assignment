from firewall import *

class TestFirewall:
    def test1(self):
        firewall = Firewall("testing_data.csv")
        assert firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2") == True

    def test2(self):
        firewall = Firewall("testing_data.csv")
        assert firewall.accept_packet("outbound", "tcp", 45, "1.1.1.1") == True

    def test3(self):
        firewall = Firewall("testing_data.csv")
        assert firewall.accept_packet("inbound", "udp", 53, "192.168.1.2") == False

    def test4(self):
        firewall = Firewall("testing_data.csv")
        assert firewall.accept_packet("outbounds", "udp", 53, "192.168.1.2") == False

    def test5(self):
        firewall = Firewall("testing_data.csv")
        assert firewall.accept_packet("inbound", "udp", 46000, "192.168.10.1") == True

    def test6(self):
        firewall = Firewall("testing_data.csv")
        assert firewall.accept_packet("outbound", "udp", 53, "266.168.1.2") == False
