from opencanary.modules import CanaryService
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.application import internet
from opencanary.modules.des import des
import os

RFB_33 = b"003.003"
RFB_37 = b"003.007"
RFB_38 = b"003.008"

def load_password_list():
    """Load passwords from file with validation"""
    password_file = os.path.join(os.path.dirname(__file__), 'vncpasswords.txt')
    passwords = []
    try:
        with open(password_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    if not line.isascii():
                        print(f"WARNING: Skipping non-ASCII password '{line}'")
                        continue
                    passwords.append(line)
        print(f"Loaded {len(passwords)} VNC passwords")
        return passwords
    except Exception as e:
        print(f"ERROR: Failed to load passwords ({e}), using defaults")
        return [
            "password", "123456", "admin", "root", 
            "1234", "qwerty", "letmein", "vizxv"
        ]

COMMON_PASSWORDS = load_password_list()

# Protocol states
PRE_INIT = 1
HANDSHAKE_SEND = 2
SECURITY_SEND = 3
AUTH_SEND = 4
AUTH_OVER = 5

class ProtocolError(Exception):
    pass

class UnsupportedVersion(Exception):
    pass

class VNCProtocol(Protocol):
    def __init__(self, version=RFB_38):
        self.serv_version = version
        self.state = PRE_INIT

    def _try_decrypt_response(self, response):
        """Check response against passwords without precomputation"""
        for password in COMMON_PASSWORDS:
            try:
                pw = password[:8].ljust(8, '\x00').encode('ascii')
                mirrored = bytearray(int(f"{x:08b}"[::-1], 2) for x in pw)
                if des(mirrored).decrypt(response) == self.challenge:
                    return password
            except Exception as e:
                print(f"WARNING: Failed to check password '{password}': {e}")
        return None

    def _send_handshake(self):
        self.transport.write(f"RFB {self.serv_version.decode()}\n".encode())
        self.state = HANDSHAKE_SEND

    def _recv_handshake(self, data):
        if len(data) != 12 or not data.startswith(b"RFB"):
            raise ProtocolError()
        client_ver = data[4:-1]
        if client_ver not in (RFB_33, RFB_37, RFB_38):
            raise UnsupportedVersion()
        self._send_security(client_ver)

    def _send_security(self, client_ver):
        if client_ver == RFB_33:
            self.transport.write(b"\x00\x00\x00\x02")  # VNC auth
            self._send_auth()
        else:
            self.transport.write(b"\x01\x02")  # VNC auth
            self.state = SECURITY_SEND

    def _recv_security(self, data):
        if data != b"\x02":
            raise ProtocolError()
        self._send_auth()

    def _send_auth(self):
        self.challenge = os.urandom(16)
        self.transport.write(self.challenge)
        self.state = AUTH_SEND

    def _recv_auth(self, data):
        if len(data) != 16:
            raise ProtocolError()

        used_password = self._try_decrypt_response(data)
        self.factory.log({
            "VNC Challenge": self.challenge.hex(),
            "VNC Response": data.hex(),
            "VNC Password": used_password or "<Not in list>"
        }, transport=self.transport)
        
        self._send_auth_failed()

    def _send_auth_failed(self):
        self.transport.write(
            b"\x00\x00\x00\x01" +  # Auth failed
            b"\x00\x00\x00\x16" +  # Message length
            b"Authentication failure"  # Message
        )
        self.state = AUTH_OVER
        self.transport.loseConnection()

    def connectionMade(self):
        self._send_handshake()

    def dataReceived(self, data):
        try:
            if self.state == HANDSHAKE_SEND:
                self._recv_handshake(data)
            elif self.state == SECURITY_SEND:
                self._recv_security(data)
            elif self.state == AUTH_SEND:
                self._recv_auth(data)
        except (ProtocolError, UnsupportedVersion):
            self.transport.loseConnection()

class CanaryVNC(Factory, CanaryService):
    NAME = "VNC"
    protocol = VNCProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("vnc.port", 5900)
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_VNC

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)

CanaryServiceFactory = CanaryVNC
