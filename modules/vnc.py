from opencanary.modules import CanaryService

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory

from opencanary.modules.des import des

import os

RFB_33 = b"003.003"
RFB_37 = b"003.007"
RFB_38 = b"003.008"

# states
PRE_INIT = 1
HANDSHAKE_SEND = 2
SECURITY_SEND = 3
AUTH_SEND = 4
AUTH_OVER = 5

# if one of these is used in the VNC authentication attempt, alert that
# a common password was tried
COMMON_PASSWORDS = [
'123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', 'administrator', 'root', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', '696969', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'pussy', 'superman', '1qaz2wsx', '7777777', 'fuckyou', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'fuckme', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'asshole', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'fuck', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', '6969', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'william', 'corvette', 'hello', 'martin', 'heather', 'secret', 'fucker', 'merlin', 'diamond', '1234qwer', 'gfhjkm', 'hammer', 'silver', '222222', '88888888', 'anthony', 'justin', 'test', 'bailey', 'q1w2e3r4t5', 'patrick', 'internet', 'scooter', 'orange', '11111', 'golfer', 'cookie', 'richard', 'samantha', 'bigdog', 'guitar', 'jackson', 'whatever', 'mickey', 'chicken', 'sparky', 'snoopy', 'maverick', 'phoenix', 'camaro', 'sexy', 'peanut', 'morgan', 'welcome', 'falcon', 'cowboy', 'ferrari', 'samsung', 'andrea', 'smokey', 'steelers', 'joseph', 'mercedes', 'dakota', 'arsenal', 'eagles', 'melissa', 'boomer', 'booboo', 'spider', 'nascar', 'monster', 'tigers', 'yellow', 'xxxxxx', '123123123', 'gateway', 'marina', 'diablo', 'bulldog', 'qwer1234', 'compaq', 'purple', 'hardcore', 'banana', 'junior', 'hannah', '123654', 'porsche', 'lakers', 'iceman', 'money', 'cowboys', '987654', 'london', 'tennis', '999999', 'ncc1701', 'coffee', 'scooby', '0000', 'miller', 'boston', 'q1w2e3r4', 'fuckoff', 'brandon', 'yamaha', 'chester', 'mother', 'forever', 'johnny', 'edward', '333333', 'oliver', 'redsox', 'player', 'nikita', 'knight', 'fender', 'barney', 'midnight', 'please', 'brandy', 'chicago', 'badboy', 'iwantu', 'slayer', 'rangers', 'charles', 'angel', 'flower', 'bigdaddy', 'rabbit', 'wizard', 'bigdick', 'jasper', 'enter', 'rachel', 'chris', 'steven', 'winner', 'adidas', 'victoria', 'natasha', '1q2w3e4r', 'jasmine', 'winter', 'prince', 'panties', 'marine', 'ghbdtn', 'fishing', 'cocacola', 'casper', 'james', '232323', 'raiders', '888888', 'marlboro', 'gandalf', 'asdfasdf', 'crystal', '87654321', '12344321', 'sexsex', 'golden', 'blowme', 'bigtits', '8675309', 'panther', 'lauren', 'angela', 'bitch', 'spanky', 'thx1138', 'angels', 'madison', 'winston', 'shannon', 'mike', 'toyota', 'blowjob', 'jordan23', 'canada', 'sophie', 'Password', 'apples', 'dick', 'tiger', 'razz', '123abc', 'pokemon', 'qazxsw', '55555', 'qwaszx', 'muffin', 'johnson', 'murphy', 'cooper', 'jonathan', 'liverpoo', 'david', 'danielle', '159357', 'jackie', '1990', '123456a', '789456', 'turtle', 'horny', 'abcd1234', 'scorpion', 'qazwsxedc', '101010', 'butter', 'carlos', 'password1', 'dennis', 'slipknot', 'qwerty123', 'booger', 'asdf', '1991', 'black', 'startrek', '12341234', 'cameron', 'newyork', 'rainbow', 'nathan', 'john', '1992', 'rocket', 'viking', 'redskins', 'butthead', 'asdfghjkl', '1212', 'sierra', 'peaches', 'gemini', 'doctor', 'wilson', 'sandra', 'helpme', 'qwertyui', 'victor', 'florida', 'dolphin', 'pookie', 'captain', 'tucker', 'blue', 'liverpool', 'theman', 'bandit', 'dolphins', 'maddog', 'packers', 'jaguar', 'lovers', 'nicholas', 'united', 'tiffany', 'maxwell', 'zzzzzz', 'nirvana', 'jeremy', 'suckit', 'stupid', 'porn', 'monica', 'elephant', 'giants', 'jackass', 'hotdog', 'rosebud', 'success', 'debbie', 'mountain', '444444', 'xxxxxxxx', 'warrior', '1q2w3e4r5t', 'q1w2e3', '123456q', 'albert', 'metallic', 'lucky', 'azerty', '7777', 'shithead', 'alex', 'bond007', 'alexis', '1111111', 'samson', '5150', 'willie', 'scorpio', 'bonnie', 'gators', 'benjamin', 'voodoo', 'driver', 'dexter', '2112', 'jason', 'calvin', 'freddy', '212121', 'creative', '12345a', 'sydney', 'rush2112', '1989', 'asdfghjk', 'red123', 'bubba', '4815162342', 'passw0rd', 'trouble', 'gunner', 'happy', 'fucking', 'gordon', 'legend', 'jessie', 'stella', 'qwert', 'eminem', 'arthur', 'apple', 'nissan', 'bullshit', 'bear', 'america', '1qazxsw2', 'nothing', 'parker', '4444', 'rebecca', 'qweqwe', 'garfield', '01012011', 'beavis', '69696969', 'jack', 'asdasd', 'december', '2222', '102030', '252525', '11223344', 'magic', 'apollo', 'skippy', '315475', 'girls', 'kitten', 'golf', 'copper', 'braves', 'shelby', 'godzilla', 'beaver', 'fred', 'tomcat', 'august', 'buddy', 'airborne', '1993', '1988', 'lifehack', 'qqqqqq', 'brooklyn', 'animal', 'platinum', 'phantom', 'online', 'xavier', 'darkness', 'blink182', 'power', 'fish', 'green', '789456123', 'voyager', 'police', 'travis', '12qwaszx', 'heaven', 'snowball', 'lover', 'abcdef', '00000', 'pakistan', '007007', 'walter', 'playboy', 'blazer', 'cricket', 'sniper', 'hooters', 'donkey', 'willow', 'loveme', 'saturn', 'therock', 'redwings', 'bigboy', 'pumpkin', 'trinity', 'williams', 'tits', 'nintendo', 'digital', 'destiny', 'topgun', 'runner', 'marvin', 'guinness', 'chance', 'bubbles', 'testing', 'fire', 'november', 'minecraft', 'asdf1234', 'lasvegas', 'sergey', 'broncos', 'cartman', 'private', 'celtic', 'birdie', 'little', 'cassie', 'babygirl', 'donald', 'beatles', '1313', 'dickhead', 'family', '12121212', 'school', 'louise', 'gabriel', 'eclipse', 'fluffy', '147258369', 'lol123', 'explorer', 'beer', 'nelson', 'flyers', 'spencer', 'scott', 'lovely', 'gibson', 'doggie', 'cherry', 'andrey', 'snickers', 'buffalo', 'pantera', 'metallica', 'member', 'carter', 'qwertyu', 'peter', 'alexande', 'steve', 'bronco', 'paradise', 'goober', '5555', 'samuel', 'montana', 'mexico', 'dreams', 'michigan', 'cock', 'carolina', 'yankee', 'friends', 'magnum', 'surfer', 'poopoo', 'maximus', 'genius', 'cool', 'vampire', 'lacrosse', 'asd123', 'aaaa', 'christin', 'kimberly', 'speedy', 'sharon', 'carmen', '111222', 'kristina', 'sammy', 'racing', 'ou812', 'sabrina', 'horses', '0987654321', 'qwerty1', 'pimpin', 'baby', 'stalker', 'enigma', '147147', 'star', 'poohbear', 'boobies', '147258', 'simple', 'bollocks', '12345q', 'marcus', 'brian', '1987', 'qweasdzxc', 'drowssap', 'hahaha', 'caroline', 'barbara', 'dave', 'viper', 'drummer', 'action', 'einstein', 'bitches', 'genesis', 'hello1', 'scotty', 'friend', 'forest', '010203', 'hotrod', 'google', 'vanessa', 'spitfire', 'badger', 'maryjane', 'friday', 'alaska', '1232323q', 'tester', 'jester', 'jake', 'champion', 'billy', '147852', 'rock', 'hawaii', 'badass', 'chevy', '420420', 'walker', 'stephen', 'eagle1', 'bill', '1986', 'october', 'gregory', 'svetlana', 'pamela', '1984', 'music', 'shorty', 'westside', 'stanley', 'diesel', 'courtney', '242424', 'kevin', 'porno', 'hitman', 'boobs', 'mark', '12345qwert', 'reddog', 'frank', 'qwe123', 'popcorn', 'patricia', 'aaaaaaaa', '1969', 'teresa', 'mozart', 'buddha', 'anderson', 'paul', 'melanie', 'abcdefg', 'security', 'lucky1', 'lizard', 'denise', '3333', 'a12345', '123789', 'ruslan', 'stargate', 'simpsons', 'scarface', 'eagle', '123456789a', 'thumper', 'olivia', 'naruto', '1234554321', 'general', 'cherokee', 'a123456', 'vincent', 'Usuckballz1', 'spooky', 'qweasd', 'cumshot', 'free', 'frankie', 'douglas', 'death', '1980', 'loveyou', 'kitty', 'kelly', 'veronica', 'suzuki', 'semperfi', 'enguin', 'mercury', 'liberty', 'spirit', 'scotland', 'natalie', 'marley', 'vikings', 'system', 'sucker', 'king', 'allison', 'marshall', '1979', '098765', 'qwerty12', 'hummer', 'adrian', '1985', 'vfhbyf', 'sandman', 'rocky', 'leslie', 'antonio', '98765432', '4321', 'softball', 'passion', 'mnbvcxz', 'bastard', 'passport', 'horney', 'rascal', 'howard', 'franklin', 'bigred', 'assman', 'alexander', 'homer', 'redrum', 'jupiter', 'claudia', '55555555', '141414', 'zaq12wsx', 'shit', 'patches', 'nigger', 'cunt', 'raider', 'infinity', 'andre', '54321', 'galore', 'college', 'russia', 'kawasaki', 'bishop', '77777777', 'vladimir', 'money1', 'freeuser', 'wildcats', 'francis', 'disney', 'budlight', 'brittany', '1994', '00000000', 'sweet', 'oksana', 'honda', 'domino', 'bulldogs', 'brutus', 'swordfis', 'norman', 'monday', 'jimmy', 'ironman', 'ford', 'fantasy', '9999', '7654321', 'PASSWORD', 'hentai', 'duncan', 'cougar', '1977', 'jeffrey', 'house', 'dancer', 'brooke', 'timothy', 'super', 'marines', 'justice', 'digger', 'connor', 'patriots', 'karina', '202020', 'molly', 'everton', 'tinker', 'alicia', 'rasdzv3', 'poop', 'pearljam', 'stinky', 'naughty', 'colorado', '123123a', 'water', 'test123', 'ncc1701d', 'motorola', 'ireland', 'asdfg', 'slut', 'matt', 'houston', 'boogie', 'zombie', 'accord', 'vision', 'bradley', 'reggie', 'kermit', 'froggy', 'ducati', 'avalon', '6666', '9379992', 'sarah', 'saints', 'logitech', 'chopper', '852456', 'simpson', 'madonna', 'juventus', 'claire', '159951', 'zachary', 'yfnfif', 'wolverin', 'warcraft', 'hello123', 'extreme', 'penis', 'peekaboo', 'fireman', 'eugene', 'brenda', '123654789', 'russell', 'panthers', 'georgia', 'smith', 'skyline', 'jesus', 'elizabet', 'spiderma', 'smooth', 'pirate', 'empire', 'bullet', '8888', 'virginia', 'valentin', 'psycho', 'predator', 'arizona', '134679', 'mitchell', 'alyssa', 'vegeta', 'titanic', 'christ', 'goblue', 'fylhtq', 'wolf', 'mmmmmm', 'kirill', 'indian', 'hiphop', 'baxter', 'awesome', 'people', 'danger', 'roland', 'mookie', '741852963', '1111111111', 'dreamer', 'bambam', 'arnold', '1981', 'skipper', 'serega', 'rolltide', 'elvis', 'changeme', 'simon', '1q2w3e', 'lovelove', 'fktrcfylh', 'denver', 'tommy', 'mine', 'loverboy', 'hobbes', 'happy1', 'alison', 'nemesis', 'chevelle', 'cardinal', 'burton', 'wanker', 'picard', '151515', 'tweety', 'michael1', '147852369', '12312', 'xxxx', 'windows', 'turkey', '456789', '1974', 'vfrcbv', 'sublime', '1975', 'galina', 'bobby', 'newport', 'manutd', 'daddy', 'american', 'alexandr', '1966', 'victory', 'rooster', 'qqq111', 'madmax', 'electric', 'bigcock', 'a1b2c3', 'wolfpack', 'spring', 'phpbb', 'lalala', 'suckme', 'spiderman', 'eric', 'darkside', 'classic', 'raptor', '123456789q', 'hendrix', '1982', 'wombat', 'avatar', 'alpha', 'zxc123', 'crazy', 'hard', 'england', 'brazil', '1978', '01011980', 'wildcat', 'polina', 'freepass'
]


class ProtocolError(Exception):
    pass


class UnsupportedVersion(Exception):
    pass


class VNCProtocol(Protocol):
    """
    Implementation of VNC up to VNC authentication
    """

    def __init__(self, version=RFB_38):
        self.serv_version = version
        self.state = PRE_INIT

    def _send_handshake(
        self,
    ):
        print("send handshake")
        version_string = "RFB {version}\n".format(
            version=self.serv_version.decode("utf-8")
        )
        self.transport.write(version_string.encode("utf-8"))
        self.state = HANDSHAKE_SEND

    def _recv_handshake(self, data=None):
        print("got handshake")
        if len(data) != 12 or data[:3] != b"RFB":
            raise ProtocolError()
        client_ver = data[4:-1]

        # support single version for now
        if client_ver not in [RFB_33, RFB_37, RFB_38]:
            raise UnsupportedVersion()

        self._send_security(client_ver)

    def _send_security(self, client_ver):
        print("send security")
        if client_ver == RFB_33:
            self.transport.write(b"\x00\x00\x00\x02")  # specify VNC auth using 4 bytes
            self._send_auth()
        else:
            self.transport.write(b"\x01\x02")  # VNC authentication
            self.state = SECURITY_SEND

    def _recv_security(self, data=None):
        print("got security")
        if len(data) != 1 and data != "\x02":
            raise ProtocolError()
        self._send_auth()

    def _send_auth(
        self,
    ):
        print("send auth")
        self.challenge = os.urandom(16)
        self.transport.write(self.challenge)
        self.state = AUTH_SEND

    def _recv_auth(self, data=None):
        print("got auth")
        if len(data) != 16:
            raise ProtocolError()

        logdata = {
            "VNC Server Challenge": self.challenge.hex(),
            "VNC Client Response": data.hex(),
        }

        used_password = self._try_decrypt_response(response=data)
        if used_password:
            logdata["VNC Password"] = used_password
        else:
            logdata["VNC Password"] = "<Password was not in the common list>"
        self.factory.log(logdata, transport=self.transport)
        self._send_auth_failed()

    def connectionMade(self):
        if self.state != PRE_INIT:
            raise ProtocolError()
        self._send_handshake()

    def _send_auth_failed(
        self,
    ):
        self.transport.write(
            b"\x00\x00\x00\x01"
            + b"\x00\x00\x00\x16"  # response code
            + b"Authentication failure"  # message length
        )  # Message
        self.state = AUTH_OVER
        raise ProtocolError()

    def _try_decrypt_response(self, response=None):
        # attempt to decrypt each of the common passwords
        # really inefficient, but it means we don't have to rely on
        # a static challenge
        for password in COMMON_PASSWORDS:
            pw = password[:8]  # vnc passwords are max 8 chars
            if len(pw) < 8:
                pw += "\x00" * (8 - len(pw))

            pw = pw.encode("ascii")
            # VNC use of DES requires password bits to be mirrored
            values = bytearray()
            for x in pw:
                values.append(int("{:08b}".format(x)[::-1], 2))
            desbox = des(values)

            decrypted_challenge = desbox.decrypt(response)
            if decrypted_challenge == self.challenge:
                return password
        return None

    def dataReceived(self, data):
        """
        Received data is unbuffered so we buffer it for telnet.
        """
        try:
            if self.state == HANDSHAKE_SEND:
                self._recv_handshake(data=data)
            elif self.state == SECURITY_SEND:
                self._recv_security(data=data)
            elif self.state == AUTH_SEND:
                self._recv_auth(data=data)
        except (UnsupportedVersion, ProtocolError):
            self.transport.loseConnection()
            return


class CanaryVNC(Factory, CanaryService):
    NAME = "VNC"
    protocol = VNCProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config, logger)
        self.port = config.getVal("vnc.port", 5900)
        self.logtype = logger.LOG_VNC


CanaryServiceFactory = CanaryVNC
