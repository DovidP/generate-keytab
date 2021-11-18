import struct
from time import time
from dataclasses import astuple, dataclass
import argparse
import sys

def data_bytes(data):
    return struct.pack(f'>h{len(data)}s', len(data), bytes(data, 'ascii'))

@dataclass
class Principal:
    count_of_components: int = 1
    realm: bytes = None
    component: bytes = None
    name_type: int = 1

    def packed(self):
        return struct.pack(f'>h{len(self.realm)}s{len(self.component)}sl', *astuple(self))


@dataclass
class Entry:
    principal: bytes = None
    timestamp: int = int(time())
    key_version1: int = 1
    enctype: int = None
    key_length: int = None
    key_contents: bytes = None
    key_version2: int = 1

    def packed(self):
        packed_entry = struct.pack(f'>{len(self.principal)}sibhh{self.key_length}sl', *astuple(self))
        return struct.pack('>l{}s'.format(len(packed_entry)), len(packed_entry), packed_entry)


etypes = {
    'des-cbc-crc': 1,
    'des-cbc-md4': 2,
    'des-cbc-md5': 3,
    'des3-cbc-md5': 5,
    'des3-cbc-sha1': 7,
    'dsaWithSHA1-CmsOID': 9,
    'md5WithRSAEncryption-CmsOID': 10,
    'sha1WithRSAEncryption-CmsOID': 11,
    'rc2CBC-EnvOID': 12,
    'rsaEncryption-EnvOID': 13,
    'rsaES-OAEP-ENV-OID': 14,
    'des-ede3-cbc-Env-OID': 15,
    'des3-cbc-sha1-kd': 16,
    'aes128-cts-hmac-sha1-96': 17,
    'aes256-cts-hmac-sha1-96': 18,
    'aes128-cts-hmac-sha256-128': 19,
    'aes256-cts-hmac-sha384-192': 20,
    'rc4-hmac': 23,
    'rc4-hmac-exp': 24,
    'camellia128-cts-cmac': 25,
    'camellia256-cts-cmac': 26
}




def write_entry(user, enctype, key, realm, wfile):
    try:
        etype = etypes[enctype]
    except KeyError:
        print('etype not supported')
        return

    key = bytes.fromhex(key)

    principal = Principal(realm = data_bytes(realm), component = data_bytes(user))

    entry = Entry()
    entry.principal = principal.packed()
    entry.enctype = etype
    entry.key_length = len(key)
    entry.key_contents = key

    with open(wfile, 'ab') as f:
        f.write(entry.packed())

def initfile(wfile):
    version = b'\x05\x02'
    with open(wfile, 'wb') as f:
        f.write(version)

def main():

    parser = argparse.ArgumentParser(description="Create a keytab file")
    parser.add_argument("-infile", help="The .kerberos file from impacket/examples/secretsdump.py to parse", required=True)
    parser.add_argument("-outfile", help="The outfile if append is specified, this is the file to append to", required=True)
    parser.add_argument("-realm", help= "The realm for the keytab entries "
                                        "(if the user string in the infile contains the realm this will be ignored)", required=True)
    parser.add_argument("-append", action='store_true', default=False, help="Append to an existing keytab instead of overwriting it", required=True)
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile

    if not args.append:
        initfile(outfile)

    with open(infile, 'r') as f:
        for line in f.readlines():
            user, enctype, key = line.split(":")
            if '\\' in user:
                realm, user = user.split('\\')
            
            write_entry(user, enctype, key, realm, outfile)

if __name__ == '__main__':
    main()