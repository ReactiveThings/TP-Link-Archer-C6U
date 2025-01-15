from base64 import b64decode, b64encode
from binascii import b2a_hex
import json
from urllib.parse import unquote
from Crypto import Random
import re
from requests import post, get
import urllib
from tplinkrouterc6u.common.package_enum import Connection
from tplinkrouterc6u.common.dataclass import Device, Firmware, Status
from tplinkrouterc6u.common.exception import ClientException
from tplinkrouterc6u.client_abstract import AbstractRouter
from tplinkrouterc6u.common.encryption import EncodeHelper, EncryptionWrapper
from tplinkrouterc6u.common.helper import get_mac, get_ip

class TplinkC6V4Router(AbstractRouter):
    def supports(self) -> bool:
        firmware = None
        try:
            firmware = self.get_firmware()
        except BaseException:
            return False

        return firmware and firmware.model == "Archer C6 4.0"
    
    def post(self, code, asyn, data = None, id = None, skipEncryption = False) -> str:

        if id and data and not skipEncryption:
            encrypted = self._encryptor.data_encrypt(data)
            data = "sign=" + encrypted['sign'] + "\r\ndata=" + encrypted['data']
        params = {}
        
        if code:
            params['code'] = code
        if asyn:
            params['asyn'] = asyn
        if id:
            params['id'] = id

        response = post(
            self.host,
            params=params,
            data=data,
            timeout=self.timeout,
            verify=self._verify_ssl,
            headers= {'Referer': 'http://192.168.1.111/'},
        )

        result = response.text

        if id and not skipEncryption:
            result = self._encryptor.data_decrypt(result)
        
        result = TplinkC6V4Router.error_and_data_split(result)['data'].split("\r\n")
        return result


    def authorize(self) -> None:
        get(self.host)
        self.post(16,0,"enable")
        auth_info = self.post(7,1)
        self._id = str(EncodeHelper.security_encode(auth_info[2], EncodeHelper.encode_password(self.password), auth_info[3]))
        data = self.post(16,0,"get")

        secrets = {
            "ee": data[0],
            "nn": data[1],
            "seq": data[2]
        }

        self._encryptor = C6V4Encryptor(secrets['nn'], secrets['ee'], secrets['seq'])
        self.post(16,0,'set '+ self._encryptor.get_encoded_aes_key(),self._id, True)

    

    def logout(self) -> None:
        self.post(11,0,"", self._id)
        #raise ClientException('Not Implemented')

    def get_firmware(self) -> Firmware:
        results = self.post(2,1,"0|1,0,0")
        results = self._parse(results)
        return Firmware(results["hardVer"], results["modelName"] + " " + results["modelVer"], results["softVer"])

    def get_status(self) -> Status:
        info = self.post(2,1,"1|1,0,0", self._id)
        info = self._parse(info)

        results = self.post(2,1,"13|1,0,0", self._id)
        results = self._parse(results)

        print(info)
        status = Status()
        status._lan_macaddr = info["mac"]["0"]
        devices = {}

        keys = ["mac","ip","aveRssi","name","txRate","rxRate", "online", "type"]
        for k in keys:
            for r in results[k]:
                if r not in devices:
                    devices[r] = {}
                devices[r][k] = results[k][r]

        for d in devices:
            if devices[d]["ip"] != "0.0.0.0" and devices[d]["online"] == "1":
                dd = Device(Connection.HOST_2G if devices[d]["type"] == "1" else Connection.WIRED , get_mac(devices[d]["mac"]), get_ip(devices[d]["ip"]), devices[d]["name"])
                dd.signal = devices[d]["aveRssi"]
                dd.up_speed = devices[d]["txRate"]
                dd.down_speed = devices[d]["rxRate"]
                status.devices.append(dd)

        return status

    def reboot(self) -> None:
        self.post(6,1,"", self._id)

    def set_wifi(self, wifi: Connection, enable: bool) -> None:
        print("set wifi")
        #raise ClientException('Not Implemented')
    
    
    def _parse(self, results):
        result = {}

        # Process each line of input
        for line in results:
            parts = line.split(' ')
            self._add_to_nested_dict(result, parts[:-1], parts[-1])
        return result

    def _add_to_nested_dict(self, data, keys, value):
        if len(keys) == 0:
            return

        # Base case: if there's only one key left, assign the value
        if len(keys) == 1:
            data[keys[0]] = unquote(value)
            return

        # Recursive case: work on the first key and recurse on the rest
        if keys[0] not in data:
            data[keys[0]] = {}
        self._add_to_nested_dict(data[keys[0]], keys[1:], value)

    @staticmethod
    def error_and_data_split(t):
        try:
            s = 0
            e = re.search(r'\r|\n', t)
            if e:
                e = e.start()
                i = t[:e]
            else:
                i = t

            if re.search(r'\D', i) or len(i) == 0:
                i = None
                r = t
            else:
                n = len(i) - 1
                while s < n and i[s] == "0":
                    s += 1
                i = int(i[s:])
                if re.search(r'\r\n', t):
                    r = t[e + 2:]
                else:
                    r = t[e + 1:]

            return {
                "errorCode": i,
                "data": r
            }
        except Exception:
            return {
                "errorCode": None,
                "data": t
            }

class C6V4Encryptor:
    def __init__(self,nn,ee,seq):
        self.nn = nn
        self.ee = ee
        self.seq = int(seq)
        self.AESKey = EncryptionWrapper()
        

    def get_signature(self, t):
        r = f"{self.get_key()}&s={t}"
        e = ""
        n = 0
        while n < len(r):
            e += self.encrypt(r[n:n+53])
            n += 53
        return e

    def data_encrypt(self, t, r=None):
        return {
            "sign": self.get_signature(self.seq + len(t)),
            "data": self.AESKey.aes_encrypt(t)
        }

    def data_decrypt(self, t):
        return self.AESKey.aes_decrypt(t)

    def get_encoded_aes_key(self):
        return self.encrypt(self.AESKey._get_aes_string())
    
    def get_key(self):
        return f"nn={self.nn}&ee={self.ee}"

    def encrypt(self, t):
        return EncryptionWrapper.rsa_encrypt(t, self.nn, self.ee)
    