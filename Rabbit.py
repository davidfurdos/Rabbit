WORDSIZE = 0x100000000

class Rabbit:
    
    def __init__(self, K, iv=None):
        if len(K) != 16:
            raise ValueError("Key must be 128 bits (16 bytes) long")
        if iv is not None and len(iv) != 8:
            raise ValueError("IV must be 64 bits (8 bytes) long")

        self.b = 0
        self.K = K
        self.iv = iv
        
        subkeys = []       
        key = int.from_bytes(K, byteorder='big')
        for i in range(0, 128, 16):
            subkeys.append((key >> i) & 0xFFFF)
            
        self.X = []
        for i in range(8):
            if i & 1 == 0:
                value = (subkeys[(i + 1) % 8] << 16) | subkeys[i]
            else:
                value = (subkeys[(i + 5) % 8] << 16) | subkeys[(i + 4) % 8]
            self.X.append(value)

        self.C = []
        for i in range(8):
            if i & 1 == 0:
                value = (subkeys[(i + 4) % 8] << 16) | subkeys[(i + 5) % 8]
            else:
                value = (subkeys[i] << 16) | subkeys[(i + 1) % 8]
            self.C.append(value)

        for i in range(4):
            self.next_state()
            
        for i in range(8):
            self.C[i] = self.C[i] ^ self.X[(i + 4) % 8]

        
        if iv is not None:
            self.re_initialize(iv)
    
    def re_initialize(self, old_iv):
        iv = [0] * 4
        for i in range(4):
            iv[3 - i] = (old_iv[2 * i] << 8) | (old_iv[2 * i + 1])
            
        for i in range(8):
            if i & 3 == 1:
                left_part = iv[3] << 16
            else:
                left_part = iv[(9 - i) % 4] << 16

            if i & 3 == 3:
                right_part = iv[0] & 0xFFFF
            else:
                right_part = iv[i % 4] & 0xFFFF

            self.C[i] ^= left_part | right_part

        for i in range(4):
            self.next_state()
    
    def next_state(self):
        A = [0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3]
        
        temp = self.C[0] + A[0] + self.b
        self.C[0] = temp % WORDSIZE
        
        for i in range(1, 8):
             temp = self.C[i] + A[i] + temp // WORDSIZE
             self.C[i] = temp % WORDSIZE
        self.b = temp // WORDSIZE
        
        g = []
        for j in range(8):
            g.append(self.g(self.X[j], self.C[j]))

        self.X[0] = (g[0] + self.rotate16(g[7]) + self.rotate16(g[6])) % WORDSIZE
        self.X[1] = (g[1] + self.rotate8(g[0])  + g[7]) % WORDSIZE
        self.X[2] = (g[2] + self.rotate16(g[1]) + self.rotate16(g[0])) % WORDSIZE
        self.X[3] = (g[3] + self.rotate8(g[2]) + g[1]) % WORDSIZE
        self.X[4] = (g[4] + self.rotate16(g[3]) + self.rotate16(g[2])) % WORDSIZE
        self.X[5] = (g[5] + self.rotate8(g[4])  + g[3]) % WORDSIZE
        self.X[6] = (g[6] + self.rotate16(g[5]) + self.rotate16(g[4])) % WORDSIZE
        self.X[7] = (g[7] + self.rotate8(g[6])  + g[5]) % WORDSIZE

    def g(self, u, v):
        square_uv = (((u + v) % WORDSIZE) * ((u + v) % WORDSIZE))
        return (square_uv ^ (square_uv >> 32)) % WORDSIZE
    
    def rotate8(self, x): return ((x <<  8) & 0xFFFFFFFF) | (x >> 24)
    def rotate16(self, x): return ((x << 16) & 0xFFFFFFFF) | (x >> 16)

    def keystream(self, n):
        result = []

        while len(result) < n:
            self.next_state()
            s = [0] * 16

            x = self.X[6] ^ (self.X[3] >> 16) ^ (self.X[1] << 16)
            s[0] = (x >> 24) & 0xFF
            s[1] = (x >> 16) & 0xFF
            s[2] = (x >> 8) & 0xFF
            s[3] = x & 0xFF

            x = self.X[4] ^ (self.X[1] >> 16) ^ (self.X[7] << 16)
            s[4] = (x >> 24) & 0xFF
            s[5] = (x >> 16) & 0xFF
            s[6] = (x >> 8) & 0xFF
            s[7] = x & 0xFF

            x = self.X[2] ^ (self.X[7] >> 16) ^ (self.X[5] << 16)
            s[8] = (x >> 24) & 0xFF
            s[9] = (x >> 16) & 0xFF
            s[10] = (x >> 8) & 0xFF
            s[11] = x & 0xFF

            x = self.X[0] ^ (self.X[5] >> 16) ^ (self.X[3] << 16)
            s[12] = (x >> 24) & 0xFF
            s[13] = (x >> 16) & 0xFF
            s[14] = (x >> 8) & 0xFF
            s[15] = x & 0xFF
            
            result.extend(s)

        return bytes(result[:n])
    
    def print_state(self):
        print(f"b = {self.b}")
        for i in range(8):
            print(f"X{i} = {hex(self.X[i])}, C{i} = {hex(self.C[i])}")
    
    def encrypt(self, plaintext):
        plaintext_bytes = plaintext.encode('utf-8')
        
        self.__init__(self.K, self.iv)
        keystream_bytes = self.keystream(len(plaintext_bytes))
        
        ciphertext_bytes = bytes([p ^ k for p, k in zip(plaintext_bytes, keystream_bytes)])
        
        return ciphertext_bytes.hex()

    def decrypt(self, ciphertext_hex):
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        
        self.__init__(self.K, self.iv)
        keystream_bytes = self.keystream(len(ciphertext_bytes))
        
        plaintext_bytes = bytes([c ^ k for c, k in zip(ciphertext_bytes, keystream_bytes)])
        
        return plaintext_bytes.decode('utf-8')

key = bytes.fromhex("91 28 13 29 2e 3d 36 fe 3b fc 62 f1 dc 51 c3 ac")
iv = bytes.fromhex("c3 73 f5 75 c1 26 7e 59")

rabbit = Rabbit(key, iv)

plaintext = "ciphertext"
ciphertext = rabbit.encrypt(plaintext)
print("Encrypted: " + ciphertext)

decrypted = rabbit.decrypt(ciphertext)
print("Decrypted: " + decrypted)