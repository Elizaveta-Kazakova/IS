import secrets

BLOCK_SIZE = 64
KEY_SIZE = 128
ROUNDS = 27
WORD_SIZE_N = 32
KEY_WORDS_M = 4


# 32-разрядная функция поворота влево
def Rol(x, r):
    tmp = (x >> (WORD_SIZE_N - r)) & 0x00000000ffffffff
    return ((x << r) | tmp) & 0x00000000ffffffff


# 32-разрядная функция поворота вправо
def Ror(x, r):
    tmp = (x << (WORD_SIZE_N - r)) & 0x00000000ffffffff
    return ((x >> r) | tmp) & 0x00000000ffffffff


# планировщик ключей: получает ключ и подготавливает буфер round ключей
def keySchedule(key):
    subKey = [0] * ROUNDS
    key = key
    A, B, C, D = key[0], key[1], key[2], key[3]

    for i in range(0, ROUNDS, 3):
        subKey[i] = A
        B = Ror(B, 8)
        B = (B + A) & 0x00000000ffffffff
        B ^= i
        A = Rol(A, 3)
        A ^= B

        subKey[i + 1] = A
        C = Ror(C, 8)
        C = (C + A) & 0x00000000ffffffff
        C ^= (i + 1)
        A = Rol(A, 3)
        A ^= C

        subKey[i + 2] = A
        D = Ror(D, 8)
        D = (D + A) & 0x00000000ffffffff
        D ^= (i + 2)
        A = Rol(A, 3)
        A ^= D
    return subKey


def bytesToWord32(inBytes):
    lenght = len(inBytes)
    outWords = [0] * (lenght // 4)
    j = 0
    for i in range(0, lenght, 4):
        outWords[j] = inBytes[i] | (inBytes[i + 1] << 8) | (inBytes[i + 2] << 16) | (inBytes[i + 3] << 24)
        j += 1
    return outWords

    # преобразует 32-битное слово в 4 байта, используя порядок little-endian:


def word32ToBytes(inWords):
    lenght = len(inWords)
    outBytes = [0] * (lenght * 4)
    j = 0
    for i in range(0, lenght):
        outBytes[j] = inWords[i] & 0xff
        outBytes[j + 1] = (inWords[i] >> 8) & 0xff
        outBytes[j + 2] = (inWords[i] >> 16) & 0xff
        outBytes[j + 3] = (inWords[i] >> 24) & 0xff
        j += 4
    return outBytes


def IV():
    return secrets.randbits(32)


# заполнение строки дополнительными значениями до заданной длины
def padding(txt, lng, pad=0, truncate=False):
    text = str(txt)
    # если это массив байтов, удаляем ненужные символы
    if text.find("b'") != -1:
        text = text[2:-1]
    pad = pad
    # требуется ли усечение?
    if truncate:
        if len(text) % lng == 0:
            # длина равна запрашиваемой: возвращает заданную строку
            return text
        else:
            # Возвращает выровненную строку
            return text.ljust(len(text) + lng - (len(text) % lng))
    # проверяем, заполнена ли строка
    if len(text) == lng:
        # возвращаем строку
        return text
    elif len(text) > lng:
        return text[:lng]
    else:
        # Возвращает выровненную строку
        return text.ljust(len(text) + lng - (len(text) % lng), chr(pad))


def encryptBlock(plainText, roundKey, intVect):
    cipherText = plainText  # [0, 0]
    plainText = plainText
    for i in range(0, ROUNDS):
        intVect[1] = Ror(intVect[1], 8)
        intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff
        intVect[1] ^= roundKey[i]
        intVect[0] = Rol(intVect[0], 3)
        intVect[0] ^= intVect[1]
    cipherText[0] = plainText[0] ^ intVect[0]
    cipherText[1] = plainText[1] ^ intVect[1]
    return cipherText


def hashFunction(text, key):
    cipherText = [0, 0]
    plainText = [0, 0]
    # получаем round ключ из ключа
    roundKey = keySchedule(bytesToWord32(key))
    # создаём и сохраняем IV (вектор инициализации)
    intVect = [0, 0]
    intVect[0] = IV()
    intVect[1] = IV()
    blockSize = 8
    _padding = -1
    encText = ""
    hash_value = 0
    # читаем блоки по 8 бит
    for i in range(0, len(text), blockSize):
        block = text[i: i + blockSize]
        endIndex = i + blockSize
        endIndex = len(text) if endIndex > len(text) else endIndex
        # проверяем необходимы ли заполняющие биты
        if len(block) < blockSize:
            _padding = blockSize - (endIndex % blockSize)
            if _padding != blockSize:
                blck = padding(block, blockSize, pad=_padding)
                block = [ord(x) for x in blck]
        # зашифровываем блок
        block_list = list(block)
        plainText = bytesToWord32(block_list)
        cipherText = encryptBlock(plainText, roundKey, intVect)
        encBlock = word32ToBytes(cipherText)
        # Добавление блока данных к хешу с использованием Speck-шифра
        block_hash = int.from_bytes(block, byteorder='big')
        hash_value ^= block_hash
        hash_value ^= int.from_bytes(encBlock, byteorder='big')
    # если длина дополнения = 8, то добавляем ещё один блок
    if _padding == blockSize:
        block = [8] * blockSize
        plainText = bytesToWord32(block)
        cipherText = encryptBlock(plainText, roundKey, intVect)
        encBlock = word32ToBytes(cipherText)
        # Добавление блока данных к хешу с использованием Speck-шифра
        block_hash = int.from_bytes(block, byteorder='big')
        hash_value ^= block_hash
        hash_value ^= int.from_bytes(encBlock, byteorder='big')
    return hash_value


if __name__ == "__main__":
    key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'  # 128-битный ключ
    data = input("Введите строку для шифрования: ").encode()

    hash_result = hashFunction(data, key)
    print(f'Hash result: {hash_result}')
