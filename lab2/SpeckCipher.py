import os  # необходим для доступа к файловой системе
import secrets  # необходим для генерации рандомных чисел
from sys import argv
import time
import os.path


class SpeckCipher:
    BLOCK_SIZE = 64
    KEY_SIZE = 128
    ROUNDS = 27
    WORD_SIZE_N = 32
    KEY_WORDS_M = 4

    def encryptFile(self, fileName, key):
        cipherText = [0, 0]
        plainText = [0, 0]
        # получаем round ключ из ключа
        roundKey = self.keySchedule(self.bytesToWord32(key))
        # создаём и сохраняем IV (вектор инициализации)
        intVect = [0, 0]
        intVect[0] = self.IV()
        intVect[1] = self.IV()
        dataBytes = self.word32ToBytes(intVect)
        # открываем файл для зашифрованного текста
        fileOutput = open(fileName + '.enc', "wb")
        # записывам в него IV
        fileOutput.write(bytearray(dataBytes))
        # oткрываем файл исходного текста
        fileSize = os.path.getsize(fileName)
        fileInput = open(fileName, "rb")
        blockSize = 8
        padding = -1
        # читаем блоки по 8 бит
        for i in range(0, fileSize, blockSize):
            block = fileInput.read(blockSize)
            endIndex = i + blockSize
            endIndex = fileSize if endIndex > fileSize else endIndex
            # проверяем необходимы ли заполняющие биты
            if len(block) < blockSize:
                padding = blockSize - (endIndex % blockSize)
                if padding != blockSize:
                    blck = self.padding(block, blockSize, pad=padding)
                    block = [ord(x) for x in blck]
            # зашифровываем блок и записываем его в файл
            block_list = list(block)
            plainText = self.bytesToWord32(block_list)
            cipherText = self.encrypt(plainText, roundKey, intVect)
            encBlock = self.word32ToBytes(cipherText)
            fileOutput.write(bytearray(encBlock))
        # если длина дополнения = 8, то добавляем ещё один блок
        if padding == blockSize:
            block = [8] * blockSize
            plainText = self.bytesToWord32(block)
            cipherText = self.encrypt(plainText, roundKey, intVect)
            encBlock = self.word32ToBytes(cipherText)
            fileOutput.write(bytearray(encBlock))
        # закрываем файлы
        fileOutput.flush()
        fileOutput.close()
        fileInput.close()

    def decryptFile(self, fileName, key):
        cipherText = [0, 0]
        plainText = [0, 0]
        # получаем round ключ из ключа
        roundKey = self.keySchedule(self.bytesToWord32(key))
        # открываем файл для дешифрованного текста
        fileOutput = open(fileName + '.dec', "wb")
        # открываем файл с зашифрованным текстом
        fileSize = os.path.getsize(fileName + '.enc')
        fileInput = open(fileName + '.enc', "rb")
        blockSize = 8
        # создаём и сохраняем IV (вектор инициализации)
        intVect = [0, 0]
        for i in range(0, fileSize, blockSize):
            endIndex = i + blockSize
            endIndex = fileSize if endIndex > fileSize else endIndex
            block = list(fileInput.read(blockSize))
            if i == 0:
                # первый блок содержит вектор инициализации
                intVect = self.bytesToWord32(block)
            else:
                # остальные блоки содержат зашифрованный текст
                cipherText = self.bytesToWord32(block)
                plainText = self.decrypt(cipherText, roundKey, intVect)
                decBlock = self.word32ToBytes(plainText)
                # ...за исключением последнего, который дополнен значениями до длины блока
                if endIndex == fileSize:
                    # получаем длину отступа
                    a = decBlock[7]
                    # удаляем дополнительные биты
                    while a > 0:
                        decBlock.pop()
                        a -= 1
                # записываем в файл
                fileOutput.write(bytearray(decBlock))
        #закрываем файлы
        fileOutput.flush()
        fileOutput.close()
        fileInput.close()

    # 32-разрядная функция поворота влево
    def Rol(self, x, r):
        tmp = (x >> (self.WORD_SIZE_N - r)) & 0x00000000ffffffff
        return ((x << r) | tmp) & 0x00000000ffffffff

    # 32-разрядная функция поворота вправо
    def Ror(self, x, r):
        tmp = (x << (self.WORD_SIZE_N - r)) & 0x00000000ffffffff
        return ((x >> r) | tmp) & 0x00000000ffffffff

    # вектор инициализации: возвращаем 32 битное число
    def IV(self):
        return secrets.randbits(32)

    # преобразует блоки по 4 байта в 32-битные слова, используя little-endian порядок:
    # первый байт в самые правые 8 бит и так далее до самых левых 8 бит
    def bytesToWord32(self, inBytes):
        lenght = len(inBytes)
        outWords = [0] * (lenght // 4)
        j = 0
        for i in range(0, lenght, 4):
            outWords[j] = inBytes[i] | (inBytes[i + 1] << 8) | (inBytes[i + 2] << 16) | (inBytes[i + 3] << 24)
            j += 1
        return outWords

    # преобразует 32-битное слово в 4 байта, используя порядок little-endian:
    def word32ToBytes(self, inWords):
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

    # планировщик ключей: получает ключ и подготавливает буфер round ключей
    def keySchedule(self, key):
        subKey = [0] * self.ROUNDS
        key = key
        A, B, C, D = key[0], key[1], key[2], key[3]

        for i in range(0, self.ROUNDS, 3):
            subKey[i] = A
            B = self.Ror(B, 8)
            B = (B + A) & 0x00000000ffffffff
            B ^= i
            A = self.Rol(A, 3)
            A ^= B

            subKey[i + 1] = A
            C = self.Ror(C, 8)
            C = (C + A) & 0x00000000ffffffff
            C ^= (i + 1)
            A = self.Rol(A, 3)
            A ^= C

            subKey[i + 2] = A
            D = self.Ror(D, 8)
            D = (D + A) & 0x00000000ffffffff
            D ^= (i + 2)
            A = self.Rol(A, 3)
            A ^= D
        return subKey

    # зашифрует блок, используя round ключ и IV, и вернет зашифрованный блок
    def encrypt(self, plainText, roundKey, intVect):
        cipherText = plainText  # [0, 0]
        plainText = plainText
        for i in range(0, self.ROUNDS):
            intVect[1] = self.Ror(intVect[1], 8)
            intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff
            intVect[1] ^= roundKey[i]
            intVect[0] = self.Rol(intVect[0], 3)
            intVect[0] ^= intVect[1]
        cipherText[0] = plainText[0] ^ intVect[0]
        cipherText[1] = plainText[1] ^ intVect[1]
        return cipherText

    # расшифрует блок, используя round ключ и IV, и вернет расшифрованный блок
    def decrypt(self, cipherText, roundKey, intVect):
        plainText = cipherText  # [0, 0]
        cipherText = cipherText
        for i in range(0, self.ROUNDS):
            intVect[1] = self.Ror(intVect[1], 8)
            intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff
            intVect[1] ^= roundKey[i]
            intVect[0] = self.Rol(intVect[0], 3)
            intVect[0] ^= intVect[1]
        plainText[0] = cipherText[0] ^ intVect[0]
        plainText[1] = cipherText[1] ^ intVect[1]
        return plainText

    # заполнение строки дополнительными значениями до заданной длины
    def padding(self, txt, lng, pad=0, truncate=False):
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


FILENAME = "sample.txt"

# создание экземпляра класса
speck = SpeckCipher()



def main(arguments):
    # запрашиваем ключ
    tmpKey = input('Enter key (16 chars, no spaces): ')
    tmpKey.replace(' ', '')
    if tmpKey == '':
        return
    # дополняем ключ до 16 байт
    key = speck.padding(tmpKey, 16, truncate=True)
    keyLst = list(key)
    keyList = [ord(x) for x in keyLst]

    # запрашиваем файл для зашифрования
    tmpFile = input('File to be encrypted (return = sample file): ')
    if tmpFile == '':
        # если файл не задан, то берём дефолтный
        tmpFile = FILENAME
        if not os.path.isfile(tmpFile):
            # если файл не создан, создаём
            f = open(tmpFile, "w")
            f.write("Sample text")
            f.flush()
            f.close()
            print('Sample file not found - created')
    # проверяем если заданный файл существует
    if not os.path.exists(tmpFile):
        print('{} doesn\'t exist.'.format(tmpFile))
        return
    # проверяем за заданный файл валидный
    if not os.path.isfile(tmpFile):
        print('{} isn\'t a valide file.'.format(tmpFile))
        return

    print(f'Encrypting {tmpFile}...')
    time1 = time.time()
    speck.encryptFile(tmpFile, keyList)
    time2 = time.time()
    print('File encrypted. Time elapsed: {}'.format(time2 - time1))

    print('Now decrypting...')
    time1 = time.time()
    speck.decryptFile(tmpFile, keyList)
    time2 = time.time()
    print('File decrypted. Time elapsed: {}'.format(time2 - time1))


if __name__ == "__main__":
    main(argv)
