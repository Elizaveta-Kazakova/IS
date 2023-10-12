A = 13
B = 17
M = 65536
Y0 = 4003


def generate(y):
    generated_list = []
    for _ in range(8):
        y = (A * y + B) % M
        generated_list.append(y)
    return generated_list


def Crypt():
    generated_list = generate(Y0)
    text = str(input('Enter text to encrypt: '))
    r = ""
    for j in range(0, len(text), 8):
        temp = text[j: j + 8]
        if temp:
            for i, item in enumerate(temp):
                r = r + chr(ord(item) ^ generated_list[i])
        else:
            break
    print('encrypted text = ' + r)


Crypt()


def DeCrypt():
    gamma = generate(Y0)
    text = str(input('Enter text to decrypt: '))
    r = ""
    for j in range(0, len(text), 8):
        temp = text[j: j + 8]
        if temp:
            for i, item in enumerate(temp):
                r = r + chr(ord(item) ^ gamma[i])
        else:
            break
    print('decrypted text = ' + r)


DeCrypt()
