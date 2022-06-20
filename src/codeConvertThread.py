from PyQt5.QtCore import Qt, pyqtSignal, QThread
import base64,html,binascii,hashlib
from urllib import parse

class CodeConvert(QThread):

    def __init__(self, coding, inputCoding, optionLeft1, optionLeft2, outputCoding, optionRight1, optionRight2, text, coding21):
        super(CodeConvert, self).__init__()
        self.coding = coding
        self.inputCoding =inputCoding
        self.optionLeft1 = optionLeft1
        self.optionLeft2 = optionLeft2
        self.outputCoding = outputCoding
        self.optionRight1 = optionRight1
        self.optionRight2 = optionRight2
        self.text = text
        self.coding21 = coding21
        self.coding24 = ["Bash", "Powershell", "Python", "Perl"]
        # self.coding21 = [["aDefault", "Ascii", "Base64", "Html", "Reverse", "Unicode", "UnicodeBase64", "Url"],
        #                 ["JavaRuntimeExec", "Normal"],
        #                 ["MD5_32", "MD5_16", "SHA256"],
        #                 ["16", "10", "8", "2"]]

    updateSignal = pyqtSignal(str)
    updateSignal2 = pyqtSignal(str, str)

    def run(self):
        if self.outputCoding == self.coding21[0][0]:    # 输出编码为 aDefault
            result = self.toDefault()
        elif self.outputCoding == self.coding21[0][1]:  # 输出编码 Ascii
            result = self.toAscii()
        elif self.outputCoding == self.coding21[0][2]:  # 输出编码 base64
            result = self.toBase64()
        elif self.outputCoding == self.coding21[0][3]:  # 输出编码 html
            result = self.toHtml()
        # elif self.outputCoding == self.coding21[0][4]:  # 输出编码 mdb
        #     pass
        elif self.outputCoding == self.coding21[0][4]:  # 输出编码 reverse
            result = self.toReverse()
        elif self.outputCoding == self.coding21[0][5]:  # 输出编码 unicode
            result = self.toUnicode()
        elif self.outputCoding == self.coding21[0][6]:  # 输出编码 unicodeBase64
            result = self.toUnicodeBase64()
        elif self.outputCoding == self.coding21[0][7]:  # 输出编码 url
            result = self.toUrl()
        elif self.outputCoding == self.coding21[1][0]:  # 输出编码 javaruntimeexec
            result = self.toJavaRuntimeExec()
        elif self.outputCoding == self.coding21[1][1]:  # 输出编码 normal
            result = self.toCmdNormal()
        elif self.outputCoding == self.coding21[2][0]:  # 输出编码 md5_32
            result = self.toMd5_32()
        elif self.outputCoding == self.coding21[2][1]:  # 输出编码 md5_16
            result = self.toMd5_16()
        elif self.outputCoding == self.coding21[2][2]:  # 输出编码 sha256
            result = self.toSha256()
        # elif self.outputCoding == self.coding21[2][3]:  # 输出编码 xorb64
        #     result = self.toXorB64()
        elif self.inputCoding and self.outputCoding in self.coding21[3]:  # 进制转换
            result = self.binHexOct()
        self.updateSignal.emit(result)

    def toDefault(self):
        try:
            message = ''
            if self.inputCoding == self.coding21[0][0]:  # 输入编码 adefault
                message = self.text
            elif self.inputCoding == self.coding21[0][1]:    # 输入编码 Ascii  ord()得到ascii码，chr()得到字符
                if self.optionLeft2:
                    t = (self.text.strip("\n")).split(self.optionLeft2)
                else:
                    t = self.text.strip("\n").split(",")
                s = ""
                if self.optionLeft1 == "16":
                    for i in t:
                        s+=chr(int(i.upper(), 16))
                if self.optionLeft1 == "10":
                    for i in t:
                        s+=chr(int(i))
                if self.optionLeft1 == "8":
                    for i in t:
                        s+=chr(int(i, 8))
                if self.optionLeft1 == "2":
                    for i in t:
                        s+=chr(int(i, 2))
                return s
            elif self.inputCoding == self.coding21[0][2]:    # 输入编码 base64
                message = base64.b64decode(self.text).decode(self.coding)
            elif self.inputCoding == self.coding21[0][3]:    # 输入编码 html
                message = html.unescape(self.text)
            # elif self.inputCoding == self.coding21[0][4]:    # 输入编码 mdb
            #     pass
            elif self.inputCoding == self.coding21[0][4]:    # 输入编码 reverse
                message = (self.text)[::-1]
            elif self.inputCoding == self.coding21[0][5]:    # 输入编码 unicode
                message = (self.text).encode(self.coding).decode("unicode_escape")
            # UnicodeBase64表示先unicode编码再进行base64编码，这个base64编码主要用在powershell命
            # 令编码上，因为powershell字符集默认使用unicode编码。
            elif self.inputCoding == self.coding21[0][6]:    # 输入编码 unicodebase64
                message = base64.b64decode(self.text).decode(self.coding)
                message = message.encode(self.coding).decode("unicode_escape")
            elif self.inputCoding == self.coding21[0][7]:    # 输入编码 url
                message = parse.unquote(self.text)
            elif self.inputCoding == self.coding21[1][0]:    # 输入编码 JavaRuntimeExec
                message = self.text
            elif self.inputCoding == self.coding21[1][1]:    # 输入编码 Normal
                message = self.text
            else:
                message = self.text
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toAscii(self):
        try:
            message = binascii.b2a_hex((self.toDefault()).encode(self.coding)).decode(self.coding)
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                a = "<img src=1 onerrorr=alert(1)>"
                return str(message)

    def toBase64(self):
        try:
            message = base64.b64encode((self.toDefault()).encode(self.coding)).decode(self.coding)
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return message

    def toHtml(self):
        try:
            message = html.escape(self.toDefault())
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toReverse(self):
        try:
            message = (self.toDefault())[::-1]
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toUnicode(self):
        try:
            message = ''
            s = self.toDefault()
            for i in list(s):
                message+= r"\u%04x" % ord(i)
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toUnicodeBase64(self):
        try:
            message = ''
            s = self.toDefault()
            for i in list(s):
                # message+= r"\u%04x" % ord(i)
                message+= i + "\x00"
            message = base64.b64encode(message.encode(self.coding)).decode(self.coding)
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toUrl(self):
        try:
            message = parse.urlencode(self.toDefault())
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toJavaRuntimeExec(self):
        try:
            message = (self.toDefault()).encode(self.coding)
            if self.optionRight1 == self.coding24[0]:   # bash
                message = 'bash -c {echo,'+ base64.b64encode(message).decode(self.coding) + '}|{base64,-d}|{bash,-i}'
            elif self.optionRight1 == self.coding24[1]: # powershell
                message = 'powershell.exe -noni -w hidden -nop -ep b -e {}'.format(self.toUnicodeBase64())
            elif self.optionRight1 == self.coding24[2]: # python
                message = "python -c exec('{}'.decode('base64'))".format(base64.b64encode(message).decode(self.coding))
            elif self.optionRight1 == self.coding24[3]: # perl
                message = "perl -MMIME::Base64 -e eval(decode_base64('{}'))".format(base64.b64encode(message).decode(self.coding))
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toCmdNormal(self):
        try:
            message = (self.toDefault()).encode(self.coding)
            if self.optionRight1 == self.coding24[0]:   # bash
                message = 'bash -c "{echo,'+ base64.b64encode(message).decode(self.coding) + '}|{base64,-d}|{bash,-i}"'
            elif self.optionRight1 == self.coding24[1]: # powershell
                message = 'powershell.exe -noni -w hidden -nop -ep b -e {}'.format(self.toUnicodeBase64())
            elif self.optionRight1 == self.coding24[2]: # python
                message = "python -c {}exec('{}'.decode('base64')){}".format('"', base64.b64encode(message).decode(self.coding), '"')
            elif self.optionRight1 == self.coding24[3]: # perl
                message = "perl -MMIME::Base64 -e {}eval(decode_base64('{}')){}".format('"', base64.b64encode(message).decode(self.coding), '"')
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toMd5_32(self):
        try:
            s = (self.text).strip()
            md5 = hashlib.md5()
            md5.update(s.encode(self.coding))
            newmd5 = md5.hexdigest()
            message = newmd5
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toMd5_16(self):
        try:
            s = (self.text).strip()
            md5 = hashlib.md5()
            md5.update(s.encode(self.coding))
            newmd5 = md5.hexdigest()
            message = newmd5[8:-8]
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def toSha256(self):
        try:
            s = (self.text).strip()
            sha256 = hashlib.sha256()
            sha256.update(s.encode(self.coding))
            message = sha256.hexdigest()
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def binHexOct(self):
        try:
            message = ''
            if self.inputCoding == "16":
                n = int(self.text.upper(), 16)  # 先把十六进制转换成十进制
                if self.outputCoding == "16":
                    return hex(n)
                if self.outputCoding == "10":
                    return str(n)
                if self.outputCoding == "8":
                    return oct(n)
                if self.outputCoding == "2":
                    return bin(n)
            elif self.inputCoding == "10":  # hex() oct() bin()
                if self.outputCoding == "16":
                    return hex(int(self.text))
                if self.outputCoding == "10":
                    return str(int(self.text))
                if self.outputCoding == "8":
                    return oct(int(self.text))
                if self.outputCoding == "2":
                    return bin(int(self.text))
            elif self.inputCoding == "8":  # 把八进制转换成十进制
                n = int(self.text, 8)
                if self.outputCoding == "16":
                    return hex(n)
                if self.outputCoding == "10":
                    return str(n)
                if self.outputCoding == "8":
                    return oct(n)
                if self.outputCoding == "2":
                    return bin(n)
            elif self.inputCoding == "2":  # 把二进制转换成十进制
                n = int(self.text, 2)
                if self.outputCoding == "16":
                    return hex(n)
                if self.outputCoding == "10":
                    return str(n)
                if self.outputCoding == "8":
                    return oct(n)
                if self.outputCoding == "2":
                    return bin(n)
            else:
                pass
        except Exception as e:
            print(e)
            message = e
        finally:
            if message:
                return str(message)

    def saveResult(self, text, saveDirPath):
        try:
            print(text)
            resultFile = open(saveDirPath, "a+", encoding="utf-8")
            resultFile.write(text)
            self.updateSignal2.emit("结果已保存至：{}，是否打开目录？".format(saveDirPath), saveDirPath)
            resultFile.close()
        except Exception as e:
            print(e)

    def stop(self):
        self.is__running = False
        self.terminate()
