import base64,urllib,urllib.parse
#def decode():
    #string = 'mNFTiQxWSWy1BlFFazd3eshx6uXNvSnx'
    #b =  urllib.parse.unquote(string)   
    #decode = base64.b64decode(b)              
    #print(decode)
#decode()
    
def encode():
        string = '\xc8q\xea\xe5\xcd\xbd)\xf1\xb5\x06QEk7wz\x98\xd1S\x89\x0cVIl'
        b = base64.b64encode(bytes(string.encode()))
        encode = urllib.parse.quote(b)
        print(encode)
encode()
#print(len('\x98\xd1S\x89\x0cVIl'))