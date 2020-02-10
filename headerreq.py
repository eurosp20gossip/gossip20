import requests
import os
import hashlib
import datetime
import codecs
import time
import sys
import base64
from binascii import unhexlify
from utils import header_from_string, header_to_string, bytes8_to_int, hash_decode
from struct import pack, unpack, unpack_from

headers_path = '.'

def reader_header(block_height):
    global count 
    headers_filename = os.path.join(headers_path, 'blockchain_headers')
    count = 0
    h = b''
    if os.path.exists(headers_filename):
        with open(headers_filename, 'rb') as f:
            f.seek(block_height * 80)
            h = f.read(80)
            with open('header_chunk_client', 'ab+') as the_file:
                the_file.write(h)

        if len(h) == 80:
            count = count + 1
    
    h = header_from_string(h)
    return header_to_string(h)

def rev_string(s):
    i = len(s)
    rev_str = ''
    while i > 0:
        rev_str = rev_str + s[i-2:i]
        i = i - 2
    
    return rev_str

if __name__ == '__main__':
    block_height = 540020+267
    header = ''
    
    start = int(sys.argv[1])
    end = int(sys.argv[2])
    
    if os.path.exists("header_chunk_client"):
        os.remove("header_chunk_client")
    
    for i in range(start, end):
        header = header+reader_header(block_height+i)
    
    data = open("header_chunk_client", "rb").read()
    print(len(data))
    encode_header = base64.b64encode(data)
    print(len(encode_header))
    header_range = str(start)+':'+str(end)
    
    
    tests = 20
    resp_time = []
    i = 0
    total_time = 0
    
    while i < tests:
        start = time.time() * 1000
        # Starting the protocol
        headers = {'range':header_range}
        print("Range sent!!")
        response = requests.get('http://127.0.0.1:8000/', headers=headers)
        print(response.text)
        # Server Range
        print(response.headers['range'])
        print("Server Encoded Header Size:",len(response.headers['data']))
        # Sending request block headers to server.
        print("Client Encoded Header Size:",len(encode_header))
        headers = {'data':encode_header}
        response = requests.get('http://127.0.0.1:8000/body.html', headers=headers)
        print(response.text)
        end = time.time() * 1000
        resp_time.append(end - start)
        i = i + 1
        print(i)
        print("=====")

    for i in resp_time:
        total_time = total_time + i

    print(total_time/len(resp_time))