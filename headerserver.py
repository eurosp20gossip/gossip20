import requests
import os
import hashlib
import datetime
import base64
import sys

from flask import Flask, render_template, request, redirect, jsonify, send_file, Response
from binascii import unhexlify
from blockutils import header_from_string, header_to_string
from struct import pack, unpack, unpack_from, Struct

app = Flask(__name__)
headers_path = '.'
diff = []
count = 0
startBlockTime = 0
endBlockTime = 0
superBlockCount = 0
hashSum = 0
factor = 4
blockHash = {}
bits = {}
timestamp = {}
rec_blocks = {}
serverHeaders = {}
clientReqHeaders = ''
header_data = b''
header_range = ''
encode_header = ''

def main():
    global header_data
    global header_range
    global encode_header
   
    block_height = 540020+267    
    start = int(sys.argv[1])
    end = int(sys.argv[2])
    header = ''
    
    if os.path.exists("header_chunk_server"):
        os.remove("header_chunk_server")
        
    # reading the header chunk within that range.
    for i in range(start, end):
        header = header+read_headers_local(block_height+i)
    
    header_data = open("header_chunk_server", "rb").read()
    header_range = str(start)+":"+str(end)
    print(len(header_data))
    encode_header = base64.b64encode(header_data)
    print(len(encode_header))
    app.run(host='0.0.0.0', port=8000, debug=True)

@app.route('/')
@app.route('/index.html')
def index():
    global header_data 
    global header_range
    global encode_header
    
    # Server received 'range field in the header!!'
    resp = Response("Server Index!!")
    print("Client Range Received:",request.headers['range'])
    print("Server Encoded Header Size:",len(encode_header))
    # Modify server response header.
    resp.headers['data'] = encode_header
    resp.headers['range'] = header_range
    return resp

@app.route('/body.html', methods=['GET', 'POST'])
def body():
    # Block Range to compare
    header_data = request.headers['data']
    print("Client Encoded Header Size:",len(header_data))
    resp = Response("Server body!!")
    return resp

def read_header(block_height):
    global count 
    headers_filename = os.path.join(headers_path, 'blockchain_headers')
    if os.path.exists(headers_filename):
        with open(headers_filename, 'rb') as f:
            f.seek(block_height * 80)
            h = f.read(80)
            with open('header_chunk', 'wb+') as the_file:
                the_file.write(h)

        if len(h) == 80:
            count = count + 1
            h = header_from_string(h)
            d = int(h['bits'])
            verifyHash = getVerifyHash(h['version'], h['prev_block_hash'], h['merkle_root'], 
                    h['timestamp'], h['bits'], h['nonce'])
            return verifyHash, h['bits'], h['timestamp']

def getVerifyHash(version, prev_block, merkle_root, time, bits, nonce):
    version = pack('<I', version).encode('hex_codec')
    prev_block = unhexlify(prev_block)
    prev_block = prev_block[::-1].encode('hex_codec')
    merkle_root = unhexlify(merkle_root)
    merkle_root = merkle_root[::-1].encode('hex_codec')
    timestamp = pack('<I', time).encode('hex_codec')
    bits = pack('<I', bits).encode('hex_codec')
    nonce = pack('<I', nonce).encode('hex_codec')
    headerHex = (version + prev_block + merkle_root + timestamp + bits + nonce)
    return calHash(headerHex)

def calHash(headerHex):
    headerByte = headerHex.decode('hex')
    blockHash = hashlib.sha256(hashlib.sha256(headerByte).digest()).digest()
    blockHash.encode('hex_codec')
    blockHash = blockHash[::-1].encode('hex_codec')
    return blockHash

def bits_to_difficulty(bits):
    nShift = 0
    dDiff = 0.0
    if bits is None:
        return 0

    nShift = (bits >> 24) & 0xff
    dDiff = float(0x0000ffff)/float(bits & 0x00ffffff)

    while (nShift < 29):
        dDiff = dDiff * 256.0
        nShift = nShift + 1

    while (nShift > 29):
        dDiff = dDiff / 256.0
        nShift = nShift - 1

    return dDiff

def findCummulativeSum(blockHash, bits, factor, index, timestamp):
    global hashSum
    MAX_TARGET = int("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)
    difficulty = bits_to_difficulty(bits)
    target = int(MAX_TARGET / difficulty)
    target = target/factor
    target32 = '{:0>64x}'.format(target)             

    if hashSum == 0:
        hashSum = int(blockHash, 16)
    else:
        hashSum = hashSum + int(blockHash, 16)
        
def read_headers_local(block_height):
    global count
    headers_filename = os.path.join('.', 'blockchain_headers')
    h = b''
    if os.path.exists(headers_filename):
        with open(headers_filename, 'rb') as f:
            f.seek(block_height * 80)
            h = f.read(80)
            with open('header_chunk_server', 'ab+') as the_file:
                the_file.write(h)

        if len(h) == 80:
            count = count + 1
            
    h = header_from_string(h)
    return header_to_string(h)

if __name__ == '__main__':
    main()