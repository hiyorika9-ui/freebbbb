# -*- coding: utf-8 -*-
import os
import sys
import re
import json
import time
import socket
import random
import logging
import binascii
import threading
from datetime import datetime
from time import sleep
import requests
import httpx
import urllib3
import jwt
import base64
import psutil
import select
import errno
import signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import google.protobuf
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import telebot # Telegram Bot Library

# --- Configurations ---
API_TOKEN = '8540529232:AAGHCffS02vVmAl8S1ajD5FbppvaQNs9sV8' # ใส่ Token บอทที่นี่ / Put your Bot Token here
MASTER_ACCOUNT_ID = '6553870873'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Settings & Constants ---
Payload1A13 = "1a13323032352d30382d30322031373a31353a3033220966726565206669726528013a07312e3131382e314239416e64726f6964204f5320372e312e32202f204150492d32352028515031412e3139303731312e3032302f473938384e4b53553141544544294a0848616e6468656c645208542d4d6f62696c655a045749464960b60a68ee0572033234307a1841524d7637205646507633204e454f4e207c2030207c20348001ec1e8a010f416472656e6f2028544d29203635309201234f70656e474c20455320332e312028342e352e30204e5649444941203537372e3030299a012b476f6f676c657c32663563383830652d306533662d343236362d626638662d643331613666303462333464a2010d3130352e3130372e37312e3134aa0102656eb201206237303234356239326265383237616635366438393332333436663335316632ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473938384eea014031306532393962653966383139396264353066386335326262616534363935626331393335353633626131376433383539633937323337626434356362343238f00101ca0208542d4d6f62696c65d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003faf603e803baaf03f003fe3df803c62a800497c9038804faf603900497c9039804faf603c80402d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363932b205094f70656e474c455332b805ff7fc00504d2050b436f6e7374616e74696e65da05023235e0058b8b0bea0507616e64726f6964f205704b717348543876426332444378756538733871597a7675572f4e786463336a4230305152464554524f39454e656156674b2f662f6b4b79413566625531597350374d55477a686344423555454841637464656f662b5057634d4b644f4878342f625562704772413831714445563244418806019a060134a2060134b20600"
FreeFireVersion = "OB51"
GetLoginDataRegionMena = "https://client.ind.freefiremobile.com/GetLoginData"
MajorLoginRegionMena = "https://loginbp.ggblueshark.com/MajorLogin"

# --- Accounts (ตัวอย่าง) ---
accounts = {
   "4130126542": "YOUR PASSWORD"
}

# --- Protobuf Decoder Placeholder ---
# Try to import Parser, if not available, define a dummy or use raw decode logic
try:
    from protobuf_decoder.protobuf_decoder import Parser
except ImportError:
    print("Warning: protobuf_decoder module not found. Some functionality might fail.")
    # Simple Dummy Parser to prevent immediate crash, though functionality will be broken without the real one or a replacement
    class Parser:
        def parse(self, data):
            raise NotImplementedError("protobuf_decoder not found")

# --- Protobuf Setup ---
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"\x87\x05\n\rMajorLoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x13\n\x0block_region\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl\x18\t \x01(\x05\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mulator_score\x18\x0c \x01(\x03\x12\x32\n\tblacklist\x18\r \x01(\x0b\x32\x1f.MajorLoginRes.BlacklistInfoRes\x12\x31\n\nqueue_info\x18\x0f \x01(\x0b\x32\x1d.MajorLoginRes.LoginQueueInfo\x12\x0e\n\x06tp_url\x18\x10 \x01(\t\x12\x15\n\rapp_server_id\x18\x11 \x01(\x03\x12\x0f\n\x07\x61no_url\x18\x12 \x01(\t\x12\x0f\n\x07ip_city\x18\x13 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x14 \x01(\x03\x12\x0b\n\x03kts\x18\x15 \x01(\x03\x12\n\n\x02\x61k\x18\x16 \x01(\x0c\x12\x0b\n\x03\x61iv\x18\x17 \x01(\x0c\x1aQ\n\x10\x42lacklistInfoRes\x12\x12\n\nban_reason\x18\x01 \x01(\x05\x12\x17\n\x0f\x65xpire_duration\x18\x02 \x01(\x03\x12\x10\n\x08\x62\x61n_time\x18\x03 \x01(\x03\x1a\x66\n\x0eLoginQueueInfo\x12\r\n\x05\x41llow\x18\x01 \x01(\x08\x12\x16\n\x0equeue_position\x18\x02 \x01(\x03\x12\x16\n\x0eneed_wait_secs\x18\x03 \x01(\x03\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08\x62\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "MajorLoginRes_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_MAJORLOGINRES']._serialized_start=24
  _globals['_MAJORLOGINRES']._serialized_end=671
  _globals['_MAJORLOGINRES_BLACKLISTINFORES']._serialized_start=486
  _globals['_MAJORLOGINRES_BLACKLISTINFORES']._serialized_end=567
  _globals['_MAJORLOGINRES_LOGINQUEUEINFO']._serialized_start=569
  _globals['_MAJORLOGINRES_LOGINQUEUEINFO']._serialized_end=671

Key , Iv = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56]) , bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# --- Helper Functions ---
def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)
    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed

def encode_varint(num):
    if num < 0: raise ValueError("Number must be non-negative")
    out = []
    while True:
        b = num & 0x7F
        num >>= 7
        if num: b |= 0x80
        out.append(b)
        if not num: break
    return bytes(out)

def create_field(num, val):
    if isinstance(val, int): 
        return encode_varint((num<<3)|0) + encode_varint(val)
    if isinstance(val, (str,bytes)):
        v = val.encode() if isinstance(val,str) else val
        return encode_varint((num<<3)|2) + encode_varint(len(v)) + v
    if isinstance(val, dict):
        nested = create_packet(val)
        return encode_varint((num<<3)|2) + encode_varint(len(nested)) + nested
    return b""

def create_packet(fields):
    return b"".join(create_field(k,v) for k,v in fields.items())

def dec_to_hex(n): 
    return f"{n:02x}"

def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def aes_encrypt(data, key, iv):
    data = bytes.fromhex(data) if isinstance(data,str) else data
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data,16)).hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def get_packet2(key,iv): 
    fields = {1:3, 2:{2:5,3:"en"}}
    packet = create_packet(fields).hex()+"7200"
    hlen = len(aes_encrypt(packet,key,iv))//2
    return bytes.fromhex("1215000000"+dec_to_hex(hlen)+aes_encrypt(packet,key,iv))

def OpenSquad(key, iv):
    fields = {1:1, 2:{2:"\u0001",3:1,4:1,5:"en",9:1,11:1,13:1,14:{2:5756,6:11,8:"1.109.5",9:3,10:2}}}
    packet = create_packet(fields).hex()
    encrypted_packet = aes_encrypt(packet, key, iv)
    hlen = len(encrypted_packet) // 2
    return bytes.fromhex("0515000000" + dec_to_hex(hlen) + encrypted_packet)

def ReqSquad(client_id, key, iv):
    fields = {1:2, 2:{1:int(client_id),2:"ME",4:1}}
    packet = create_packet(fields).hex()
    encrypted_packet = aes_encrypt(packet, key, iv)
    hlen = len(encrypted_packet) // 2
    return bytes.fromhex("0515000000" + dec_to_hex(hlen) + encrypted_packet)

def GeneratMsg(msg, cid, key, iv):
    fields = {1:1,2:{1:7141867918,2:int(cid),3:2,4:msg,5:int(datetime.now().timestamp()),7:2,9:{1:"TheIconicDevFOx",2:902000066,3:901037021,4:random.randint(301,330),5:901037021,8:"TheIconicDevFOx",10:2,11:2010,13:{1:2,2:1},14:{1:11017917409,2:8,3:"\u0010\u0015\b\n\u000b"}},10:"en",13:{1:"https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",2:1,3:1},14:{1:{1:random.choice([1,4]),2:1,3:random.randint(1,180),4:1,5:int(datetime.now().timestamp()),6:"en"}}}}
    packet = create_packet(fields).hex()
    encrypted_packet = aes_encrypt(packet, key, iv)
    hlen = len(encrypted_packet) // 2
    hlen_final = dec_to_hex(hlen)
    if len(hlen_final) == 2:
        final_packet = "1215000000" + hlen_final + encrypted_packet
    elif len(hlen_final) == 3:
        final_packet = "121500000" + hlen_final + encrypted_packet
    elif len(hlen_final) == 4:
        final_packet = "12150000" + hlen_final + encrypted_packet
    elif len(hlen_final) == 5:
        final_packet = "1215000" + hlen_final + encrypted_packet

    return bytes.fromhex(final_packet)

def EnC_AEs(HeX):
    cipher = AES.new(Key , AES.MODE_CBC , Iv)
    return cipher.encrypt(pad(bytes.fromhex(HeX), AES.block_size)).hex()
    
def DEc_AEs(HeX):
    cipher = AES.new(Key , AES.MODE_CBC , Iv)
    return unpad(cipher.decrypt(bytes.fromhex(HeX)), AES.block_size).hex()
    
def EnC_PacKeT(HeX , K , V): 
    return AES.new(K , AES.MODE_CBC , V).encrypt(pad(bytes.fromhex(HeX) ,16)).hex()
    
def DEc_PacKeT(HeX , K , V):
    return unpad(AES.new(K , AES.MODE_CBC , V).decrypt(bytes.fromhex(HeX)) , 16).hex()  

def EnC_Uid(H , Tp):
    e , H = [] , int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0)) ; H >>= 7
    return bytes(e).hex() if Tp == 'Uid' else None

def EnC_Vr(N):
    if N < 0: ''
    H = []
    while True:
        BesTo = N & 0x7F ; N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)
    
def DEc_Uid(H):
    n = s = 0
    for b in bytes.fromhex(H):
        n |= (b & 0x7F) << s
        if not b & 0x80: break
        s += 7
    return n
    
def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet    
    
def DecodE_HeX(H):
    R = hex(H) 
    F = str(R)[2:]
    if len(F) == 1: F = "0" + F ; return F
    else: return F

def Fix_PackEt(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = Fix_PackEt(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def DeCode_PackEt(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = Fix_PackEt(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
                      
def xMsGFixinG(n):
    return '🗿'.join(str(n)[i:i + 3] for i in range(0 , len(str(n)) , 3))

def ArA_CoLor():
    Tp = [
        # 🔴 الأحمر
        "FF0000","DC143C","B22222","8B0000","A52A2A","CD5C5C","FA8072","E9967A","F08080","FF6347","FF4500","FF5F1F","FF2400","8B1A1A","FF6F61","FF7F50",
        
        # 🟠 البرتقالي
        "FFA500","FF8C00","FF7F00","FF7518","FF6700","E65100","FFB347","D2691E","CD853F","A0522D","8B4513","FFDEAD","FFE4B5","FFDAB9","FFE4C4","F4A460",
        
        # 🟡 الأصفر / الذهبي
        "FFFF00","FFD700","FFFACD","FAFAD2","EEE8AA","F0E68C","FFD700","EEDC82","DAA520","B8860B","CDAD00","FFC300","F1C40F","F39C12","FFEA00","FFF44F",
        
        # 🟢 الأخضر
        "00FF00","32CD32","7CFC00","7FFF00","ADFF2F","98FB98","90EE90","8FBC8F","66CDAA","20B2AA","3CB371","2E8B57","228B22","008000","006400","004225",
        
        # 🔵 الأزرق
        "0000FF","0000CD","00008B","191970","1E90FF","4169E1","4682B4","5F9EA0","6495ED","87CEEB","87CEFA","00BFFF","B0E0E6","ADD8E6","7B68EE","6A5ACD",
        
        # 🟣 البنفسجي / الوردي
        "800080","8A2BE2","9400D3","9932CC","BA55D3","DA70D6","DDA0DD","EE82EE","FF00FF","C71585","DB7093","FF1493","FF69B4","FFB6C1","FFC0CB","E75480",
        
        # ⚪ الرمادي / الأبيض / الأسود
        "FFFFFF","F8F8FF","F5F5F5","FFFAFA","F0F8FF","E6E6FA","DCDCDC","D3D3D3","C0C0C0","A9A9A9","808080","696969","2F4F4F","000000","778899","708090",
        
        # 🌈 ألوان زاهية إضافية
        "00FFFF","40E0D0","48D1CC","00CED1","1ABC9C","16A085","76EEC6","7FFFD4","AFEEEE","5F9EA0","48C9B0","45B39D","3498DB","2980B9","2471A3","154360",
        
        # 🎨 إضافات حديثة (درجات متنوعة)
        "E74C3C","C0392B","9B59B6","8E44AD","2874A6","1F618D","52BE80","27AE60","229954","1D8348","F39C12","D68910","CA6F1E","A04000","7E5109","6E2C00",
        
        # ✨ ألوان فاتحة/باستيل
        "FFDEAD","FFE4C4","FFEFD5","FFF5EE","FAEBD7","FFEBCD","FFF8DC","FDF5E6","F5DEB3","FFF0F5","E0FFFF","F0FFF0","F5FFFA","F0FFFF","F0F8FF","FFFACD"
    ]
    return random.choice(Tp)
    
def xBunnEr():
    bN = [902000306 , 902000305 , 902000003 , 902000016 , 902000017 , 902000019 , 902000020 , 902000021 , 902000023 , 902000070 , 902000087 , 902000108 , 902000011 , 902049020 , 902049018 , 902049017 , 902049016 , 902049015 , 902049003 , 902033016 , 902033017 , 902033018 , 902048018 , 902000306 , 902000305]
    return random.choice(bN)

def GeneRaTePk(Pk, Header, K, V):
    # Dummy implementation if GeneRaTePk was missing from snippet, but assuming logic from context
    # It seems to wrap packet with length and header
    encrypted = aes_encrypt(Pk, K, V)
    hlen = len(encrypted) // 2
    return bytes.fromhex(Header + "000000" + dec_to_hex(hlen) + encrypted)

def xSEndMsg(Msg , Tp , Tp2 , id , K , V):
    feilds = {1: id, 2: Tp2, 3: Tp, 4: Msg , 5: 1735129800, 7: 2, 9: {1: "xBesTo - C4­", 2: xBunnEr(), 3: 901048018, 4: 330, 5: 909034009, 8: "xBesTo - C4", 10: 1, 11: 1, 14: {1: 1158053040, 2: 8, 3: "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"}}, 10: "en", 13: {2: 1, 3: 1}, 14: {}}
    Pk = str(CrEaTe_ProTo(feilds).hex())
    Pk = "080112" + EnC_Uid(len(Pk) // 2 , Tp = 'Uid') + Pk
    return GeneRaTePk(str(Pk) , '1215' , K , V)

def Auth_Chat(idT, sq, K, V):
    fields = {
        1: 3,
        2: {
            1: idT,
            3: "fr",
            4: sq
        }
    }
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '1215' , K , V)

def xSendTeamMsg(msg, idT,  K, V):
    fields = {
    1: 1,
    2: {
        1: 12404281032,
        2: idT,
        4: msg,
        7: 2,
        10: "fr",
        9: {
            1: "C4 TEAM",
            2: xBunnEr(),
            4: 330,
            5: 827001005,
            8: "C4 TEAM",
            10: 1,
            11: 1,
            12: {
                1: 2
            },
            14: {
                1: 1158053040,
                2: 8,
                3: "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            }
        },
        13: {
            1: 2,
            2: 1
        },
        14:{}
    }
}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '1215' , K , V)

def OpEnSq(K , V):
    fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.111.5", 9: 2, 10: 4}}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def cHSq(Nu , Uid , K , V):
    fields = {1: 17, 2: {1: int(Uid), 2: 1, 3: int(Nu - 1), 4: 62, 5: "\u001a", 8: 5, 13: 329}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def SEnd_InV(Nu , Uid , K , V):
    fields = {1: 2 , 2: {1: int(Uid) , 2: "ME" , 4: int(Nu)}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)
    
def ExiT(id , K , V):
    fields = {
        1: 7,
        2: {
            1: int(11037044965)
        }
        }
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def GenJoinSquadsPacket(squad_id, key, iv):
    # Missing from snippet, implementing best guess based on usage
    fields = {1: 8, 2: {1: int(squad_id), 2: 1}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0515', key, iv)

def ghost_pakcet(idT, name, sq, key, iv):
    # Implementation guess based on context
    return xSendTeamMsg("Ghost Msg", idT, key, iv)


def SpamAddFriend(uid):
        try:
            url = f"https://spam-rose.vercel.app/send_friend?player_id={uid}"
            req = requests.get(url)
            data = req.json()
            for detail in data.get("details", []):
                status = detail.get("status")
                if status == "success":
                    return f"ส่งสแปมคำขอเป็นเพื่อนไปยัง {fix_num(uid)} สำเร็จ"
                else:
                    return "ส่งสแปมคำขอเป็นเพื่อนล้มเหลว ตรวจสอบ UID หรือลองใหม่ภายหลัง"
        except Exception as e:
            return f"ข้อผิดพลาด: {e}"   

def GetPlayerInfoRegionMena(uid):
    url = f"https://info-five-sooty.vercel.app/get?uid={uid}"
    try:
        req = requests.get(url)
        data = req.json()    
        account = data.get('AccountInfo', {})
        profile = data.get('AccountProfileInfo', {})
        guild = data.get('GuildInfo', {})
        pet = data.get('petInfo', {})
        credit = data.get('creditScoreInfo', {})
        social = data.get('socialinfo', {})
        
        def format_time(ts):
            try:
                return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
            except:
                return ts
                
        message1 = f"""
===== ข้อมูลบัญชี =====
ชื่อ: {account.get('AccountName')}
เลเวล: {account.get('AccountLevel')}
ภูมิภาค: {account.get('AccountRegion')}
EXP: {fix_num(account.get('AccountEXP'))}
ถูกใจ: {fix_num(account.get('AccountLikes'))}
BR Rank: {fix_num(account.get('BrMaxRank'))} ({fix_num(account.get('BrRankPoint'))} แต้ม)
CS Rank: {fix_num(account.get('CsMaxRank'))} ({fix_num(account.get('CsRankPoint'))} แต้ม)
อาวุธที่ติดตั้ง: {fix_num(account.get('EquippedWeapon'))}
ประเภทบัญชี: {account.get('AccountType')}
เวอร์ชั่น: {account.get('ReleaseVersion')}
สร้างเมื่อ: {fix_num(format_time(account.get('AccountCreateTime')))}
เข้าสู่ระบบล่าสุด: {fix_num(format_time(account.get('AccountLastLogin')))}
"""
        message2 = f"""
===== ข้อมูลสัตว์เลี้ยง =====
Pet ID: {fix_num(pet.get('id'))}
เลือก: {fix_num(pet.get('isSelected'))}
เลเวล: {pet.get('level')}
สกิลที่เลือก: {fix_num(pet.get('selectedSkillId'))}
สกิน: {fix_num(pet.get('skinId'))}
===== ข้อมูลคะแนนเครดิต =====
คะแนน: {fix_num(credit.get('creditScore'))}
สถานะรางวัล: {fix_num(credit.get('rewardState'))}
===== ข้อมูลโซเชียล =====
Account ID: {fix_num(social.get('accountId'))}
ภาษา: {social.get('language')}
Rank Show: {fix_num(social.get('rankShow'))}
ลายเซ็น: {social.get('signature')}
"""
        return [message1, message2]
    except Exception as e:
        return [f"เกิดข้อผิดพลาดในการดึงข้อมูล: {e}", ""]

# --- Bot Client Class ---
clients = {}
shutting_down = False
shared_0500_info = {
    'got': False,
    'idT': None,
    'squad': None,
    'AutH': None
}

class TcpBotConnectMain:
    def __init__(self, account_id, password):
        self.account_id = account_id
        self.password = password
        self.key = None
        self.iv = None
        self.socket_client = None
        self.clientsocket = None
        self.running = False
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.AutH = None
        self.DaTa2 = None
    
    def run(self):
        if shutting_down:
            return
            
        self.running = True
        self.connection_attempts = 0
        
        while self.running and not shutting_down and self.connection_attempts < self.max_connection_attempts:
            try:
                self.connection_attempts += 1
                print(f"[{self.account_id}] ความพยายามเชื่อมต่อ {self.connection_attempts}/{self.max_connection_attempts}")
                self.get_tok()
                break
            except Exception as e:
                print(f"[{self.account_id}] เกิดข้อผิดพลาดในการรัน: {e}")
                if self.connection_attempts >= self.max_connection_attempts:
                    print(f"[{self.account_id}] ถึงขีดจำกัดการเชื่อมต่อแล้ว หยุดการทำงาน")
                    self.stop()
                    break
                print(f"[{self.account_id}] ลองใหม่ใน 5 วินาที...")
                time.sleep(5)
    
    def stop(self):
        self.running = False
        try:
            if self.clientsocket:
                self.clientsocket.close()
        except:
            pass
        try:
            if self.socket_client:
                self.socket_client.close()
        except:
            pass
        print(f"[{self.account_id}] บอทหยุดทำงานแล้ว")
    
    def restart(self, delay=5):
        if shutting_down:
            return
            
        print(f"[{self.account_id}] กำลังรีสตาร์ทบอทใน {delay} วินาที...")
        time.sleep(delay)
        self.run()
    
    def is_socket_connected(self, sock):
        try:
            if sock is None:
                return False
            writable = select.select([], [sock], [], 0.1)[1]
            if sock in writable:
                sock.send(b'')
                return True
            return False
        except (OSError, socket.error) as e:
            if e.errno == errno.EBADF:
                print(f"[{self.account_id}] Socket bad file descriptor")
            return False
        except Exception as e:
            print(f"[{self.account_id}] Socket check error: {e}")
            return False
    
    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        while self.running and not shutting_down:
            try:
                self.socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_client.settimeout(30)
                self.socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                online_port = int(online_port)
                print(f"[{self.account_id}] กำลังเชื่อมต่อไปยัง {online_ip}:{online_port}...")
                self.socket_client.connect((online_ip, online_port))
                print(f"[{self.account_id}] เชื่อมต่อสำเร็จ {online_ip}:{online_port}")
                self.socket_client.send(bytes.fromhex(tok))
                print(f"[{self.account_id}] ส่ง Token เรียบร้อย")
                
                while self.running and not shutting_down and self.is_socket_connected(self.socket_client):
                    try:
                        readable, _, _ = select.select([self.socket_client], [], [], 1.0)
                        if self.socket_client in readable:
                            self.DaTa2 = self.socket_client.recv(99999)
                            if not self.DaTa2:
                                print(f"[{self.account_id}] เซิร์ฟเวอร์ปิดการเชื่อมต่อ")
                                break

                            if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                                try:
                                    self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                                    self.AutH = self.packet['5']['data']['7']['data']
                                    print(f"[{self.account_id}] ได้รับแพ็คเกจ 0500, AutH={self.AutH}")

                                    if self.account_id == MASTER_ACCOUNT_ID:
                                        shared_0500_info['got'] = True
                                        shared_0500_info['idT'] = self.packet['5']['data']['1']['data']
                                        shared_0500_info['squad'] = self.packet['5']['data']['31']['data']
                                        shared_0500_info['AutH'] = self.AutH
                                        print(f"[{self.account_id}] Master บันทึกข้อมูล 0500")

                                    elif shared_0500_info['got']:
                                        idT = shared_0500_info['idT']
                                        sq = shared_0500_info['squad']
                                        for _ in range(3):
                                            self.socket_client.send(GenJoinSquadsPacket(idT, key, iv))
                                            time.sleep(0.5)
                                            self.socket_client.send(ExiT('000000', key, iv))
                                            self.socket_client.send(ghost_pakcet(idT, "insta:kha_led_mhd", sq, key, iv))
                                            time.sleep(0.5)

                                except Exception as parse_err:
                                    print(f"[{self.account_id}] ผิดพลาดในการแปลง 0500: {parse_err}")
                                
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"[{self.account_id}] ข้อผิดพลาด Socket: {e}. กำลังเชื่อมต่อใหม่...")
                        break
                        
            except Exception as e:
                print(f"[{self.account_id}] ข้อผิดพลาดการเชื่อมต่อ: {e}")
                time.sleep(5)

    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        try:
            self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.clientsocket.settimeout(None)
            self.clientsocket.connect((whisper_ip, int(whisper_port)))
            print(f"[{self.account_id}] เชื่อมต่อกับ Whisper {whisper_ip}:{whisper_port}")
            self.clientsocket.send(bytes.fromhex(tok))
            self.data = self.clientsocket.recv(1024)
            self.clientsocket.send(get_packet2(self.key, self.iv))

            thread = threading.Thread(
                target=self.sockf1,
                args=(tok, online_ip, online_port, "anything", key, iv)
            )
            thread.daemon = True
            thread.start()
            
            # Keep alive whisper connection logic (simplified)
            
        except Exception as e:
            print(f"[{self.account_id}] ผิดพลาดใน connect: {e}")

    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes() 
        MajorLogRes.ParseFromString(serialized_data)
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN
    
    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now = str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex(Payload1A13)
        payload = payload.replace(b"2025-08-02 17:15:04", str(now).encode())
        payload = payload.replace(b"10e299be9f8199bd50f8c52bbae4695bc1935563ba17d3859c97237bd45cb428", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"b70245b92be827af56d8932346f351f2", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port
    
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = GetLoginDataRegionMena
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': FreeFireVersion,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0
        while attempt < max_retries and not shutting_down:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            except requests.RequestException as e:
                print(f"[{self.account_id}] Request failed: {e}. Attempt {attempt + 1}. Retrying...")
                attempt += 1
                time.sleep(2)
        print(f"[{self.account_id}] Failed to get login data.")
        return None, None, None, None

    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": 'application/x-www-form-urlencoded',"Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "10e299be9f8199bd50f8c52bbae4695bc1935563ba17d3859c97237bd45cb428"
        OLD_OPEN_ID = "b70245b92be827af56d8932346f351f2"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        return data

    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': FreeFireVersion,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex(Payload1A13)
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        hex_data = data.hex()
        encrypted_data = encrypt_api(hex_data)
        Final_Payload = bytes.fromhex(encrypted_data)
        URL = MajorLoginRegionMena
        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            self.key = key
            self.iv = iv
            print(f"[{self.account_id}] Key: {key}, IV: {iv}")
            return (BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False

    def get_tok(self):
        token_data = self.guest_token(self.account_id, self.password)
        if not token_data:
            print(f"[{self.account_id}] ล้มเหลวในการรับ Token")
            self.restart()
            return
        
        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        print(f"[{self.account_id}] Whisper: {whisper_ip}:{whisper_port}")
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
        except Exception as e:
            print(f"[{self.account_id}] Error decoding token: {e}")
            self.restart()
            return
        
        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'
            if length == 9: zeros = '0000000'
            elif length == 8: zeros = '00000000'
            elif length == 10: zeros = '000000'
            elif length == 7: zeros = '000000000'
            
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
        except Exception as e:
            print(f"[{self.account_id}] Error creating final token: {e}")
            self.restart()
            return
        
        self.connect(final_token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        return final_token, key, iv

# --- Telegram Bot Setup ---
if API_TOKEN == 'YOUR_TELEGRAM_BOT_TOKEN_HERE':
    print("กรุณาใส่ Token ของ Telegram Bot ในไฟล์ (บรรทัดที่ 30)")
    # Using a dummy bot to allow syntax check, but won't run without token
    bot = telebot.TeleBot("DUMMY_TOKEN", threaded=False)
else:
    bot = telebot.TeleBot(API_TOKEN)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "สวัสดี! นี่คือบอท Free Fire\nคำสั่ง:\n/login - ล็อกอินบอททั้งหมด\n/stop - หยุดบอท\n/check <uid> - ตรวจสอบข้อมูลผู้เล่น\n/spam_friend <uid> - สแปมแอดเพื่อน")

@bot.message_handler(commands=['login'])
def start_bots(message):
    bot.reply_to(message, "กำลังเริ่มบอททั้งหมด...")
    for acc_id, password in accounts.items():
        if acc_id not in clients:
            client = TcpBotConnectMain(acc_id, password)
            clients[acc_id] = client
            t = threading.Thread(target=client.run)
            t.daemon = True
            t.start()
            bot.reply_to(message, f"เริ่มบอท {acc_id} แล้ว")
        else:
            bot.reply_to(message, f"บอท {acc_id} ทำงานอยู่แล้ว")

@bot.message_handler(commands=['stop'])
def stop_bots(message):
    global shutting_down
    shutting_down = True
    for acc_id, client in clients.items():
        client.stop()
    clients.clear()
    bot.reply_to(message, "หยุดบอททั้งหมดเรียบร้อยแล้ว")

@bot.message_handler(commands=['check'])
def check_player(message):
    try:
        uid = message.text.split()[1]
        info = GetPlayerInfoRegionMena(uid)
        for msg in info:
            bot.reply_to(message, msg)
    except IndexError:
        bot.reply_to(message, "กรุณาระบุ UID: /check <uid>")
    except Exception as e:
        bot.reply_to(message, f"เกิดข้อผิดพลาด: {e}")

@bot.message_handler(commands=['spam_friend'])
def spam_friend(message):
    try:
        uid = message.text.split()[1]
        result = SpamAddFriend(uid)
        bot.reply_to(message, result)
    except IndexError:
        bot.reply_to(message, "กรุณาระบุ UID: /spam_friend <uid>")

print("บอทกำลังทำงาน... (กด Ctrl+C เพื่อหยุด)")
if API_TOKEN != 'YOUR_TELEGRAM_BOT_TOKEN_HERE':
    bot.polling()
