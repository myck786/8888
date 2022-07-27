#!/usr/bin/env python3

import os 
import subprocess
import shutil
import glob
import pathlib
import platform
import time
import sys
import base64
import argparse
import socket
import binascii
import requests
from pathlib import Path
from urllib.request import getproxies
from Cryptodome.Hash import CMAC
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pss

import license_protocol_pb2

PRIVATE_KEY = "MIIEpQIBAAKCAQEA3CRKux53ESQyi3RwguxIjoPWLXiEiyzjX2RiDOJmhE0B8u+rOhHAgUWjsccBT2HdNztoOSrPMIOg5jJ/Rl9MIMVOsURYsyD3sVWWUlSvmPLtsNrlTttEABpnBG8TJDCBLVx+5F/mn2PzwM5EV/2Nx1RqgTrRUu3fm2g5LeJwoBHDKYmivzWCl5kICHYw3nxLVh7EddaMVV87aoyjoZqbVsr+jGgANIENHt0FdWQxprJUS72o0F6gj2iSIfxI9ojrZkpp6o2ACIitYVqjxVSt6u6YHJgXySi2hdFmWFhKI6R0jdAfTrsnuWPZTl2gs5DPl8u18n3B88dwDwYAAwhz8QIDAQABAoIBAQCzEGIpKnK3YrYqcSBDnma2Zc6FVg6aFn0sTr7itBWnb+wx63lf1qi7fiXUqYcLRxNlpdD1DzlQwQDTvieA2mtWDKgh0PJFYn+Xo4KOnYvn4VIuFR+IsRny64b4OFFdkobAmwgsQ0WYSPkwz5cP65KznJq1W16BEjRceL5p8FKkH8t+oOuAcQITy/U2/hGTYGYs2LTdZHo3lcEBBdK/iPOzoKFg8CXujnTa7bu5JomgOr0aTIWf752gUeMLz7JcgILooN7FYiCthh2WDhlNLpqctsx0VDRXN4zkdX721IoaP1kNH+Qcn/hKY9jQaNvNEm6774qbP2Eju5NhYLNJsdRBAoGBAP5IV21s2oMkE8gbtTFRFoUTMTHAaEtlLr4XuEDPhiegDDlC7+yhPF0JeSKcE5SbDnHjqNjceZyqjcyVha3juMKrM3c4ngQVkwhEsgZ8pFOQe59WeRbf3QP4/jeDZbakYK7+h6WcF/AeCEj++0A1psOUZ6VI2zh1DZ9D0YaNCKw9AoGBAN2g65+tE+SN+xyuXbkHWMgZeufVXnc0JsRTi8bRGga82iOJ451Ugp7xPtGpfhZbZQuCVRYfFwc8lcGfMr+qeX2Im++IsG4QAnFI7+v3zLnOhegHGjefJiSiDwqVKAzFKObKCg8amNIYMnXDCM3DZvIRzlZDWyKJ00WefFoPzR3FAoGBAM0xaUOHBKmwsjnXihaa3bZTL257Wm4E33xMPcYm8JYHQ/XtOxjTX5egLl0sX2ya10Q2NymQeJ5gzv5ZZj9VNOH6LxS03mZjVnvkm1g6uowoWmnQ6PP5gCtVgScg5DJHYTG1eZa9aF++jGcDQ5Kj+Md4eU7ahPSBGJX9rxWJt4btAoGBAINk0gyaif6ohkWcwofd6S7InGsxvo2hZ5Jhja7TbUCtWg5Tw5QU9FPS5tFaURxkFuXZ4SP6TqbFrmtaPLYRFXHtObWrLh4yc6BCA6u7/63w2MaU32A2hGCXi59Uiqf3g6ZABfKqbAuyuMfEV0XWIQRGtjPCPxec6pqNuV+TmqGZAoGAYLtz4/HrC1lpocwwRBcDBmHySli+CWB1Xw1ZBI4tfdTmK9axxwVu5f7vB1xmv1EkZu7dph1lt1WdW3UYBhocV6JMX5yaCTJTPF9vTr/+p4pH29dUUm9wFJs5O43NzDKavFpSW0BVzsBOeyqw1SKk53LYa7SIwQZdEil3B5EI16k="

PUBLIC_KEY = "MIIEpQIBAAKCAQEA3CRKux53ESQyi3RwguxIjoPWLXiEiyzjX2RiDOJmhE0B8u+rOhHAgUWjsccBT2HdNztoOSrPMIOg5jJ/Rl9MIMVOsURYsyD3sVWWUlSvmPLtsNrlTttEABpnBG8TJDCBLVx+5F/mn2PzwM5EV/2Nx1RqgTrRUu3fm2g5LeJwoBHDKYmivzWCl5kICHYw3nxLVh7EddaMVV87aoyjoZqbVsr+jGgANIENHt0FdWQxprJUS72o0F6gj2iSIfxI9ojrZkpp6o2ACIitYVqjxVSt6u6YHJgXySi2hdFmWFhKI6R0jdAfTrsnuWPZTl2gs5DPl8u18n3B88dwDwYAAwhz8QIDAQABAoIBAQCzEGIpKnK3YrYqcSBDnma2Zc6FVg6aFn0sTr7itBWnb+wx63lf1qi7fiXUqYcLRxNlpdD1DzlQwQDTvieA2mtWDKgh0PJFYn+Xo4KOnYvn4VIuFR+IsRny64b4OFFdkobAmwgsQ0WYSPkwz5cP65KznJq1W16BEjRceL5p8FKkH8t+oOuAcQITy/U2/hGTYGYs2LTdZHo3lcEBBdK/iPOzoKFg8CXujnTa7bu5JomgOr0aTIWf752gUeMLz7JcgILooN7FYiCthh2WDhlNLpqctsx0VDRXN4zkdX721IoaP1kNH+Qcn/hKY9jQaNvNEm6774qbP2Eju5NhYLNJsdRBAoGBAP5IV21s2oMkE8gbtTFRFoUTMTHAaEtlLr4XuEDPhiegDDlC7+yhPF0JeSKcE5SbDnHjqNjceZyqjcyVha3juMKrM3c4ngQVkwhEsgZ8pFOQe59WeRbf3QP4/jeDZbakYK7+h6WcF/AeCEj++0A1psOUZ6VI2zh1DZ9D0YaNCKw9AoGBAN2g65+tE+SN+xyuXbkHWMgZeufVXnc0JsRTi8bRGga82iOJ451Ugp7xPtGpfhZbZQuCVRYfFwc8lcGfMr+qeX2Im++IsG4QAnFI7+v3zLnOhegHGjefJiSiDwqVKAzFKObKCg8amNIYMnXDCM3DZvIRzlZDWyKJ00WefFoPzR3FAoGBAM0xaUOHBKmwsjnXihaa3bZTL257Wm4E33xMPcYm8JYHQ/XtOxjTX5egLl0sX2ya10Q2NymQeJ5gzv5ZZj9VNOH6LxS03mZjVnvkm1g6uowoWmnQ6PP5gCtVgScg5DJHYTG1eZa9aF++jGcDQ5Kj+Md4eU7ahPSBGJX9rxWJt4btAoGBAINk0gyaif6ohkWcwofd6S7InGsxvo2hZ5Jhja7TbUCtWg5Tw5QU9FPS5tFaURxkFuXZ4SP6TqbFrmtaPLYRFXHtObWrLh4yc6BCA6u7/63w2MaU32A2hGCXi59Uiqf3g6ZABfKqbAuyuMfEV0XWIQRGtjPCPxec6pqNuV+TmqGZAoGAYLtz4/HrC1lpocwwRBcDBmHySli+CWB1Xw1ZBI4tfdTmK9axxwVu5f7vB1xmv1EkZu7dph1lt1WdW3UYBhocV6JMX5yaCTJTPF9vTr/+p4pH29dUUm9wFJs5O43NzDKavFpSW0BVzsBOeyqw1SKk53LYa7SIwQZdEil3B5EI16k="

def read_pssh(path: str):
	raw = Path(path).read_bytes()
	pssh_offset = raw.rfind(b'pssh')
	_start = pssh_offset - 4
	_end = pssh_offset - 4 + raw[pssh_offset-1]
	pssh = raw[_start:_end]
	return pssh

class WidevineCDM:
	def __init__(self, license_url: str):
		self.private_key = binascii.a2b_hex(PRIVATE_KEY)
		self.public_key = binascii.a2b_hex(PUBLIC_KEY)
		self.proxies = getproxies()
		self.license_url = license_url
		self.header={"Cookie": ""}
		
	def generateRequestData(self, pssh: bytes):
		_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		_socket.settimeout(1)
		try:
			_socket.connect(("127.0.0.1", 8888))
			_socket.send(pssh)
			recv = _socket.recv(10240)
		except Exception as e:
			print(f"socket recv data failed. --> {e}")
			_socket.close()
			return
		_socket.close()
		return recv
	
	def verify(self, msg: bytes, signature: bytes):

		_hash = SHA1.new(msg)
		public_key = RSA.importKey(self.public_key)
		verifier = pss.new(public_key)
		res = verifier.verify(_hash, signature)
		print(f"verify result is --> {res}")
		
	def license_request(self, payload):
		try:
			r = requests.post(self.license_url, data=payload, headers=self.header, proxies=self.proxies)
		except Exception as e:
			sys.exit(f"request license failed. --> {e}")
		return r.content
	
	def getContentKey(self, license_request_data: bytes, license_response_data: bytes):
		licenseMessage = license_protocol_pb2.License()
		requestMessage=license_protocol_pb2.SignedMessage()
		responseMessage = license_protocol_pb2.SignedMessage()
		requestMessage.ParseFromString(license_request_data)
		responseMessage.ParseFromString(license_response_data)
		
		oaep_key = RSA.importKey(self.private_key)
		cipher = PKCS1_OAEP.new(oaep_key)
		cmac_key = cipher.decrypt(responseMessage.session_key)
		
		_cipher = CMAC.new(cmac_key, ciphermod=AES)
		_auth_key = b'\x01ENCRYPTION\x00' + requestMessage.msg + b"\x00\x00\x00\x80"
		enc_cmac_key = _cipher.update(_auth_key).digest()
		
		licenseMessage.ParseFromString(responseMessage.msg)
		global KEY_ARRAY
		KEY_ARRAY=[]
		for key in licenseMessage.key:
			cryptos = AES.new(enc_cmac_key, AES.MODE_CBC, iv=key.iv[0:16])
			dkey = cryptos.decrypt(key.key[0:16])
#			print("KID:", binascii.b2a_hex(key.id).decode('utf-8'), "KEY:",binascii.b2a_hex(dkey).decode('utf-8'))
			KEY_ARRAY.append("%s:%s"%(binascii.b2a_hex(key.id).decode('utf-8'),binascii.b2a_hex(dkey).decode('utf-8')))
		KEY_ARRAY.remove(KEY_ARRAY[0])
		for item in KEY_ARRAY:
			print("[info][Found KEY] %s"%item)
		
	def work(self, pssh: bytes):
		license_request_data = self.generateRequestData(pssh)
		if license_request_data is None:
			sys.exit("generate requests data failed.")
		license_response_data = self.license_request(license_request_data)
		self.getContentKey(license_request_data, license_response_data)
		
def getkeys(init_path,license_url):
	pssh =  read_pssh(init_path)
	cdm = WidevineCDM(license_url)
	cdm.work(pssh)
	
FILE_DIRECTORY=str(pathlib.Path(__file__).parent.absolute())
TEMPORARY_PATH = FILE_DIRECTORY+"/cache"
OUTPUT_PATH = FILE_DIRECTORY+"/output"
VIDEO_ID = "bv"
AUDIO_ID = "ba"

def osinfo():
	global PLATFORM
	if platform.system()== "Darwin":
		PLATFORM = "Mac"
	else:
		PLATFORM = platform.system()

def divider():
	count = int(shutil.get_terminal_size().columns)
	count = count - 1
	print ('-' * count)
	
def empty_folder(folder):
	files = glob.glob('%s/*'%folder)
	for f in files:
		os.remove(f)
	print("Emptied Temporary Files!")
	divider()
	quit()
	
def parse_key (prompt):
	global key,kid,keys
	key = prompt[30 : 62]
	kid = prompt[68 : 100]
	keys = "--key %s:%s"%(kid,key)
	return key,kid,keys

def download_drm_content(mpd_url):
	divider()
	print("Processing Video Info..")
	os.system('yt-dlp --external-downloader aria2c --no-warnings --allow-unplayable-formats --no-check-certificate -F "%s"'%mpd_url)
	divider()
	VIDEO_ID = input("ENTER VIDEO_ID (Press Enter for Best): ")
	if VIDEO_ID == "":
		VIDEO_ID = "bv"
	
	AUDIO_ID = input("ENTER AUDIO_ID (Press Enter for Best): ")
	if AUDIO_ID == "":
		AUDIO_ID = "ba"
	
	divider()
	print("Downloading Encrypted Video from CDN..")	
	os.system(f'yt-dlp -o "{TEMPORARY_PATH}/encrypted_video.%(ext)s" --no-warnings --external-downloader aria2c --allow-unplayable-formats --no-check-certificate -f {VIDEO_ID} "{mpd_url}" -o "{TEMPORARY_PATH}/encrypted_video.%(ext)s"')
	print("Downloading Encrypted Audio from CDN..")
	os.system(f'yt-dlp -o "{TEMPORARY_PATH}/encrypted_audio.%(ext)s" --no-warnings --external-downloader aria2c --allow-unplayable-formats --no-check-certificate -f {AUDIO_ID} "{mpd_url}"')

def decrypt_content():
	if PLATFORM == "Windows":		
		key_arg = ""
		for items in KEY_ARRAY:
			key_temp = " --key %s"%items
			key_arg += key_temp
			key_temp = ""
		keys = key_arg
			
	else:
		parse_key(KEY_PROMPT)
		
	divider()
	print("Decrypting WideVine DRM.. (Takes some time)")
	osinfo()
	if PLATFORM == "Mac":
		MP4DECRYPT_PATH = "%s/mp4decrypt/mp4decrypt_mac"%FILE_DIRECTORY
	elif PLATFORM == "Windows":
		MP4DECRYPT_PATH = "%s/mp4decrypt/mp4decrypt_win.exe"%FILE_DIRECTORY
	elif PLATFORM == "Linux":
		MP4DECRYPT_PATH = "%s/mp4decrypt/mp4decrypt_linux"%FILE_DIRECTORY
	else:
		MP4DECRYPT_PATH = MP4DECRYPT_PATH = "mp4decrypt"
		
	os.system('%s %s/encrypted_video.mp4 %s/decrypted_video.mp4 %s --show-progress'%(MP4DECRYPT_PATH,TEMPORARY_PATH,TEMPORARY_PATH,keys))
	os.system('%s %s/encrypted_audio.m4a %s/decrypted_audio.m4a %s --show-progress'%(MP4DECRYPT_PATH,TEMPORARY_PATH,TEMPORARY_PATH,keys))
	print("[info] Decryption Complete!")

def merge_content():
	global FILENAME
	FFMPEG_PATH = "%s/ffmpeg.exe"%FILE_DIRECTORY
	divider()
	FILENAME=input("Enter File Name (with extension): \n> ")
	divider()
	print("Merging Files and Processing %s.. (Takes a while)"%FILENAME)
	time.sleep(2)
	if PLATFORM == "Windows":
		os.system('%s -i %s/decrypted_video.mp4 -i %s/decrypted_audio.m4a -c:v copy -c:a copy %s/"%s"'%(FFMPEG_PATH,TEMPORARY_PATH,TEMPORARY_PATH,OUTPUT_PATH,FILENAME))
	else: 
		os.system('ffmpeg --hide-banner -i %s/decrypted_video.mp4 -i %s/decrypted_audio.m4a -c:v copy -c:a copy %s/"%s"'%(TEMPORARY_PATH,TEMPORARY_PATH,OUTPUT_PATH,FILENAME))
		
parser=argparse.ArgumentParser()
parser.add_argument('-mpd', required=False, default="NULL")
parser.add_argument('-license', required=False, default="NULL")
args = parser.parse_args()

MPD_URL = args.mpd
LICENSE_URL = args.license

def manual_input():
	global MPD_URL, LICENSE_URL
	MPD_URL = input("Enter MPD URL: \n> ")
	divider()
	LICENSE_URL = input("Enter License URL: \n> ")
	if PLATFORM == "Windows":
		pass
	else:
		KEY_PROMPT = input("Enter WideVineDecryptor Prompt: \n> ")

osinfo()
divider()
print("**** NARROWVINE by vank0n **** (%s Detected)"%PLATFORM)
divider()

if PLATFORM == "Windows":
	if MPD_URL == "NULL" or LICENSE_URL == "NULL":
		manual_input()
	else:
		pass
else:
	manual_input()
	divider()

if PLATFORM == "Windows":
	divider()
	print("Starting Widevine Proxy.. (DO NOT CLOSE THE PROXY WINDOW!)")
	os.startfile("%s/license_proxy.exe"%FILE_DIRECTORY)
	download_drm_content(MPD_URL)
	divider()
	print("Extracting Widevine Keys..")
	getkeys("%s/encrypted_video.mp4"%TEMPORARY_PATH,LICENSE_URL)
else:
	download_drm_content(MPD_URL)
	divider()
	decrypt_content()
	
decrypt_content()
merge_content()
divider()
print("[info] Process Finished. Final Video File is saved in /output directory.")
os.startfile("%s/%s"%(OUTPUT_PATH,FILENAME))
divider()

delete_choice = input("Delete cache files? (y/n)\ny) Yes (default)\nn) No\ny/n> ")

if delete_choice == "n":
	divider()
else:
	empty_folder(TEMPORARY_PATH)

time.sleep(2)


		
	
