from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

args_encryp = []

#Initialization Vector [0]
args_encryp.append("6AE5fRg46aD8f4g1".encode("utf-8"))

#Bolck length [1]
args_encryp.append(16)

#Key [2]
args_encryp.append("")

def text_encrypt(txt):
	global args_encryp

	print("Password:")
	pass_key = str(input())

	if(len(pass_key) != 16):
		print ("Password length must be 16 characters.")
		exit(1)
	
	args_encryp[2] = pass_key

	encrypter = AES.new(args_encryp[2], AES.MODE_CBC, args_encryp[0])

	encrypt_txt = encrypter.encrypt(pad(txt.encode("utf-8"), args_encryp[1]))

	return encrypt_txt


def text_decrypt(txt):
	global args_encryp

	print("Password:")
	pass_key = str(input())

	if(len(pass_key) != 16):
		print ("Password length must be 16 characters.")
		exit(1)
	
	try:
		args_encryp[2] = pass_key

		decrypter = AES.new(args_encryp[2], AES.MODE_CBC, args_encryp[0])

		decrypt_txt = unpad(decrypter.decrypt(txt.encode("utf-8"), args_encryp[1]).decode("utf-8", "ignore"))
	except:
		print("Invalid password.")
		exit(1)

	return decrypt_txt


def file_encrypt(file):

	with open(file, "r") as f:
		content = f.read()

	encrypt_cont = text_encrypt(content)

	with open(file, "wb") as f:
		f.write(encrypt_cont)

	return encrypt_cont

def file_decrypt(file):

	with open(file, "rb") as f:
		content = f.read()

	decrypt_cont = text_decrypt(content)

	with open(file, "wb") as f:
		f.write(decrypt_cont)

	return decrypt_cont

def file_decrypt(file):

	with open(file, "rb") as f:
		content = f.read()

	decrypt_cont = text_decrypt(content)

	return decrypt_cont