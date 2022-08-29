import crypter
import qrcode_terminal
import qrcode
import argparse
import hashlib
import struct
import hmac
import time
import os
import string

def parse():
	parser = argparse.ArgumentParser(
		prog = "python3 ft_otp.py", 
		description = "The ft_otp program allows you to register an initial password, and is capable of generating a new password each time it is requested."
	)
	parser.add_argument("-g", metavar="file", help="With the -g option, the program will receive as an argument a hexadecimal key of at least 64 characters. The program will safely store this key in a file called ft_otp.key, which will be encrypted", type=str)
	parser.add_argument("-k", metavar="file", help="With the -k option, the program will generate a new temporary password and print it to standard output", type=str)
	parser.add_argument("-qr", metavar="file", help="With the -qr option, the program will generate a new temporary password and print it like a QR code in to standard output", type=str)
	args = parser.parse_args()
	return args.__dict__

def file_checker(file):

	if(not os.path.isfile(file) or not os.access(file, os.R_OK)):
		print("File doesn't exist or it's not accesible.")
		exit(1)

	with open(file, "r") as f:
		f_cont = f.read()

	if(all(c in string.hexdigits for c in f_cont) and len(f_cont) >= 64):
		return True
	else:
		print("File content is not hexadecimal or doesn't contains, at leats, 64 characters.")
		exit(1)


def otp_generator(f_cont):

	f_cont_b = bytes.fromhex(f_cont)
	time_i = int(time.time() //30)
	time_b = struct.pack(">Q", time_i)

	hash_a = hmac.digest(f_cont_b, time_b, hashlib.sha1)

	pos = hash_a[19] & 15

	otp_key = struct.unpack(">I", hash_a[pos : (pos+4)])[0]
	otp_key = (otp_key & 0x7FFFFFFF) % 1000000

	return "{:06d}".format(otp_key)


if __name__ == "__main__":
	arg = parse()
	gf_path = arg.get("g")
	gk_path = arg.get("k")
	gqr_path = arg.get("qr")


	if (gf_path != None):
		if (file_checker(gf_path)):
			with open(gf_path, "r") as f:
				gf_cont = f.read()
			with open("ft_otp.key", "w") as f:
				f.write(gf_cont)
			crypter.file_encrypt("ft_otp.key")

	elif (gk_path != None or gqr_path != None):

		f_path = gk_path if (gk_path != None) else gqr_path

		if(not os.path.isfile(f_path) or not os.access(f_path, os.R_OK)):
			print("File doesn't exist or it's not accesible.")
			exit(1)

		f_cont = crypter.file_reader(f_path)

		if (gk_path != None):
			print("\nOTP:		" + otp_generator(f_cont))

		else:
			print("Scan QR code:\n")
			qrcode_terminal.draw(f_cont)

	else:
		try:
			os.system("python3 ft_opt.py -h")
		except:
			print("please introduce valid parameters.")
			pass
		exit(1)