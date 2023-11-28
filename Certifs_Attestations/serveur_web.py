#!/usr/bin/python3
# -*- coding: utf-8 -*-
from bottle import route, run, template, request, response,static_file
import qrcode
from PIL import Image
import zbarlight
import subprocess
import os
taille=7462
#################################################################### STEGANO ######################################################################
def vers_8bit(c):
	chaine_binaire = bin(ord(c))[2:]
	return "0"*(8-len(chaine_binaire))+chaine_binaire

def modifier_pixel(pixel, bit):
# on modifie que la composante rouge
	r_val = pixel[0]
	rep_binaire = bin(r_val)[2:]
	rep_bin_mod = (rep_binaire[:-1]) + bit
	r_val = int(rep_bin_mod, 2)
	return tuple([r_val] + list(pixel[1:]))

def recuperer_bit_pfaible(pixel):
	r_val = pixel[0]
	return bin(r_val)[-1]
def cacher(image,message):
	dimX,dimY = image.size
	im = image.load()
	message_binaire = ''.join([vers_8bit(c) for c in message])
	posx_pixel = 0
	posy_pixel = 0
	for bit in message_binaire:
		im[posx_pixel,posy_pixel] = modifier_pixel(im[posx_pixel,posy_pixel],bit)
		posx_pixel += 1
		if (posx_pixel == dimX):
			posx_pixel = 0
			posy_pixel += 1
		assert(posy_pixel < dimY)
def recuperer(image,taille):
	message = ""
	dimX,dimY = image.size
	im = image.load()
	posx_pixel = 0
	posy_pixel = 0
	for rang_car in range(0,taille):
		rep_binaire = ""
		for rang_bit in range(0,8):
			rep_binaire += recuperer_bit_pfaible(im[posx_pixel,posy_pixel])
			posx_pixel +=1
			if (posx_pixel == dimX):
				posx_pixel = 0
				posy_pixel += 1
		message += chr(int(rep_binaire, 2))
	return message

'''def recuperer(image):
	message = ""
	dimX,dimY = image.size
	taille = dimX * dimY // 8
	im = image.load()
	posx_pixel = 0
	posy_pixel = 0
	for rang_car in range(0,taille):
		rep_binaire = ""
		for rang_bit in range(0,8):
			rep_binaire += recuperer_bit_pfaible(im[posx_pixel,posy_pixel])
			posx_pixel +=1
			if (posx_pixel == dimX):
				posx_pixel = 0
				posy_pixel += 1
		message += chr(int(rep_binaire, 2))
	return message'''
#################################################################### creation_attestation ######################################################################
@route('/creation', method='POST')
def creation_attestation():
	contenu_identité = request.forms.get('identite')
	contenu_intitulé_certification = request.forms.get('intitule_certif')
	print('nom prénom :', contenu_identité, ' intitulé de la certification :',
		contenu_intitulé_certification)
		
#################################		
	# Concaténation du nom et prénom de l'étudiant avec l'intitulé de la certification
	infos = contenu_identité + contenu_intitulé_certification
	if len(infos) < 64:# Ajout de caractères '@' pour atteindre une taille de 64 octets
    		for i in range(64 - len(infos)):
        		infos += "@"
	with open("infos.txt", "wb") as f:
    		f.write(infos.encode())

#################################
	#TimeStamp
	command1 = subprocess.Popen("openssl ts -query -data infos.txt -no_nonce -sha256 -cert -out time.tsq",shell=True,stdout=subprocess.PIPE)
	stdout,stderr = command1.communicate()
	command2 = subprocess.Popen("curl -H \"Content-Type: application/timestamp-query\" --data-binary '@time.tsq' https://freetsa.org/tsr > time.tsr",shell=True,stdout=subprocess.PIPE)
	stdout,stderr = command2.communicate()
	command3 = subprocess.Popen('openssl base64 -in time.tsr -out time_64.tsr',shell=True,stdout=subprocess.PIPE)
	stdout,stderr = command3.communicate()
	with open("time_64.tsr","rb") as f:
    		timestamp = f.read()

#################################
	#Texte image finale
	texte_ligne = "Attestation de réussite|délivrée à " + contenu_identité
	command4 = subprocess.Popen("curl -o texte.png \"http://chart.apis.google.com/chart\" --data-urlencode \"chst=d_text_outline\" --data-urlencode \"chld=000000|56|h|FFFFFF|b|" + texte_ligne + "\"", shell=True, stdout=subprocess.PIPE)
	stdout,stderr = command4.communicate()
	#Redimensionnement avec ImageMagick de l'image texte.png
	command5 = subprocess.Popen("mogrify -resize 1000x600 texte.png",shell=True,stdout=subprocess.PIPE)
	stdout,stderr = command5.communicate()
	
#################################
	#QRCODE
	#Signature du fichier infos.txt
	command6 = subprocess.Popen("openssl dgst -sha256 -sign cle_CA.pem infos.txt | openssl base64 -out signature_64.tsr", shell=True, stdout=subprocess.PIPE)
	stdout,stderr = command6.communicate()
	with open("signature_64.tsr", "rb") as f:
    		signature = f.read()
	signature=signature.decode()
	nom_fichier = "qrcode.png"
	qr = qrcode.make(signature)
	qr.save(nom_fichier, scale=2)

	#Redimensionnement avec ImageMagick de l'image qrcode.png
	command7=subprocess.Popen("mogrify -resize 210x210 qrcode.png",shell=True,stdout=subprocess.PIPE)
	stdout,stderr=command7.communicate()
	
#################################
	#Insertion de texte.png+fond_attestation.png+qrcode.png pour avoir l'image attestation.png
	command8=subprocess.Popen("composite -gravity center texte.png fond_attestation.png fond_text.png",shell=True,stdout=subprocess.PIPE)
	stdout,stderr=command8.communicate()
	command9=subprocess.Popen("composite -geometry +1418+934 qrcode.png fond_text.png attestation.png",shell=True,stdout=subprocess.PIPE)
	stdout,stderr=command9.communicate()
	
#################################
	#Dissimulation des infos et de la timestamp dans l'image
	image = Image.open("attestation.png")
	cacher(image,infos+timestamp.decode())
	image.save("attest_final.png")
	response.set_header('Content-type', 'image/png')
	with open('attest_final.png', 'rb') as f:
    		contenu = f.read()

	return contenu

	
	


#################################################################### verification_attestation ######################################################################
@route('/verification', method='POST')
def vérification_attestation():
#################################
	#extraction du contenu stegano
	contenu_image = request.files.get('image')
	contenu_image.save('verif_attest.png',overwrite=True)
	attest_a_verif = Image.open("verif_attest.png")
	msg = recuperer(attest_a_verif,taille)
	timestamp = msg[64:]
	identite = msg[:64]

#################################
	#conversion de timestamp et identite
	with open("time_64.tsr", "wb") as f:
    		f.write(timestamp.encode())
	command1 = subprocess.Popen('openssl base64 -d -in time_64.tsr -out time_decode.tsr',shell=True,stdout=subprocess.PIPE)
	stdout,stderr = command1.communicate()
	with open("time_decode.tsr", "rb") as f:
    		timestamp = f.read() 
	with open("timestamp.tsr","wb") as f:
		f.write(timestamp)
	with open("infos1.txt","wb") as f:
		f.write(identite.encode())
	
	
#################################	
	#verification du timestamp et du qrcode(signature)
	command2=subprocess.Popen("openssl ts -query -data infos1.txt -no_nonce -sha256 -cert -out infos1.tsq",shell=True,stdout=subprocess.PIPE)
	stdout,stderr =command2.communicate()
	command3=subprocess.Popen("openssl ts -verify -in timestamp.tsr -queryfile infos1.tsq -CAfile freetsa.pem -untrusted tsa.crt",shell=True,stdout=subprocess.PIPE)
	stdout,stderr=command3.communicate()
	validite_timestamp=b'Verification: OK\n'
	
#################################
	#Affichage du résultat
	if stdout==validite_timestamp:
		resultat="Timestamp valide!"
		qrImage = attest_a_verif.crop((1418,934,1418+210,934+210))
		qrImage.save("qrcode2.png", "PNG")
		image=Image.open("qrcode2.png")
		data = zbarlight.scan_codes(['qrcode'], image)[0]
		with open("sign_64","wb") as f:
			f.write(data)
		command4=subprocess.Popen("openssl base64 -d -in sign_64 -out sign.txt",shell=True,stdout=subprocess.PIPE)
		stdout,stderr=command4.communicate()
		command5=subprocess.Popen("openssl dgst -sha256 -verify clepub_CA.pem -signature sign.txt infos1.txt",shell=True,stdout=subprocess.PIPE)
		stdout,stderr=command5.communicate()
		validite_certificat=b'Verified OK\n'
		if stdout==validite_certificat:
			resultat="Certificat valide!"
		else:
			resultat="Certificat invalide!"	
	else:
		resultat="Timestamp invalide!"
	
	#Renvoi de la réponse
	response.set_header('Content-type', 'text/plain')
	
	return resultat


run(host='0.0.0.0',port=8080,debug=True)
