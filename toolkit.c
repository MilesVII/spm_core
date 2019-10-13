/**Seventh Password Manager**
This file provides main 
functions of password manager 
that can be used by 
platform-dependent code

Created by Miles Seventh
at 14 October, 2019
Disclaimer is provided in README.md
License: [CC-BY-NC-SA] 
(https://creativecommons.org/licenses/by-nc-sa/4.0/)
*****************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "toolkit.h"
#include "monocypher.h"

char defaultHashCharset[] = "!@&#0123456789!@&#abcdefghijklmnopqrstuvwxyz!@&#ABCDEFGHIJKLMNOPQRSTUVWXYZ!@&#";
const char* SPM_SALT = "$4lt_";
const int SPM_LENGTH_COMPRESSION = 4; //times, must be power of two

void spm_generateHashPresentation(char* destination, uint8_t* source, char* customCharset, int length){
	char* charset;
	if (customCharset != NULL)
		charset = customCharset;
	else
		charset = defaultHashCharset;

	int l = strlen(charset);
	for (int i = 0; i < length; ++i)
		destination[i] = charset[source[i] % l];
}

char* spm_generatePassword(const char* master, const char* target, char* customCharset){
	char* charset;
	if (customCharset != NULL)
		charset = customCharset;
	else
		charset = defaultHashCharset;

	uint8_t hash[SPM_HASH_SIZE], key0[SPM_HASH_SIZE], key1[SPM_HASH_SIZE];
	int passwordLength = SPM_HASH_SIZE / SPM_LENGTH_COMPRESSION;
	char* password = malloc(sizeof(char) * (passwordLength + 1));

	crypto_blake2b(key0, (uint8_t*)master, strlen(master));
	crypto_blake2b(key1, (uint8_t*)target, strlen(target));
	for (int i = 0; i < SPM_HASH_SIZE; ++i)
		key0[i] += key1[i];
	crypto_blake2b(hash, key0, SPM_HASH_SIZE);
	
	for (int i = 0; i < SPM_HASH_SIZE; ++i){
		if (i > passwordLength - 1)
			break;
		int x = 0;
		for (int j = 0; j < SPM_LENGTH_COMPRESSION; ++j)
			x += hash[i + passwordLength * j];
		x %= strlen(charset);
		password[i] = charset[x];
	}
	password[passwordLength] = '\0';

	crypto_wipe(hash, SPM_HASH_SIZE);
	crypto_wipe(master, strlen(master));
	crypto_wipe(target, strlen(target));
	crypto_wipe(key0, strlen(target));
	crypto_wipe(key1, strlen(target));
	return password;
}

void spm_saltedHash(char* destination, const char* source, char* customCharset){
	uint8_t hash[SPM_HASH_SIZE];
	char* saltedSource = malloc(sizeof(char) * (strlen(source) + strlen(SPM_SALT) + 1));
	strcpy(saltedSource, SPM_SALT);
	strcat(saltedSource, source);

	spm_hash(destination, saltedSource, customCharset);
	free(saltedSource);
}

void spm_hash(char* destination, const char* source, char* customCharset){
	uint8_t hash[SPM_HASH_SIZE];
	//char* r = malloc(sizeof(char) * (SPM_HASH_SIZE + 1));
	crypto_blake2b(hash, (uint8_t*)source, strlen(source));
	spm_generateHashPresentation(destination, hash, customCharset, SPM_HASH_SIZE);
	destination[SPM_HASH_SIZE + 1] = '\0';
}

int spm_maxCharsetSize(){
	return SPM_LENGTH_COMPRESSION * 256;
}