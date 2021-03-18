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
const int SPM_LENGTH_COMPRESSION = 4; //times, must be power of two; Can only be 1, 2, 4 or 8

const int SPM_ARGON_BLOCKS = 262144;
const int SPM_ARGON_ITERATIONS = 7;

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

char* spm_generatePassword(char* master, char* target, char* customCharset){
	char* charset;
	if (customCharset != NULL)
		charset = customCharset;
	else
		charset = defaultHashCharset;

	uint8_t hash[SPM_HASH_SIZE];
	int passwordLength = SPM_HASH_SIZE / SPM_LENGTH_COMPRESSION;
	char* password = malloc(sizeof(char) * (passwordLength + 1));

	void* workArea = malloc(1024 * SPM_ARGON_BLOCKS);
	crypto_argon2i_general(hash, SPM_HASH_SIZE, workArea, SPM_ARGON_BLOCKS, SPM_ARGON_ITERATIONS, 
	                       master, strlen(master), 
	                       SPM_SALT, strlen(SPM_SALT), 
	                       0, 0, target, strlen(target));
	free(workArea);

	for (int i = 0; i < passwordLength; ++i){
		switch(SPM_LENGTH_COMPRESSION){
		case (1): {
			//64 characters in password
			uint8_t x = hash[i] % strlen(charset);
			password[i] = charset[x];
			break;
		}
		case (2):{
			//32 characters in passwordstrlen(charset);
			uint16_t x = ((uint16_t*)hash)[i];
			x %= strlen(charset);
			password[i] = charset[x];
			break;
		}
		case (4):{
			//16 characters in password
			uint32_t x = ((uint32_t*)hash)[i];
			x %= strlen(charset);
			password[i] = charset[x];
			break;
		}
		case (8):{
			//8 characters in password
			uint64_t x = ((uint64_t*)hash)[i];
			x %= strlen(charset);
			password[i] = charset[x];
			break;
		}
		deafult:
			printf("E: Invalid SPM_LENGTH_COMPRESSION constant");
			assert(0);
			break;
		}
	}
	password[passwordLength] = '\0';

	crypto_wipe(hash, SPM_HASH_SIZE);
	crypto_wipe(master, strlen(master));
	crypto_wipe(target, strlen(target));
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