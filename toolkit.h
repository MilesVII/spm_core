/**Seventh Password Manager**
This file provides headers of
main functions that can be 
used by platform-dependent 
code

Created by Miles Seventh
at 14 October, 2019
Disclaimer is provided in README.md
License: [CC-BY-NC-SA] 
(https://creativecommons.org/licenses/by-nc-sa/4.0/)
*****************************/

#pragma once

#include <stdint.h>

#define SPM_HASH_SIZE 64

extern const char* SPM_SALT;

/* Generate hash string from byte array */
void spm_generateHashPresentation(char* destination, uint8_t* source, char* customCharset, int length);
char* spm_generatePassword(const char* master, const char* target, char* customCharset);
void spm_hash(char* destination, const char* source, char* customCharset);
void spm_saltedHash(char* destination, const char* source, char* customCharset);
int spm_maxCharsetSize();