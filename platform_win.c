/**Seventh Password Manager**
This file provides 
platform-dependent
implementation for M$ Windows
systems

Created by Miles Seventh
at 14 October, 2019
Disclaimer is provided in README.md
License: [CC-BY-NC-SA] 
(https://creativecommons.org/licenses/by-nc-sa/4.0/)
*****************************/

#include "windows.h"
#include "stdint.h"
#include "string.h"
#include "stdio.h"
#include "stdbool.h"
#include "toolkit.h"
#include "monocypher.h"

const char* CUSTOM_CHARSET_FILE = "spm_cc.txt";
const char* SAVED_TARGETS_FILE = ".spm_at";
#define MAX_REGISTERED_TARGETS 256
char registeredTargets[SPM_HASH_SIZE * MAX_REGISTERED_TARGETS + 1];

void platform_clipboard(char* text){
	int size = strlen(text) + 1;
	if (OpenClipboard(0)){
		EmptyClipboard();
		HGLOBAL data = GlobalAlloc(GMEM_MOVEABLE, sizeof(char) * size);
		memcpy(GlobalLock(data), text, sizeof(char) * size);
		GlobalUnlock(data);
		SetClipboardData(CF_TEXT, data);
		CloseClipboard();
	}
}

int main(int argc, char* args[]){
	if (argc < 3){
		printf("%s\n%s%s", "usage: spm <master_password> <auth_target> -r(egister) | -c(heck)", 
		                   "      custom charset should be stored in the first line of ", CUSTOM_CHARSET_FILE);
		exit(0);
	}
	bool registering = false, checking = false;
	if (argc >= 4){
		if (args[3][1] == 'r')
			registering = true;
		else if (args[3][1] == 'c')
			checking = true;
	}

	char* charset = NULL;
	FILE* charsetFile = fopen(CUSTOM_CHARSET_FILE, "r");
	int maxCharsetSize = spm_maxCharsetSize();
	char* customCharsetData = malloc(sizeof(char) * maxCharsetSize);
	if (charsetFile != NULL){
		if (!feof(charsetFile)){
			fgets(customCharsetData, maxCharsetSize, charsetFile);
			charset = customCharsetData;
		}
		fclose(charsetFile);
	}

	if (checking || registering){
		FILE* authTargetsFile = fopen(SAVED_TARGETS_FILE, "a+");
		int offset = 0;
		char targetHash[SPM_HASH_SIZE];
		spm_saltedHash(targetHash, args[2], charset);
		for (; !feof(authTargetsFile); offset += SPM_HASH_SIZE){
			char* i = registeredTargets;
			char* loaded = fgets(i + offset, SPM_HASH_SIZE + 1, authTargetsFile);
			if (loaded == NULL)
				break;
			if (strncmp(loaded, targetHash, SPM_HASH_SIZE) == 0)
				goto TARGET_ALREADY_REGISTERED;
		}
		if (registering){
			fwrite(targetHash, sizeof(char), SPM_HASH_SIZE, authTargetsFile);
			printf("%s\n", "Authorization target registration successful");
		} else {
			printf("%s\n", "Authorization target unknown. Use -r flag to register new target");
			exit(0);
		}

TARGET_ALREADY_REGISTERED:
		fclose(authTargetsFile);
	}
	char* password = spm_generatePassword(args[1], args[2], charset);
	platform_clipboard(password);

	crypto_wipe(password, strlen(password));
	free(password);
	free(customCharsetData);

	printf("%s\n", "Done");

	return 0;
}
