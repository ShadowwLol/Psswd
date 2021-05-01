#include <openssl/evp.h>
#include <openssl/aes.h>
#include <assert.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#define LINE_MAX 3072
#define MIN_CRED_SIZE 3 // Minimum size of credentials

char * path;

int mkpath(char* file_path, mode_t mode) {
	assert(file_path && *file_path);
	for (char* p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
		*p = '\0';
		if (mkdir(file_path, mode) == -1) {
			if (errno != EEXIST) {
				*p = '/';
				return -1;
			}
		}
		*p = '/';
	}
	return 0;
}

int read_cipher(unsigned char *ciphertext, char *cp_len, unsigned char *tag, char *path, char * ciphertextP, char * cp_len_strP, unsigned char * tagP) {
	if (!ciphertext || !cp_len || !tag || !path || !ciphertextP || !cp_len_strP || !tagP)
		return 1;

	FILE *fp = fopen(path, "r");

	if (!fp)
		return 1;

	char line[LINE_MAX];

	int done = 0;

	while (fgets(line, LINE_MAX, fp)) {
		int ll = strlen(line);
		line[--ll] = '\0'; // Removes the \n

		if (ll > 0) {
			if (done == 0)
				strcpy((char *)ciphertext, line); // Buffer overflow if ciphertext can't store the entire line
			else if (line[0] == '/') {
				if (done == 1){
					strcpy(cp_len, line + 1); // + 1 to ignore the / at the start
				}
				else if (done == 2){
					strcpy((char *)tag, line + 1);
				}
				else if (done == 4){
					strcpy((char *)cp_len_strP, line+1);
				}
				else if (done == 5){
					strcpy((char *)tagP, line+1);
				}
				else{
					continue;
				}
			}
			else if (line[0] == '+'){
				strcpy((char *)ciphertextP, line+1);
			}
			done++;
		}
	}

	if (done != 6)
		return 1;

	return 0;
}

void handleErrors(void)
{
	unsigned long errCode;

	printf("An error occurred\n");
	while(errCode = ERR_get_error())
	{
		char *err = ERR_error_string(errCode, NULL);
		printf("%s\n", err);
	}
	abort();
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
				unsigned char *aad, int aad_len,
				unsigned char *key,
				unsigned char *iv, int iv_len,
				unsigned char *ciphertext,
				unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/*
	 * Set IV length if default 12 bytes (96 bits) is not appropriate
	 */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
				unsigned char *aad, int aad_len,
				unsigned char *tag,
				unsigned char *key,
				unsigned char *iv, int iv_len,
				unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	} else {
		/* Verify failed */
		return -1;
	}
}

void help(){
	printf("./Psswd\nHelp:\n\tPsswd <option>\n\tOptions:\n\t\ta, add\tAdds a new account.\n\t\tr	 \tRetrieves an account.\n\t\td, del\tDeletes an account.\n");
	exit(0);
}

void add(char * website){
	if (strlen(website) < MIN_CRED_SIZE){fprintf(stderr, "\033[31m[-] Error: account too short.\033[0m\n"); exit(1);}

	printf("./Psswd {%s}\n", website);

	// Verification
	int lives = 0;
	mpcheck:
	if (lives < 3){
		printf("\nMaster password: ");
		char try[1024];
		fgets(try, 1024, stdin);
		try[strlen(try)-1] = '\0';
		if (strncmp(try, "shadoww", 1024) != 0){
			lives ++;
			goto mpcheck;
		}
	}else{fprintf(stderr, "[-] Error: Max ammount of tries exceeded.\n"); exit(1);}

	char username[1024];
	char password[1024];

	// Defining the aad, key and iv
	static const unsigned char key[] = "01234567890123456789012345678901";
	/* A 128 bit IV */
	static const unsigned char iv[] = "0123456789012345";
	/* Some additional data to be authenticated */
	static const unsigned char aad[] = "Some AAD data";

	unsigned char cipherUsername[1024];
	int cpu_len = 0;
	unsigned char Utag[16];

	unsigned char cipherPassword[1024];
	int cpp_len = 0;
	unsigned char Ptag[16];

	strcat(path, website);
	if (access( path, F_OK ) == 0){fprintf(stderr, "\033[31m[-] Error: Account already exists.\033[0m\n"); exit(1);}
	printf("Username: ");
	fgets(username, 1024, stdin);
	printf("Password: ");
	fgets(password, 1024, stdin);
	if (strlen(username) < MIN_CRED_SIZE || strlen(password) < MIN_CRED_SIZE){fprintf(stderr, "\033[31m[-] Error: Username or password too short.\033[0m\n"); exit(1);}
	username[strlen(username)-1] = '\0';
	password[strlen(password)-1] = '\0';
	//Encrypting username
	cpu_len = gcm_encrypt(username, strlen(username), aad, strlen(aad), key, iv, strlen(iv), cipherUsername, Utag);
	cpp_len = gcm_encrypt(password, strlen(password), aad, strlen(aad), key, iv, strlen(iv), cipherPassword, Ptag);
	FILE * fp = fopen(path, "w");
	fprintf(fp, "%s\n", cipherUsername);
	fputs("/", fp);
	fprintf(fp, "%d\n", cpu_len);
	fputs("/", fp);
	BIO_dump_fp(fp, Utag, 14);
	fputs("+", fp);
	//Encrypting password
	fprintf(fp, "%s\n", cipherPassword);
	fputs("/", fp);
	fprintf(fp, "%d\n", cpp_len);
	fputs("/", fp);
	BIO_dump_fp(fp, Ptag, 14);
	fclose(fp);
	printf("\033[32m[+] Successfully added [%s] account.\033[0m\n", path);
	exit(0);
}

void retrieve(){
	printf("./Psswd\nRetrieve an account.\n");
	int n=0, i=0;
	DIR *d;
	struct dirent *dir;
	d = opendir(path);

	//Determine the number of files
	while((dir = readdir(d)) != NULL) {
		if ( !strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") )
		{

		} else {
			n++;
		}
	}
	rewinddir(d);
	if (n < 1){ exit(1); }

	// Verification
	int lives = 0;
	mpcheck:
	if (lives < 3){
		printf("\nMaster password: ");
		char try[1024];
		fgets(try, 1024, stdin);
		try[strlen(try)-1] = '\0';
		if (strncmp(try, "shadoww", 1024) != 0){
			lives ++;
			goto mpcheck;
		}
	}else{fprintf(stderr, "[-] Error: Max ammount of tries exceeded.\n"); exit(1);}

	char *files[n];

	//Put file names into the array
	while((dir = readdir(d)) != NULL) {
		if ( !strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") )
		{}
		else {
			files[i]= dir->d_name;
			i++;
		}
	}
	rewinddir(d);

	for(i=0; i<n; i++){
		printf("%d. [%s]\n", i+1, files[i]);
	}
	char * input[1];
	FILE * file;
	char * data[2048];
	printf("\n> ");
	fflush(stdin);
	fread(input, sizeof(char),  1, stdin);
	if (atoi(input) && atoi(input) <= n){strcat(path, files[atoi(input)-1]);}
	else{exit(1);}
	unsigned char ciphertext[1024];
	unsigned char tag[1024];
	char cp_len_str[1024];

	unsigned char ciphertextP[1024];
	unsigned char tagP[1024];
	char cp_len_strP[1024];
	read_cipher(ciphertext, cp_len_str, tag, path, ciphertextP, cp_len_strP, tagP);
	int cp_len = atoi(cp_len_str);
	int cp_lenP = atoi(cp_len_strP);
	// Defining the aad, key and iv
	static const unsigned char key[] = "01234567890123456789012345678901";
	/* A 128 bit IV */
	static const unsigned char iv[] = "0123456789012345";
	/* Some additional data to be authenticated */
	static const unsigned char aad[] = "Some AAD data";
	// Decrypting credentials
	unsigned char decryptedtext[1024];
	unsigned char decryptedtextP[1024];
	int decryptedtext_len;
	int decryptedtext_lenP;
	decryptedtext_len = gcm_decrypt(ciphertext, cp_len, aad, strlen(aad), tag, key, iv, strlen(iv), decryptedtext);
	decryptedtext_lenP = gcm_decrypt(ciphertextP, cp_lenP, aad, strlen(aad), tagP, key, iv, strlen(iv), decryptedtextP);
	decryptedtext[cp_len] = '\0';
	decryptedtextP[cp_lenP] = '\0';
	printf("Username: [%s]\nPassword: [%s]\n", decryptedtext, decryptedtextP);
	printf("\033[32m[+] Successfully retrieved [%s] account credentials.\033[0m\n", path);
	exit(0);
}

void delete(){
	printf("./Psswd\nDelete an account\n");
	int n=0, i=0;
	DIR *d;
	struct dirent *dir;
	d = opendir(path);

	//Determine the number of files
	while((dir = readdir(d)) != NULL) {
		if ( !strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") )
		{

		} else {
			n++;
		}
	}
	rewinddir(d);
	if (n < 1){ exit(1); }

	char *files[n];

	//Put file names into the array
	while((dir = readdir(d)) != NULL) {
		if ( !strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") )
		{}
		else {
			files[i]= dir->d_name;
			i++;
		}
	}
	rewinddir(d);

	for(i=0; i<n; i++){
		printf("%d. [%s]\n", i+1, files[i]);
	}
	char * input[1];
	FILE * file;
	char * data[2048];
	printf("\n> ");
	fflush(stdin);
	fread(input, sizeof(char),  1, stdin);
	if (atoi(input) && atoi(input) <= n){strcat(path, files[atoi(input)-1]);}
	else{exit(1);}
	remove(path);
	printf("\033[32m[+] Successfully deleted [%s] account.\033[0m\n", path);
	exit(0);
}

int main(int argc, char * argv[]){
	if (argc < 2){
		fprintf(stderr, "\033[31m[-] Error: arguments required.\033[0m\nCheck \"./Psswd help\" for help.\n");
		exit(1);
	}
	path = getenv("HOME");
	char * dir[19];
	struct stat st = {0};
	strcpy(dir, "/.config/Psswd/accounts/");
	strcat(path, dir);
	if (stat(path, &st) == -1){mkpath(path, 0755);}
	if (strcmp(argv[1], "h") == 0 || strcmp(argv[1], "help") == 0){help();}
	else if (strcmp(argv[1], "a") == 0 || strcmp(argv[1], "add") == 0){if (argc < 3){fprintf(stderr, "\033[31m[-] Error: arguments required.\033[0m\nCheck \"./Psswd help\" for help.\n"); exit(1);} add(strdup(argv[2]));}
	else if (strcmp(argv[1], "r") == 0){retrieve();}
	else if (strcmp(argv[1], "d") == 0 || strcmp(argv[1], "del") == 0){delete();}
	else{
		fprintf(stderr, "\033[31m[-] Error: invalid arguments.\033[0m\nCheck \"./Psswd help\" for help.\n");
		exit(1);
	}

	/*
	char input[1];
	printf("./Psswd\n");
	printf("1. encrypt decrypt string\n2. encrypt decrypt string in file.\n> ");
	fgets(input, 2, stdin);
	if (atoi(input) == 1){
		fflush(stdin);
		getchar();
		char * plaintext[1024];
		printf("Enter string to be encrypted: ");
		fgets(plaintext, 1024, stdin);
		printf("plaintext: %s\n", plaintext);
		printf("strlen(plaintext): %d\n", strlen(plaintext));
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();
		static const unsigned char key[] = "01234567890123456789012345678901";
		static const unsigned char iv[] = "0123456789012345";
		static const unsigned char aad[] = "Some AAD data";
		unsigned char ciphertext[3072];
		unsigned char decryptedtext[3072];
		unsigned char tag[16];
		int decryptedtext_len = 0, ciphertext_len = 0;
		ciphertext_len = gcm_encrypt(plaintext, strlen(plaintext), aad, strlen(aad), key, iv, strlen(iv), ciphertext, tag);
		printf("Ciphertext is:\n");
		BIO_dump_fp(stdout, ciphertext, ciphertext_len);
		printf("Ciphertext var: %s, ciphertext_len: %d\n", ciphertext, ciphertext_len);
		char * path = "file.enc";
		FILE * fp = fopen(path, "w");
		fprintf(fp, "%s\n", ciphertext);
		//BIO_dump_fp(fp, ciphertext, ciphertext_len);
		fputs("/", fp);
		fprintf(fp, "%d\n", ciphertext_len);
		fputs("/", fp);
		BIO_dump_fp(fp, tag, 14);
		fclose(fp);
		printf("Tag is:\n");
		BIO_dump_fp(stdout, tag, 14);
		decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len, aad, strlen(aad), tag, key, iv, strlen(iv), decryptedtext);
		if(decryptedtext_len < 0)
		{
			printf("Decrypted text failed to verify\n");
		}
		else
		{
			decryptedtext[decryptedtext_len] = '\0';
			printf("Decrypted text is:\n");
			printf("%s\n", decryptedtext);
		}
		ERR_free_strings();
	}else if (atoi(input) == 2){
	// enc dec string in file
		unsigned char ciphertext[LINE_MAX];
		unsigned char tag[LINE_MAX];
		char cp_len_str[LINE_MAX];
		char * path = "file.enc";
		FILE * fp = fopen(path, "r");
		static const unsigned char key[] = "01234567890123456789012345678901";
		static const unsigned char iv[] = "0123456789012345";
		static const unsigned char aad[] = "Some AAD data";
		char line[3072];
		unsigned char decryptedtext[LINE_MAX];
		int decryptedtext_len;
		if (read_cipher(ciphertext, cp_len_str, tag, path)) {
			fprintf(stderr, "Error parsing the file\n");
			return 1;
		}

		int cp_len = atoi(cp_len_str);
		// Decrypt
		decryptedtext_len = gcm_decrypt(ciphertext, cp_len, aad, strlen(aad), tag, key, iv, strlen(iv), decryptedtext);

		printf("RECOVERED CREDENTIALS FROM FILE:\n");
		printf("Ciphertext: %s\nCiphertext_len: %d\nTag: %s\n", ciphertext, cp_len, tag);
		decryptedtext[decryptedtext_len] = '\0';
		printf("Decrypted Text: %s\n", decryptedtext);
		return 0;
	}
	*/
	return 0;
}
