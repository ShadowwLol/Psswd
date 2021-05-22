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
#include <termios.h>
#include <limits.h>

#define MIN_CRED_SIZE 3 // Minimum size of credentials
#define TAG_SIZE 16

#define CCLEAR "\033[0m"
#define RED    "\033[31m"
#define GREEN  "\033[32m"
#define YELLOW "\033[33m"
#define BLUE   "\033[34m"



#define listFiles(P)\
{\
	int n=0, i=0;\
	DIR *d;\
	struct dirent *dir;\
	d = opendir(P);\
	while((dir = readdir(d)) != NULL) {\
		if ( !strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") )\
		{\
		} else {\
			n++;\
		}\
	}\
	rewinddir(d);\
	if (n < 1){ exit(EXIT_FAILURE); }\
	char *files[n];\
	while((dir = readdir(d)) != NULL) {\
		if ( !strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") )\
		{}\
		else {\
			files[i]= dir->d_name;\
			i++;\
		}\
	}\
	rewinddir(d);\
	for(i=0; i<n; i++){\
		printf("%d. [%s]\n", i+1, files[i]);\
	}\
	char input[1];\
	FILE * file;\
	printf("\n> ");\
	fflush(stdin);\
	fread(input, sizeof(char),  1, stdin);\
	if (atoi(input) && atoi(input) <= n){strcat(P, files[atoi(input)-1]);}\
	else{exit(EXIT_FAILURE);}\
}

int mkpath(char* file_path, mode_t mode) {
	assert(file_path && *file_path);
	for (char* p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
		*p = '\0';
		if (mkdir(file_path, mode) == -1) {
			if (errno != EEXIST) {
				*p = '/';
				return EXIT_FAILURE;
			}
		}
		*p = '/';
	}
	return EXIT_SUCCESS;
}

int read_master(unsigned char *ciphertext, char *cp_len, unsigned char *tag, char *path) {
    if (!ciphertext || !cp_len || !tag || !path)
        return EXIT_FAILURE;

    FILE *fp = fopen(path, "r");

    if (!fp){return EXIT_FAILURE;}

    char line[LINE_MAX];

    int done = 0;

    while (fgets(line, LINE_MAX, fp)) {
        int ll = strlen(line);
        line[--ll] = '\0'; // Removes the \n

        if (ll > 0) {
            if (done == 0)
                strcpy((char *)ciphertext, line); // Buffer overflow if ciphertext can't store the entire line
            else if (line[0] == '/') {
                if (done == 1)
                    strcpy(cp_len, line + 1); // + 1 to ignore the / at the start
                else if (done == 2)
                    strcpy((char *)tag, line + 1);
                else
                    continue;
            }
            done++;
        }
    }

    if (done != 3){return EXIT_FAILURE;}

    return EXIT_SUCCESS;
}

int read_cipher(unsigned char *ciphertext, char *cp_len, unsigned char *tag, char *path, char * ciphertextP, char * cp_len_strP, unsigned char * tagP) {
	if (!ciphertext || !cp_len || !tag || !path || !ciphertextP || !cp_len_strP || !tagP)
		return EXIT_FAILURE;

	FILE *fp = fopen(path, "r");

	if (!fp)
		return EXIT_FAILURE;

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

	if (done != 6){return EXIT_FAILURE;}

	return EXIT_SUCCESS;
}

void handleErrors(void)
{
	unsigned long errCode;

	printf("An error occurred\n");
	while((errCode = ERR_get_error()))
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
		return EXIT_FAILURE;
	}
}

int pStartup(char * p, char * mP, char * mPS, const unsigned char key[], const unsigned char iv[], const unsigned char aad[]){
	char pass1[LINE_MAX];
	char pass2[LINE_MAX];
	struct termios saved_attributes;
	struct termios term;

	printf("[+] Successfully built Psswd.\n");
	mkpath(p, 0755);
	printf("\033[96m./Psswd\033[0m\n");
	pst:
	printf("%sEnter Master Password: %s", YELLOW, CCLEAR);

	tcgetattr(STDIN_FILENO,&saved_attributes);
	term = saved_attributes;
	term.c_lflag = term.c_lflag ^ ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &term);

	fgets(mPS, LINE_MAX, stdin);
	if (strlen(mPS) < 3){tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes); fprintf(stderr, "\n%s[-] Error: Master Password too short.%s\n", RED, CCLEAR); goto pst;}
	strcpy(pass1, mPS);

	tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);

	printf("\n%sRe-enter Master Password: %s", YELLOW, CCLEAR);

	tcgetattr(STDIN_FILENO,&saved_attributes);
	term = saved_attributes;
	term.c_lflag = term.c_lflag ^ ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &term);

	fgets(mPS, LINE_MAX, stdin);
	strcpy(pass2, mPS);
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
	if (strcmp(pass1, pass2) != 0){fprintf(stderr, "\n%s[-] Error: passwords do not match.%s\n", RED, CCLEAR); goto pst;}
	mPS[strlen(mPS)-1] = '\0';

	unsigned char cipher[NAME_MAX];
	int cp_len = 0;
	unsigned char tag[TAG_SIZE];

	//Encrypting Master Password
	cp_len = gcm_encrypt(mPS, strlen(mPS), aad, strlen(aad), key, iv, strlen(iv), cipher, tag);
	FILE * fp = fopen(mP, "w");
	fprintf(fp, "%s\n", cipher);
	fputs("/", fp);
	fprintf(fp, "%d\n", cp_len);
	fputs("/", fp);
	BIO_dump_fp(fp, tag, 14);
	fclose(fp);
	return EXIT_SUCCESS;
}

int pLoad(char * mP, char * mPS, const unsigned char key[], const unsigned char iv[], const unsigned char aad[]){
	char line[LINE_MAX];
	char pass1[LINE_MAX];
	printf("[+] Successfully loaded Psswd.\n");
	FILE * fptr = fopen(mP, "r");
	while (fgets(line, LINE_MAX, fptr)){}
	fclose(fptr);
	strcpy(mPS, line);

	unsigned char ciphertext[LINE_MAX];
	unsigned char tag[LINE_MAX];
	char cp_len_str[LINE_MAX];

	read_master(ciphertext, cp_len_str, tag, mP);
	int cp_len = atoi(cp_len_str);
	// Decrypting credentials
	unsigned char decryptedtext[LINE_MAX];
	int decryptedtext_len;
	decryptedtext_len = gcm_decrypt(ciphertext, cp_len, aad, strlen(aad), tag, key, iv, strlen(iv), decryptedtext);
	decryptedtext[cp_len] = '\0';

	// Verification
	// Echo management
	struct termios saved_attributes;
	struct termios term;
	int lives = 0;
	mpcheck:
	if (lives < 3){
		printf("\n%sMaster password: %s", YELLOW, CCLEAR);

		tcgetattr(STDIN_FILENO,&saved_attributes);
		term = saved_attributes;
		term.c_lflag = term.c_lflag ^ ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &term); // Echo off

		char try[LINE_MAX];
		fgets(try, LINE_MAX, stdin);
		try[strlen(try)-1] = '\0';
		if (strcmp(try, decryptedtext) != 0){
			lives ++;
			tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes); // Echo on
			goto mpcheck;
		}else{tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);}
	}else{tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes); fprintf(stderr, "\n%s[-] Error: Max ammount of tries exceeded.%s\n", RED, CCLEAR); exit(EXIT_FAILURE);}
	return EXIT_SUCCESS;
}

void help(){
	printf("\nHelp:\n\tPsswd <option>\n\tOptions:\n\t\ta, add\tAdds a new account.\n\t\tr	 \tRetrieves an account.\n\t\td, del\tDeletes an account.\n");
	exit(EXIT_SUCCESS);
}

void add(char P[], char * website, const unsigned char key[], const unsigned char iv[], const unsigned char aad[]){
	if (strlen(website) < MIN_CRED_SIZE){fprintf(stderr, "%s[-] Error: account too short.%s\n", RED, CCLEAR); exit(EXIT_FAILURE);}

	printf("\n\033[96mAdd a website {%s}\033[0m\n", website);
	char username[NAME_MAX];
	char password[NAME_MAX];
	unsigned char cipherUsername[NAME_MAX];
	int cpu_len = 0;
	unsigned char Utag[16];

	unsigned char cipherPassword[NAME_MAX];
	int cpp_len = 0;
	unsigned char Ptag[16];

	strcat(P, website);
	if (access( P, F_OK ) == 0){fprintf(stderr, "%s[-] Error: Account already exists.%s\n", RED, CCLEAR); exit(EXIT_FAILURE);}
	printf("Username: ");
	fgets(username, NAME_MAX, stdin);
	printf("Password: ");

	// Echo management
	struct termios saved_attributes;
	struct termios term;

	tcgetattr(STDIN_FILENO,&saved_attributes);
	term = saved_attributes;
	term.c_lflag = term.c_lflag ^ ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &term); // Echo off

	fgets(password, NAME_MAX, stdin);

	tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes); // Echo on

	if (strlen(username) < MIN_CRED_SIZE || strlen(password) < MIN_CRED_SIZE){fprintf(stderr, "%s[-] Error: Username or password too short.%s\n", RED, CCLEAR); exit(EXIT_FAILURE);}
	username[strlen(username)-1] = '\0';
	password[strlen(password)-1] = '\0';
	//Encrypting username
	cpu_len = gcm_encrypt(username, strlen(username), aad, strlen(aad), key, iv, strlen(iv), cipherUsername, Utag);
	cpp_len = gcm_encrypt(password, strlen(password), aad, strlen(aad), key, iv, strlen(iv), cipherPassword, Ptag);
	FILE * fp = fopen(P, "w");
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
	printf("\n%s[+] Successfully added [%s] account.%s\n",GREEN, P, CCLEAR);
	exit(EXIT_SUCCESS);
}

void retrieve(char P[], const unsigned char key[], const unsigned char iv[], const unsigned char aad[]){
	printf("\n\033[96mRetrieve an account.\033[0m\n");
	listFiles(P);
	char * data[2048];
	unsigned char ciphertext[1024];
	unsigned char tag[1024];
	char cp_len_str[1024];

	unsigned char ciphertextP[1024];
	unsigned char tagP[1024];
	char cp_len_strP[1024];
	read_cipher(ciphertext, cp_len_str, tag, P, ciphertextP, cp_len_strP, tagP);
	int cp_len = atoi(cp_len_str);
	int cp_lenP = atoi(cp_len_strP);
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
	printf("%s[+] Successfully retrieved [%s] account credentials.%s\n", GREEN, P, CCLEAR);
	// Echo management
	struct termios saved_attributes;
	struct termios term;

	tcgetattr(STDIN_FILENO,&saved_attributes);
	term = saved_attributes;
	term.c_lflag = term.c_lflag ^ ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &term); // Echo off

	char c;
	while((c = getchar()) != '\n' && c != EOF);
	getchar();

	printf("\e[1;1H\e[2J"); // Clear the screen
	printf("\033[96m./Psswd\033[0m\n");
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes); // Echo on
	exit(EXIT_SUCCESS);
}

void delete(char p[]){
	printf("\n\033[96mDelete an account\033[0m\n");
	listFiles(p);
	remove(p);
	printf("%s[+] Successfully deleted [%s] account.%s\n", GREEN, p, CCLEAR);
	exit(EXIT_SUCCESS);
}

int main(int argc, char * argv[]){
	printf("\033[96m%s\033[0m\n", argv[0]);
	if (argc < 2){
		fprintf(stderr, "%s[-] Error: arguments required.%s\nCheck \"%s help\" for help.\n", RED, CCLEAR, argv[0]);
		exit(EXIT_FAILURE);
	}

	// Defining the aad, key and iv
	const unsigned char key[] = "01234567890123456789012345678901";
	/* A 128 bit IV */
	const unsigned char iv[] = "0123456789012345";
	/* Some additional data to be authenticated */
	const unsigned char aad[] = "Some AAD data";

	char * path;
	char  * masterPath;
	masterPath = getenv("HOME"); // Unix exclusive
	path = getenv("HOME");      // Unix exclusive
	char masterP[PATH_MAX];
	char P[PATH_MAX];
	struct stat st = {0};
	struct stat buffer;
	strcpy(P, path);
	strcat(P, "/.config/Psswd/accounts/");
	strcpy(masterP, masterPath);
	strcat(masterP, "/.config/Psswd/details");
	char * mPS; // Master Password                                No password                 /      With Password
	if (stat(P, &st) == -1 || stat(masterP,&buffer) == -1){pStartup(P, masterP, &mPS, key, iv, aad);}else{pLoad(masterP, &mPS, key, iv, aad);}
	if (strcmp(argv[1], "h") == 0 || strcmp(argv[1], "help") == 0){help();}
	else if (strcmp(argv[1], "a") == 0 || strcmp(argv[1], "add") == 0){(argc < 3) ? fprintf(stderr, "\n%s[-] Error: arguments required.%s\nCheck \"%s help\" for help.\n", RED, CCLEAR, argv[0]), exit(EXIT_FAILURE) : add(P, strdup(argv[2]), key, iv, aad);}
	else if (strcmp(argv[1], "r") == 0 || strcmp(argv[1], "retrieve") == 0){retrieve(P, key, iv, aad);}
	else if (strcmp(argv[1], "d") == 0 || strcmp(argv[1], "del") == 0){delete(P);}
	else{
		fprintf(stderr, "\n%s[-] Error: invalid arguments.%s\nCheck \"%s help\" for help.\n", RED, CCLEAR, argv[0]);
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}