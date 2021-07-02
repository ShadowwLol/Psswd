#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <assert.h>
#include <openssl/err.h>
#include <bsd/string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>
#include <limits.h>
#include <zip.h>

#define MIN_CRED_SIZE 3 // Minimum size of credentials
#define TAG_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define AAD_SIZE 25

#define ZIP_NAME "Psswd-resources.zip"

#define CCLEAR "\033[0m"
#define RED    "\033[31m"
#define GREEN  "\033[32m"
#define YELLOW "\033[33m"
#define PURPLE "\033[35m"

static char k[ PATH_MAX ];
static int root_len = 0;
static struct zip *z = NULL;

//#define CLEAR_SCREEN printf("\e[1;1H\e[2J");
//#define CLEAR_SCREEN printf("%c2J", 27);
#define GET_HOME getenv("HOME");

#define err(msg)\
{\
	fprintf(stderr, "\n%s[-] Error: ", RED);\
	perror(msg);\
	fprintf(stderr, "%s", CCLEAR);\
	exit(EXIT_FAILURE);\
}

#define ECHO_ON()\
{\
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);\
}

#define ECHO_OFF()\
{\
	tcgetattr(STDIN_FILENO,&saved_attributes);\
	term = saved_attributes;\
	term.c_lflag = term.c_lflag ^ ECHO;\
	tcsetattr(STDIN_FILENO, TCSANOW, &term);\
}

#define listFiles(P)\
{\
	int n=0, i=0;\
	DIR *d;\
	struct dirent *dir;\
	d = opendir(P);\
	while((dir = readdir(d)) != NULL) {\
		if ( !strncmp(dir->d_name, ".", 1) || !strncmp(dir->d_name, "..", 2) )\
		{\
		} else {\
			n++;\
		}\
	}\
	rewinddir(d);\
	if (n < 1){ exit(EXIT_FAILURE); }\
	char *files[n];\
	while((dir = readdir(d)) != NULL) {\
		if ( !strncmp(dir->d_name, ".", 1) || !strncmp(dir->d_name, "..", 2) )\
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
	printf("\n> ");\
	fflush(stdin);\
	fread(input, sizeof(char),  1, stdin);\
	if (atoi(input) && atoi(input) <= n){strlcat(P, files[atoi(input)-1], PATH_MAX);}\
	else{exit(EXIT_FAILURE);}\
}

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void ClearScreen()
{
  HANDLE                     hStdOut;
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  DWORD                      count;
  DWORD                      cellCount;
  COORD                      homeCoords = { 0, 0 };

  hStdOut = GetStdHandle( STD_OUTPUT_HANDLE );
  if (hStdOut == INVALID_HANDLE_VALUE) return;

  /* Get the number of cells in the current buffer */
  if (!GetConsoleScreenBufferInfo( hStdOut, &csbi )) return;
  cellCount = csbi.dwSize.X *csbi.dwSize.Y;

  /* Fill the entire buffer with spaces */
  if (!FillConsoleOutputCharacter(
    hStdOut,
    (TCHAR) ' ',
    cellCount,
    homeCoords,
    &count
    )) return;

  /* Fill the entire buffer with the current colors and attributes */
  if (!FillConsoleOutputAttribute(
    hStdOut,
    csbi.wAttributes,
    cellCount,
    homeCoords,
    &count
    )) return;

  /* Move the cursor home */
  SetConsoleCursorPosition( hStdOut, homeCoords );
}

#else // !_WIN32
#include <unistd.h>
#include <term.h>

void ClearScreen()
{
  if (!cur_term)
  {
     int result;
     setupterm( NULL, STDOUT_FILENO, &result );
     if (result <= 0) return;
  }

   putp( tigetstr( "clear" ) );
}
#endif




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
                strlcpy((char *)ciphertext, line, LINE_MAX); // Buffer overflow if ciphertext can't store the entire line
            else if (line[0] == '/') {
				switch(done){
					case 1:
					strlcpy(cp_len, line + 1, LINE_MAX); // + 1 to ignore the / at the start
					break;
					case 2:
					strlcpy((char *)tag, line + 1, LINE_MAX);
					break;
					default:
					continue;
				}
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
				strlcpy((char *)ciphertext, line, LINE_MAX); // Buffer overflow if ciphertext can't store the entire line
			else if (line[0] == '/') {
				switch(done){
					case 1:
					strlcpy(cp_len, line + 1, LINE_MAX); // + 1 to ignore the / at the start
					break;
					case 2:
					strlcpy((char *)tag, line + 1, LINE_MAX);
					break;
					case 4:
					strlcpy((char *)cp_len_strP, line+1, LINE_MAX);
					break;
					case 5:
					strlcpy((char *)tagP, line+1, LINE_MAX);
					break;
					default:
					continue;
				}
			}
			else if (line[0] == '+'){
				strlcpy((char *)ciphertextP, line+1, LINE_MAX);
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

int pStartup(char * p, char * mP, char * mPS, unsigned char key[], unsigned char iv[], unsigned char aad[]){
	char pass1[LINE_MAX];
	char pass2[LINE_MAX];
	struct termios saved_attributes;
	struct termios term;

	printf("[+] Successfully built Psswd.\n");
	mkpath(p, 0755);
	printf("%s./Psswd%s\n", PURPLE, CCLEAR);
	pst:
	printf("%sEnter Master Password: %s", YELLOW, CCLEAR);

	ECHO_OFF();

	fgets(mPS, LINE_MAX, stdin);
	if (strlen(mPS) < 3){ECHO_ON(); err("Master Password too short.\n"); goto pst;}
	strlcpy(pass1, mPS, LINE_MAX);

	ECHO_ON();

	printf("\n%sRe-enter Master Password: %s", YELLOW, CCLEAR);

	ECHO_OFF();

	fgets(mPS, LINE_MAX, stdin);
	strlcpy(pass2, mPS, LINE_MAX);
	ECHO_ON();
	if (strncmp(pass1, pass2, LINE_MAX) != 0){err("Passwords do not match.\n"); goto pst;}
	mPS[strlen(mPS)-1] = '\0';

	unsigned char cipher[NAME_MAX];
	int cp_len = 0;
	unsigned char tag[TAG_SIZE];

	//Encrypting Master Password

	cp_len = gcm_encrypt((unsigned char *)mPS, strlen(mPS), aad, strlen((const char *)aad), key, iv, strlen((const char *)iv), cipher, tag);
	FILE * fp = fopen(mP, "w");
	fprintf(fp, "%s\n", cipher);
	fputs("/", fp);
	fprintf(fp, "%d\n", cp_len);
	fputs("/", fp);
	BIO_dump_fp(fp, (const char *)tag, 14);
	fclose(fp);
	return EXIT_SUCCESS;
}

int pLoad(char * mP, char * mPS, unsigned char key[], unsigned char iv[], unsigned char aad[]){
	char line[LINE_MAX];
	printf("[+] Successfully loaded Psswd.\n");
	FILE * fptr = fopen(mP, "r");
	while (fgets(line, LINE_MAX, fptr)){}
	fclose(fptr);
	strlcpy(mPS, line, LINE_MAX);

	unsigned char ciphertext[LINE_MAX];
	unsigned char tag[LINE_MAX];
	char cp_len_str[LINE_MAX];

	read_master(ciphertext, cp_len_str, tag, mP);
	int cp_len = atoi(cp_len_str);
	// Decrypting credentials
	unsigned char decryptedtext[LINE_MAX];
	gcm_decrypt(ciphertext, cp_len, aad, strlen((const char *)aad), tag, key, iv, strlen((const char *)iv), decryptedtext);
	decryptedtext[cp_len] = '\0';

	// Verification
	// Echo management
	struct termios saved_attributes;
	struct termios term;
	int lives = 0;
	mpcheck:
	if (lives < 3){
		printf("\n%sMaster password: %s", YELLOW, CCLEAR);

		ECHO_OFF();

		char try[LINE_MAX];
		fgets(try, LINE_MAX, stdin);
		try[strlen(try)-1] = '\0';
		if (strncmp(try, (const char *)decryptedtext, LINE_MAX) != 0){
			lives ++;
			ECHO_ON();
			goto mpcheck;
		}else{ECHO_ON();}
	}else{ECHO_ON(); err("Max amount of tries excedeed.\n");}
	return EXIT_SUCCESS;
}

void help(){
	printf("\nHelp:\n\tPsswd <option>\n\tOptions:\n\t\ta, add\tAdds a new account.\n\t\tr\tRetrieves an account.\n\t\td, del\tDeletes an account.\n\t\texport\tExports account information.\n");
	exit(EXIT_SUCCESS);
}

void add(char P[], char * website, unsigned char key[], unsigned char iv[], unsigned char aad[]){
	if (strlen(website) < MIN_CRED_SIZE){err("Invalid account length.\n");}

	printf("\n%sAdd a website {%s}%s\n", PURPLE, website, CCLEAR);
	char username[NAME_MAX];
	char password[NAME_MAX];
	unsigned char cipherUsername[NAME_MAX];
	int cpu_len = 0;
	unsigned char Utag[16];

	unsigned char cipherPassword[NAME_MAX];
	int cpp_len = 0;
	unsigned char Ptag[16];

	strlcat(P, website, PATH_MAX);
	if (access( P, F_OK ) == 0){err("Account already exists.\n");}
	printf("Username: ");
	fgets(username, NAME_MAX, stdin);
	printf("Password: ");

	// Echo management
	struct termios saved_attributes;
	struct termios term;

	ECHO_OFF();

	fgets(password, NAME_MAX, stdin);

	ECHO_ON();

	if (strlen(username) < MIN_CRED_SIZE || strlen(password) < MIN_CRED_SIZE){err("Invalid username or password length.\n");}
	username[strlen(username)-1] = '\0';
	password[strlen(password)-1] = '\0';
	//Encrypting username
	cpu_len = gcm_encrypt((unsigned char *)username, strlen(username), aad, strlen((const char *)aad), key, iv, strlen((const char *)iv), cipherUsername, Utag);
	cpp_len = gcm_encrypt((unsigned char *)password, strlen(password), aad, strlen((const char *)aad), key, iv, strlen((const char *)iv), cipherPassword, Ptag);
	FILE * fp = fopen(P, "w");
	fprintf(fp, "%s\n", cipherUsername);
	fputs("/", fp);
	fprintf(fp, "%d\n", cpu_len);
	fputs("/", fp);
	BIO_dump_fp(fp, (const char *)Utag, 14);
	fputs("+", fp);
	//Encrypting password
	fprintf(fp, "%s\n", cipherPassword);
	fputs("/", fp);
	fprintf(fp, "%d\n", cpp_len);
	fputs("/", fp);
	BIO_dump_fp(fp, (const char *)Ptag, 14);
	fclose(fp);
	printf("\n%s[+] Successfully added [%s] account.%s\n",GREEN, P, CCLEAR);
	exit(EXIT_SUCCESS);
}

void retrieve(char P[], unsigned char key[], unsigned char iv[], unsigned char aad[]){
	printf("\n%sRetrieve an account.%s\n", PURPLE, CCLEAR);
	listFiles(P);
	unsigned char ciphertext[1024];
	unsigned char tag[1024];
	char cp_len_str[1024];

	unsigned char ciphertextP[1024];
	unsigned char tagP[1024];
	char cp_len_strP[1024];
	read_cipher(ciphertext, cp_len_str, tag, P, (char *)ciphertextP, cp_len_strP, tagP);
	int cp_len = atoi(cp_len_str);
	int cp_lenP = atoi(cp_len_strP);
	// Decrypting credentials
	unsigned char decryptedtext[1024];
	unsigned char decryptedtextP[1024];
	gcm_decrypt(ciphertext, cp_len, aad, strlen((const char *)aad), tag, key, iv, strlen((const char *)iv), decryptedtext);
	gcm_decrypt(ciphertextP, cp_lenP, aad, strlen((const char *)aad), tagP, key, iv, strlen((const char *)iv), decryptedtextP);
	decryptedtext[cp_len] = '\0';
	decryptedtextP[cp_lenP] = '\0';
	printf("Username: [%s]\nPassword: [%s]\n", decryptedtext, decryptedtextP);
	printf("%s[+] Successfully retrieved [%s] account credentials.%s\n", GREEN, P, CCLEAR);
	// Echo management
	struct termios saved_attributes;
	struct termios term;

	ECHO_OFF();

	char c;
	while((c = getchar()) != '\n' && c != EOF);
	getchar();

	ClearScreen();
	printf("%s./Psswd%s\n", PURPLE, CCLEAR);
	ECHO_ON();
	exit(EXIT_SUCCESS);
}

void delete(char p[]){
	printf("\n%sDelete an account%s\n", PURPLE, CCLEAR);
	listFiles(p);
	remove(p);
	printf("%s[+] Successfully deleted [%s] account.%s\n", GREEN, p, CCLEAR);
	exit(EXIT_SUCCESS);
}

int search_dir ( const char * name )
{
    struct stat _stbuf;

    char pathBak[ PATH_MAX ];
    strlcpy(pathBak, k, PATH_MAX);
    strlcat( k, name, PATH_MAX);

    if( stat( k, &_stbuf ) == 0 ) {

        if( S_ISDIR( _stbuf.st_mode )) {
            DIR * _dir;
            struct dirent * _file;
            _dir    =    opendir( k );

            if( _dir ) {
                strlcat( k, "/", PATH_MAX);
                while(( _file = readdir( _dir )) != NULL ) {
                    if( strncmp( _file->d_name, ".", 1 ) != 0 ) {
                        search_dir( _file->d_name);
                    }
                }
                closedir( _dir );
            }
            else {
            	err("Failed opening zip-file directory.\n");
            }
        }
        else {
            struct zip_source *s = zip_source_file(z, k, 0, -1);
            if(s != NULL) {
                zip_file_add(z, &k[root_len+1], s, ZIP_FL_OVERWRITE|ZIP_FL_ENC_GUESS);
            } else {
				err("Failed sourcing zip-file.\n");
            }
        }
    }
    else {
        err("Failed using stat.\n");
    }

    /* remove parsed name */
    strlcpy(k, pathBak, PATH_MAX);
	return EXIT_SUCCESS;
}

void export(char path[PATH_MAX]){

	int err = 0;

    root_len = strlen(path);
    z = zip_open(ZIP_NAME, ZIP_CREATE|ZIP_EXCL, &err);

    if (z != NULL) {
        search_dir(path);
        err = zip_close(z);
    }

    if (err != 0) {
		err("Failed exporting information.\n");
    }else{printf("\n%s[+] Successfully exported information.%s\n", GREEN, CCLEAR);}
}

int main(int argc, char * argv[]){
	printf("%s%s%s\n", PURPLE, argv[0], CCLEAR);
	if (argc < 2){err("Arguments required.\nCheck \"./Psswd help\" for help.\n");}

	// Defining the aad, key and iv
	unsigned char MASTER_KEY[32] = "01231231231241243789012345678901"; // Replace with MASTER_KEY
	/* A 128 bit IV */
	unsigned char MASTER_IV[16] = "6536458789016245";//                   Replace with MASTER_IV
	/* Some additional data to be authenticated */
	unsigned char MASTER_AAD[25] = "More aad data";//                     Replace with MASTER_AAD

	// Defining the aad, key and iv
	// The data to be hashed
	/*char data[] = "Hello, world!";
	size_t length = strlen(data);

	unsigned char hash[KEY_SIZE];
	SHA1(data, length, hash);*/
	// hash now contains the 20-byte SHA-1 hash

	//const unsigned char key[32] = "01234567890123456789012345678901"; // Replace with KEY
	unsigned char key[KEY_SIZE];
	SHA1(MASTER_KEY, KEY_SIZE, key);
	/* A 128 bit IV */
	//const unsigned char iv[16] = "0123456789012345";                  // Replace With IV
	unsigned char iv[IV_SIZE];
	SHA1(MASTER_IV, IV_SIZE, iv);
	/* Some additional data to be authenticated */
	//const unsigned char aad[25] = "Some AAD data";                    // Replace with AAD
	unsigned char aad[AAD_SIZE];
	SHA1(MASTER_AAD, AAD_SIZE, aad);

	char * path;
	path = GET_HOME;
	char masterP[PATH_MAX];
	char P[PATH_MAX];
	char exPath[PATH_MAX];
	struct stat st = {0};
	struct stat buffer;
	strlcpy(P, path, PATH_MAX);
	strlcat(P, "/.config/Psswdata/accounts/", PATH_MAX);
	strlcpy(masterP, path, PATH_MAX);
	strlcat(masterP, "/.config/Psswdata/details", PATH_MAX);
	strlcpy(exPath, path, PATH_MAX);
	strlcat(exPath, "/.config/Psswdata/", PATH_MAX);
	char mPS[NAME_MAX]; // Master Password                                No password                 /      With Password
	if (stat(P, &st) == -1 || stat(masterP,&buffer) == -1){pStartup(P, masterP, mPS, MASTER_KEY, MASTER_IV, MASTER_AAD);}else{pLoad(masterP, mPS, MASTER_KEY, MASTER_IV, MASTER_AAD);}
	if (strncmp(argv[1], "h", 1) == 0 || strncmp(argv[1], "help", 4) == 0){help();}
	else if (strncmp(argv[1], "a", 1) == 0 || strncmp(argv[1], "add", 3) == 0){
		if (argc < 3){
			err("Arguments required.\nCheck \"./Psswd help\" for help.\n");
		}else{add(P, strdup(argv[2]), key, iv, aad);}
	}else if (strncmp(argv[1], "r", 1) == 0 || strncmp(argv[1], "retrieve", 8) == 0){retrieve(P, key, iv, aad);}
	else if (strncmp(argv[1], "d", 1) == 0 || strncmp(argv[1], "del", 3) == 0){delete(P);}
	else if (strncmp(argv[1], "export", 6) == 0){export(exPath);}
	else{err("Arguments required.\nCheck \"./Psswd help\" for help.\n");}
	return EXIT_SUCCESS;
}
