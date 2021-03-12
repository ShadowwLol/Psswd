#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sgtty.h>
#include <string.h>
#include <unistd.h>
#include "aes.h"
// ./Psswd a <site>
// ./Psswd r <site>
// ./Psswd d <site>

char * path;
uint8_t* username;
uint8_t* password;

void add(char * website){
	FILE * fileptr;

	uint8_t key[32] =  {0};
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);

	printf("a: %s\n", website);
	printf("Psswd\n[%s]\nUsername: ", website);
	fgets(username, sizeof(username), stdin); // Max 40 characters
	if (strlen(username) < 1) { exit(1); }
	int i = 0;
	for (i = 0; i < sizeof(username); i++){if (username[i] == '\n'){username[i] = '\0';}}
	printf("\nPassword: ");
	//echoff();
	printf("\033[8m"); // echo off
	fgets(password, sizeof(password), stdin);
	printf("\033[38m"); // echo on
	if (strlen(password) < 2) { exit(1); }
	for (i = 0; i < sizeof(password); i++){if (password[i] == '\n'){password[i] = '\0';}}
	//echon();
	//printf("user: [%s], pass: [%s]\n", (char *)username, (char *)password);
	//encryption
	//AES_ECB_encrypt(&ctx, username);
	//AES_ECB_encrypt(&ctx, password);
	//printf("user: [%s], pass: [%s]\n", (char *)username, (char *)password);
	//decryption
	//AES_ECB_decrypt(&ctx, username);
	//AES_ECB_decrypt(&ctx, password);
	//printf("user: [%s], pass: [%s]\n", (char *)username, (char *)password);
	//Appending input to the file
	// Create File
	strcat(path, website); // path is now the filename
	if (access( path, F_OK ) == 0){
		printf("Error: Website already exists.\n");
		return;
	}else{
		AES_ECB_encrypt(&ctx, username);
		AES_ECB_encrypt(&ctx, password);
		printf("USER: %s\nPASS: %s\n", username, password);
		fileptr = fopen(path, "w");
		fputs(username, fileptr);
		fputs("\n", fileptr);
		fputs(password, fileptr);
		fclose(fileptr);
		printf("[+] Added [%s] account.\n", website);
		return;
	}
}

void retrieve(){
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
	uint8_t key[32] =  {0};
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);

	char * input[1];
	FILE * file;
	char * data[2048];
	printf("\n> ");
	fflush(stdin);
	fread(input, sizeof(char),  1, stdin);
	if (atoi(input)){strcat(path, files[atoi(input)-1]);}
	else{exit(1);}
	printf("FILE: %s\n", path);
	// ERROR V
	FILE * my_file = fopen(path, "r");
	printf("Data: ");
	int done = 0;
	int c;
	while ((c=fgetc(my_file))!=EOF){
		printf("%c", c);
		if (done == 1){
			strcat(password, &c);
			printf("P");
		}else if (c != '\n'){
			strcat(username, &c);
			printf("U|");
		}else{
			done = 1;
		}
	}
	printf("USERNAME: %s\n", username);
	printf("PASSWORD: %s\n", password);
	AES_ECB_decrypt(&ctx, username);
	AES_ECB_decrypt(&ctx, password);
	printf("DECRYPTED-USERNAME: %s\n", username);
	printf("DECRYPTED-PASSWORD: %s\n", password);
}

void help(){
	printf("./Psswd\n\t./Psswd <option>\nOptions:\na <website>\tAdd an account\nr <website>\tRetrieve an account\nd <website>\tDelete an account\n");
	exit(1);
}

int main(int argc, char * argv[]){
	path = getenv("HOME");
	char * dir = malloc(19);
	char * website = NULL;
	username = malloc(256);
	password = malloc(256);
	struct stat st = {0};
	strcpy(dir, "/.config/Psswd/");
	strcat(path, dir);
	free(dir);
	if (stat(path, &st) == -1){mkdir(path, 0700);}

	if (strcmp(argv[1], "h") == 0 || strcmp(argv[1], "help") == 0){help();}
	else if (strcmp(argv[1], "a") == 0){
		website = strdup(argv[2]);
		add(website);
		printf("Adding site: [%s]\n", argv[2]);
	}
	else if (strcmp(argv[1], "r") == 0){retrieve();}
	return 0;
}
