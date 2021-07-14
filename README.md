# Psswd
A unix password manager featuring AES256 GCM encryption.
## [WIP]
## Features:
* Quick AES256 GCM encryption
* Completely offline
* Master password usage
* Easy exporting and importing
* Quick and easy exporting and importing
* Hashed credentials

## Building:
* Run: `./Setup`
* Output:

`MASTER_KEY: NA7UuZ6T(VQW9(WDyyjkjgR*RyN5cXk5`

`MASTER_IV: @@*LHC^5rG7O&myw`

`MASTER_AAD: 7ojncEV1HmUZF8KPg^BPZUfVz`

___________________________________________


* *copy generated keys, ivs and aads into their respective variables in src/psswd.c main() function*

```c

int main(int argc, char * argv[]){
  
  ...
  
	// Defining the aad, key and iv
	const unsigned char MASTER_KEY[32] = "01231231231241243789012345678901"; // Replace with MASTER_KEY
	/* A 128 bit IV */
	const unsigned char MASTER_IV[16] = "6536458789016245";//                   Replace with MASTER_IV
	/* Some additional data to be authenticated */
	const unsigned char MASTER_AAD[25] = "More aad data";//                     Replace with MASTER_AAD

  ...

}

```

* `make release`
