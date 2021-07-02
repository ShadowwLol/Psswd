# Psswd
A unix password manager featuring AES256 GCM encryption.
## [WIP]
## Features:
* Quick AES256 GCM encryption
* Completely offline
* Master password usage
* Easy exporting and importing
* Quick and easy exporting and importing

## Building:
* Run: `./Setup`
* Output:

`MASTER_KEY: NA7UuZ6T(VQW9(WDyyjkjgR*RyN5cXk5`

`MASTER_IV: @@*LHC^5rG7O&myw`

`MASTER_AAD: 7ojncEV1HmUZF8KPg^BPZUfVz`

___________________________________________

`KEY: P9aBeQc_WXkLB8VxbC96aG&Qnzpc^8P(`

`IV: gZA0xOh(cGKmM28L`

`AAD: qSV5kUDs&prvgTp4^UA(dU5O&`
        

* *copy generated keys, ivs and aads into their respective variables in src/psswd.c main() function*

```c

int main(int argc, char * argv[]){
  
  ...
  
	// Defining the aad, key and iv
	const unsigned char key[32] = "01234567890123456789012345678901"; // Replace with KEY
	/* A 128 bit IV */
	const unsigned char iv[16] = "0123456789012345";                  // Replace With IV
	/* Some additional data to be authenticated */
	const unsigned char aad[25] = "Some AAD data";                    // Replace with AAD

	// Defining the aad, key and iv
	const unsigned char MASTER_KEY[32] = "01231231231241243789012345678901"; // Replace with MASTER_KEY
	/* A 128 bit IV */
	const unsigned char MASTER_IV[16] = "6536458789016245";//                   Replace with MASTER_IV
	/* Some additional data to be authenticated */
	const unsigned char MASTER_AAD[25] = "More aad data";//                     Replace with MASTER_AAD

  ...

}

```

* `make all`
