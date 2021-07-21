# QakbotTools
Tools for assisting the reverse engineering of Qakbot's Web Inject Loader.

May be effective against core Qakbot binary, due to reuse of encryption and hashing algorithms, though may need some repurposing regarding the queried registers and instructions.

## apiHashResolver.py 

- Takes three arguments: 
  - The value used to XOR the API hashes with
  - The address of the string function used to decrypt DLL names
  - The address of API resolving functions
- Will locate all cross references to the API resolving functions, parse out the required data, decrypt the DLL names, XOR the API hashes, and brute force them
- Once the list of hashes have been resolved fully, they are then added to a new IDA local type, which is then assigned to the respective variable. 

## injectStructParser.py 

- Takes one argument: 
  - The address of the function that interacts with the inject structures
- Will locate all cross references to the API resolving functions, parse out the required data, and decrypt the DLL names and API functions
- Once the list has been parsed, comments will be added next to each entry in the inject structure, with the DLL and API name

## stringDecryption.py 

- Takes one to three arguments: 
  ### Automated
  - The addresses of the string decryption functions
  ### Manual
  - The specific string decryption wrapper
  - The address where the wrapper is referenced
  - The correct string offset
- Will locate all string decryption wrappers, parse the string and key data, and the string offset used for decryption
- This data is then used to decrypt the correct string, which is added as a comment next to the string decryption wrapper call

