#### D.RDynamicShellcode; Download & Run Dynamic Shellcode : it reads the shellcode from a url (has to be downloadable) locate it in a RWX section in memory and run it, useful for people looking for a shellcode as a 1st stage

#### NOTES:
- the file calc.ico in this repo is a meterpreter calc shellcode, used for testing
- the shellcode fetches dynamic api addresses and patch the shellcode at runtime
- edit [PAYLOAD_LINK](https://gitlab.com/ORCA000/d.rdynamicshellcode/-/blob/main/Loader.c#L8) to ur payload url 
- edit [PAYLOAD_SIZE](https://gitlab.com/ORCA000/d.rdynamicshellcode/-/blob/main/Loader.c#L9) to ur payload size







