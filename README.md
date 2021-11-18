# generate-keytab
Takes a .kerberos file generated from impacket's [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) and outputs a keytab.

This is a very crude script I threw together fairly quickly because I wanted to decrypt kerberos trafic. If there is sufficient interest in this I will fix it up.

```
usage: secretstokeytab.py [-h] -infile INFILE -outfile OUTFILE -realm REALM -append

Create a keytab file

optional arguments:
  -h, --help        show this help message and exit
  -infile INFILE    The .kerberos file from impacket/examples/secretsdump.py to parse
  -outfile OUTFILE  The outfile if append is specified, this is the file to append to
  -realm REALM      The realm for the keytab entries (if the user string in the infile contains the realm this will be ignored)
  -append           Append to an existing keytab instead of overwriting it
  ```
