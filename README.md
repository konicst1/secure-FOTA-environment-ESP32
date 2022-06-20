# secure-FOTA-environment-ESP32
Application set for secure OTA updating establishment for environment with ESP32 devices.
The implementation is created according to this thesis: https://dspace.cvut.cz/handle/10467/101797

**Note**

According to current standards, the _encrypt-then-mac_ schema should be used instead of _sign-then-encrypt_ due to the threat of _Padding Oracle attack_. However, this implementation uses AES in GCM mode which is not vulnerable to this kind of attack.
 
