# secure-FOTA-environment-ESP32
Application set for secure OTA updating establishment for environment with ESP32 devices.
The implementation is created according to this thesis: https://dspace.cvut.cz/handle/10467/101797

**Note**

According to current standards, the _encrypt-then-mac_ schema should be used instead of _sign-then-encrypt_ due to the threat of _Padding Oracle attack_. However, this implementation uses AES in GCM mode which is not vulnerable to this kind of attack.
 
This implementation consist of FW Author Application, Update Server application in Spring Boot and ESP32 OTA interface which optimizes and simplifies the use of secure OTA solution provided in ESP-IDF 5.0.

**INSTRUCTIONS:**

The solution consists of two applications implementing the FW Author and the Update Server and a secure OTA update solution for ESP32 devices which utilizes the existing OTA Upgrades with Pre-Encrypted Firmware solution pre-released in ESP-IDF v5.0. In the following sections, the implementation details are described, and an instruction guide for a secure FOTA setup is supplied.


**Cryptographic resources establishment and device configuration**

Before the secure OTA update is implemented, cryptographic keys should be generated and an ESP32 device should be configured to fulfill the security requirements of the provided solution. Cryptographic keys should be generated strictly on devices with proper entropy sources using secure libraries such as OpenSSL.

**1.** Generate an elliptic-curve key pair for secure boot using a NIST256p
(also known as prime256v1) curve. Note that this key pair should be
used only along with ESP32 revision 1 devices. For other ESP32 revisions, refer to related documentation of the secure boot implementation.

**2.** Generate an AES-256 key for flash encryption.

**3.** Generate a 3072-bit RSA key pair for manifest digital signature.

**4.** Generate a 4096-bit RSA key pair for manifest encryption.

**5.** Generate a 3072-bit key for firmware pre-encryption.

**6.** Configure the bootloader to use secure boot and flash encryption features with the generated keys concurrently according to the used ESP-IDF version documentation. Use release modes of the features in a production environment. It is recommended to configure both features before reflashing the bootloader. If the bootloader is reflashed in release secureboot mode, the subsequent reflashing for flash encryption establishment might not be possible.

**7.** Generate a cryptographic key pair for secure communication with the Update Server and obtain a trusted certificate for the Update Server.

**FW Author application**

The FW Author application is a utility that allows the firmware author to
upload the built firmware binary into distribution (Update Server) securely.
The application utilizes the generated cryptography resources to transform
the plain binary file into secured files that can be distributed to consumer
devices.

**Application setup**

Firstly, the FW Author application must be configured using the generated
cryptographic keys, upload to the Update Server and perform securely. The
application requires Java 8 installed.

**1.** Create a Java KeyStore (e.g. in PKCS #12 format) and import the
private manifest digital signature key and the private secure boot signing
key.

**2.** Secure the KeyStore with a password as well as the imported keys.

**3.** Locate the resources folder and insert the public key for firmware pre-encryption, the public key for manifest encryption and the created KeyStore file.

**4.** In the resources folder, locate the application.properties file and configure the KeyStore parameters, public keys for encryption and the UpdateServer URL.The provided URL will be used to upload the firmware image data.

**5.** Run the application on a local network. Note that the application exposes a RESTful API that is used to perform operations. The application uses secret cryptographic resources and automatically uploads the
provided data for distribution. Thus, it should never be accessible from
the Internet or an untrusted network.

**Application usage**

After the successful setup, the application can be used to secure and upload to
distribution any plain firmware binary file built in the ESP-IDF framework.
Note that the Update Server application must be configured and available to
upload the image successfully.

Usage of the FW Author application:

**1.** Include the public manifest digital signature key, private manifest encryption key and private firmware pre-encryption key in the firmware binary.

**2.** Build a firmware binary file with ESP-IDF.

**3.** Send a POST request to the application /upload endpoint. The request
must contain the following mandatory parameters:

a) _id (integer)_ – id that will be used by the Update Server to identify the
age of the firmware image (image with the highest id is considered
as the newest image)

b) _deviceType (String)_ – a device type that is compatible with the
firmware image

c) _fwName (String)_ – the name of the firmware, will be used by the
Update Server to identify the firmware image

d) _firmwarePath (String)_ – path to the location of the built firmware
binary, authenticate the request in accordance with the implemented
authentication method

**4.** Collect the HTTP response. The following response codes are to be
expected:

a) _200 (OK)_ – The firmware image file has been uploaded successfully.

b) _404 (NOT FOUND)_ – The firmware binary file is not in the specified
location.

c) _422 (UNPROCESSABLE ENTITY)_ – Files configured in the application.properties file cannot be loaded.

d) Server error response codes will be returned in case of any other error.
Refer to the application log for further information.
