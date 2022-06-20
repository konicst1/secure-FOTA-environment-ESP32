# secure-FOTA-environment-ESP32
Application set for secure OTA updating establishment for environment with ESP32 devices.
The implementation is created according to this thesis: https://dspace.cvut.cz/handle/10467/101797

**Note**

According to current standards, the _encrypt-then-mac_ schema should be used instead of _sign-then-encrypt_ due to the threat of _Padding Oracle attack_. However, this implementation uses AES in GCM mode which is not vulnerable to this kind of attack.
 
This implementation consist of FW Author Application, Update Server application in Spring Boot and ESP32 OTA interface which optimizes and simplifies the use of secure OTA solution provided in ESP-IDF 5.0.

**INSTRUCTIONS:**

The solution consists of two applications implementing the FW Author and the Update Server and a secure OTA update solution for ESP32 devices which utilizes the existing OTA Upgrades with Pre-Encrypted Firmware solution pre-released in ESP-IDF v5.0. In the following sections, the implementation details are described, and an instruction guide for a secure FOTA setup is supplied.


**0. Cryptographic resources establishment and device configuration**

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

**1. FW Author application**

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

**Application function**
After the POST request is sent, the following procedures are performed:

**1.** The firmware binary is loaded and the manifest data is extracted.

**2.** Manifest data is digitally signed and encrypted using the provided keys
from the KeyStore.

**3.** The firmware binary is signed with the secure boot signing key.

**4.** The firmware encrypted image is created in the format compatible with
the ESP-IDF OTA solution.

**5.** Both files are uploaded securely to the Update Server over HTTPS with
a single authenticated POST request


**2. Update Server application**

FW Update Server application is responsible for maintaining the uploaded
firmware images and providing them to consumer IoT devices. It is based on
the Spring Boot framework and utilizes a MySQL database for firmware image management. The application provides an API for easy implementation
of other data sources (by default, the local filesystem storage implementation
is used). It also allows the developer to easily configure the request filtering
and authentication implementation using the Spring Boot security configuration.


**Application setup**

**1.** Create a Java KeyStore (e.g. in PKCS #12 format) and import the
Update Server private key and the trusted certificate of the Update
Server.

**2.** Setup a MySQL database with the provided create script.

**3.** Secure the KeyStore with a password as well as the imported key.

**4.** Locate the resources folder and insert the created KeyStore.

**5.** In the resources folder, locate the application.properties file and configure the KeyStore parameters, SSL parameters, database URL and
credentials and a path for filesystem data storage.

**6.** Configure the authentication mechanism and request filtering in the SecurityConfiguration file located in the configuration package if needed.
Note that by default the application uses an HTTP Basic Authentication
mechanism with an enforced SSL connection and in-memory user manager. If a more robust communication scheme is implemented, a more
robust authentication protocol such as OAuth 2.0 must be used (by default, the upload process is done via a single HTTP request). Rebuild
the application if any changes are applied.

**7.** Run the application on an Internet-accessible server. Note that the
application can be run as a Linux service.


**Application usage and function**

After the successful application and database setup, it is ready to accept and
distribute firmware images.

Usage of the Update Server application:

• **_Accept the firmware image upload_** — Available on the _/uploadFile_
endpoint with a POST request. Usage of this endpoint requires authentication and is automatically used by the FW Author application. The endpoint returns _OK (String)_ if the upload was successful, else a server
error is returned. The mandatory request parameters are:
a) _manifestFile (file)_ – File containing the signed and encrypted manifest data.

b) _firmwareFile (file)_ – File containing the signed and encrypted firmware
image data.

c) _id (integer)_ – id that will be used by the Update Server to identify
the age of the firmware image (image with the highest id is considered as the newest image)

d) _deviceType (String)_ – a device type that is compatible with the
firmware image

e) _fwName (String)_ – the name of the firmware, will be used by the
Update Server to identify the firmware image

• **_Request the newest firmware update manifest_** file — Available
on the _/update/newest/manifest_ endpoint with a GET request. The
application will find the newest firmware update for the given device
type and sends its manifest file to the response output stream. 200
(OK) response is returned if manifest supply is successful, else 404 (NOT
FOUND) is returned.
The mandatory request parameter is deviceType (String) containing the
type of the device to supply the update to.

• **_Request the newest firmware update image file_** — Available on
the _/update/newest/binary_ endpoint with a GET request. The application will find the newest firmware update for the given device type
and sends its image file to the response output stream. 200 (OK) response is returned if image supply is successful, else 404 (NOT FOUND)
is returned.

The mandatory request parameter is deviceType (String) containing the
type of the device to supply the update to.


**3. ESP32 secure OTA interface**
The ESP32 secure interface provides two basic functionalities that can be easily extended for a more complex solution. It is possible to check if any new
update is available with the _check_for_update_ function and perform the update to the newest firmware available with the perform_update function. For
further information about the usage of the interface, refer to the documentation of the _secure_ota_esp32.h_ header file.

**Interface usage and function**

The following steps are to be performed in order to use the interface properly:

**1.** Include the secure_ota_esp32.h header file to the developed application
and the configuration elements from the _Kconfig.projbuild_ file.

**2.** Configure the values of EXAMPLE_FIRMWARE_UPGRADE_URL
and the CONFIG_UPDATE_CHECK_URL to use the given Update
Server.

**3.** To check for an available update, create a freeRTOS task to perform the
_check_for_update_ function. This function connects to the Update Server
over a TLS connection, retrieves the firmware manifest and performs
a decision-making process.

**4.** To perform an update to the newest available firmware, run the _perform_update_ function. This function creates a freeRTOS subtask that
utilizes the ESP-IDF Pre-Encrypted OTA Update solution to perform the update.
