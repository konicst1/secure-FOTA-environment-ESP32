package cz.fit.bp.fw_author.service;


import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class UpdateService {

    private static final int APP_DESC_OFFSET = 32;
    private static final int APP_DESC_SIZE = 256;

    private static Logger logger = LoggerFactory.getLogger(UpdateService.class);

    @Value("${keystore.name}")
    private String keystoreName;

    @Value("${keystore.password}")
    private String keystorePassword;

    @Value("${keystore.manifest_signing_key.alias}")
    private String manifestSigningKeyAlias;

    @Value("${keystore.manifest_signing_key.password}")
    private String manifestSigningKeyPassword;

    @Value("${manifest_encryption_key.path}")
    private String manifestEncryptionKeyPath;

    @Value("${keystore.secure_boot_signing_key.alias}")
    private String secureBootSigningKeyAlias;

    @Value("${keystore.secure_boot_signing_key.password}")
    private String getSecureBootSigningKeyPassword;

    @Value("${binary_encryption_key.path}")
    private String binaryEncryptionKeyPath;

    @Value("${update_server.url}")
    private String updateServerUrl;

    public void uploadFirmwareImage(String path, String fwName, int id, String deviceType) throws IOException {
        logger.info("Firmware image upload START!");
        InputStream is = new BufferedInputStream(new FileInputStream(path));
        File manifestFile = new File(fwName + ".manifest");
        File binaryFile = new File(fwName + ".bin");
        OutputStream manifestOs = new FileOutputStream(manifestFile);
        OutputStream binaryOs = new FileOutputStream(binaryFile);

        if (!is.markSupported()) {
            logger.error("Firmware image load FAILED!");
            throw new IOException("Mark not supported.");
        }
        is.mark(10000);


        byte[] appDescBuffer = extractManifest(is);
        is.reset();

        byte[] wholeImageBuffer = readAllBytes(is);
        byte[] manifestSignatureBuffer;
        byte[] firmwareSignatureBuffer;
        byte[] signedFirmwareBuffer;
        byte[] encryptedEspImgBuffer;

        logger.info("Loading keystore START!");
        KeyStore keyStore;
        try {
            keyStore = getKeyStore();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
            logger.error("Loading keystore FAILED!");
            throw new IOException();
        }
        logger.info("Loading keystore SUCCESS!");

        logger.info("Manifest extraction and signature START!");
        try {
            manifestSignatureBuffer = signManifest(keyStore, appDescBuffer);
        } catch (UnrecoverableEntryException | KeyStoreException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            e.printStackTrace();
            logger.error("Manifest extraction and signature FAILED!");
            throw new IOException();
        }
        logger.info("Manifest extraction and signature SUCCESS!");

        logger.info("Loading manifest encryption key START!");
        RSAPublicKey manifestEncKey;
        try {
            manifestEncKey = loadEncryptionKey(manifestEncryptionKeyPath);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Loading manifest encryption key FAILED!");
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            logger.error("Loading manifest encryption key FAILED!");
            throw new IOException();
        }
        logger.info("Loading manifest encryption key SUCCESS!");

        //--------------------------------------------------------------------------------------------------------------------------------------------

        //sign firmware binary with secure boot key
        logger.info("Firmware secure boot signature START!");
        try {
            firmwareSignatureBuffer = signFirmwareSecureBoot(keyStore, wholeImageBuffer);
        } catch (UnrecoverableEntryException | SignatureException | KeyStoreException | InvalidKeyException e) {
            e.printStackTrace();
            logger.error("Firmware secure boot signature FAILED!");
            throw new IOException("Firmware secure boot signature FAILED!");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            logger.error("Firmware secure boot signature FAILED!");
            throw new RuntimeException(e);
        }
        logger.info("Firmware secure boot signature SUCCESS!");

        //complete firmware binary array
        logger.info("Firmware binary completion START!");
        try {
            signedFirmwareBuffer = concatByteArrays(wholeImageBuffer, firmwareSignatureBuffer);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Firmware binary completion FAILED!");
            throw e;
        }
        logger.info("Firmware binary completion SUCCESS!");


        //build pre-encrypted firmware image structure according to https://github.com/espressif/idf-extra-components/tree/master/esp_encrypted_img
        logger.info("Loading binary pre-encryption key START!");
        RSAPublicKey espPreEncImgKey;
        try {
            espPreEncImgKey = loadEncryptionKey(binaryEncryptionKeyPath);
            encryptedEspImgBuffer = EspPreEncryptedImageBuilder.encryptFirmwareImage(signedFirmwareBuffer, espPreEncImgKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Loading binary pre-encryption key FAILED!");
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            logger.error("Loading binary-encryption key FAILED!");
            throw new IOException();
        }
        logger.info("Loading binary pre-encryption key SUCCESS!");

        logger.info("Manifest data encryption START!");
        try {
            manifestOs.write(encryptData(appDescBuffer, manifestEncKey));
            manifestOs.write(encryptData(manifestSignatureBuffer, manifestEncKey));
            binaryOs.write(encryptedEspImgBuffer);

            manifestOs.flush();
            binaryOs.flush();

            manifestOs.close();
            binaryOs.close();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("Manifest data encryption FAILED!");
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            logger.error("Manifest data encryption FAILED!");
            throw new IOException();
        }
        logger.info("Manifest data encryption SUCCESS!");


        logger.info("Upload to update server START!");
        try {
            postToUpdateServer(id, deviceType, fwName, manifestFile, binaryFile);
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            e.printStackTrace();
            logger.error("Upload to update server FAILED!");
        }
        logger.info("Upload to update server SUCCESS!");

        binaryFile.delete();
        manifestFile.delete();

        is.close();
        logger.info("Firmware image upload SUCCESS!");
    }

    private byte[] encryptData(byte[] data, RSAPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //encrypt data
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] res = cipher.doFinal(data);
        return res;
    }

    private RSAPublicKey loadEncryptionKey(String publicKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //read public key according to https://www.baeldung.com/java-read-pem-file-keys

        InputStream fis = getClass().getClassLoader().getResourceAsStream(publicKeyPath);
        String keyString = new String(readAllBytes(fis), Charset.defaultCharset());
        String PEMKey = keyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decodeBase64(PEMKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    private byte[] extractManifest(InputStream inputStream) throws IOException {
        byte[] app_desc_buffer = new byte[256];

        //throw out offset
        if (inputStream.skip(APP_DESC_OFFSET) != APP_DESC_OFFSET) {
            throw new IOException("Wrong number of bytes skipped.");
        }

        //app desc structure load to byte array
        if (inputStream.read(app_desc_buffer, 0, APP_DESC_SIZE) != APP_DESC_SIZE) {
            throw new IOException("Wrong number of bytes read.");
        }
        return app_desc_buffer;
    }

    private byte[] signManifest(KeyStore keyStore, byte[] data) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //load private key
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(manifestSigningKeyPassword.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(manifestSigningKeyAlias, keyPassword);
        PrivateKey privateSigningKey = keyEntry.getPrivateKey();

        //sign manifest
        Signature signatureObject = Signature.getInstance("SHA256withRSA");
        signatureObject.initSign(privateSigningKey);
        signatureObject.update(data);
        byte[] signatureData = signatureObject.sign();
        return signatureData;
    }

    private KeyStore getKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        InputStream fis = getClass().getClassLoader().getResourceAsStream(keystoreName);
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(fis, keystorePassword.toCharArray());
        return keyStore;
    }

    private byte[] signFirmwareSecureBoot(KeyStore keyStore, byte[] data) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException, NoSuchProviderException {
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(getSecureBootSigningKeyPassword.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(secureBootSigningKeyAlias, keyPassword);
        PrivateKey privateSigningKey = keyEntry.getPrivateKey();


        //add bouncy castle crypto provider just to be sure it is loaded
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //use bouncy castle to workaround signature DER format
        Signature ecdsaSign = Signature.getInstance("SHA256withPLAIN-ECDSA", "BC");
        ecdsaSign.initSign(privateSigningKey);
        ecdsaSign.update(data);
        byte[] signatureData = ecdsaSign.sign();
        System.out.println("siglen: " + signatureData.length);
        return signatureData;
    }


    private byte[] concatByteArrays(byte[] binary, byte[] signature) throws IOException {
        byte[] version = {0x00, 0x00, 0x00, 0x00};


        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(binary);
        //append version indicator (by Esspresif)
        baos.write(version);
        baos.write(signature);
        return baos.toByteArray();

    }

    /**
     * Import from openjdk-jdk11
     * https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/java/io/InputStream.java
     */
    private static byte[] readAllBytes(InputStream inputStream) throws IOException {

        int len = Integer.MAX_VALUE;

        List<byte[]> bufs = null;
        byte[] result = null;
        int total = 0;
        int remaining = len;
        int n;
        do {
            byte[] buf = new byte[Math.min(remaining, 8192)];
            int nread = 0;
            // read to EOF which may read more or less than buffer size
            while ((n = inputStream.read(buf, nread, Math.min(buf.length - nread, remaining))) > 0) {
                nread += n;
                remaining -= n;
            }

            if (nread > 0) {
                if ((Integer.MAX_VALUE - 8) - total < nread) {
                    throw new OutOfMemoryError("Required array size too large");
                }
                total += nread;
                if (result == null) {
                    result = buf;
                } else {
                    if (bufs == null) {
                        bufs = new ArrayList<>();
                        bufs.add(result);
                    }
                    bufs.add(buf);
                }
            }
            // if the last call to read returned -1 or the number of bytes
            // requested have been read then break
        } while (n >= 0 && remaining > 0);

        if (bufs == null) {
            if (result == null) {
                return new byte[0];
            }
            return result.length == total ?
                    result : Arrays.copyOf(result, total);
        }

        result = new byte[total];
        int offset = 0;
        remaining = total;
        for (byte[] b : bufs) {
            int count = Math.min(b.length, remaining);
            System.arraycopy(b, 0, result, offset, count);
            offset += count;
            remaining -= count;
        }

        return result;
    }

    private void postToUpdateServer(int id, String deviceType, String fwName, File manifest, File binary) throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("fw_author", "random_password");
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        //add files to request body
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("manifestFile", new FileSystemResource(manifest));
        body.add("firmwareFile", new FileSystemResource(binary));


        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity(updateServerUrl, requestEntity, String.class, id, deviceType, fwName);
        if (!response.getBody().equals("OK")) {
            throw new IOException();
        }
    }

}
