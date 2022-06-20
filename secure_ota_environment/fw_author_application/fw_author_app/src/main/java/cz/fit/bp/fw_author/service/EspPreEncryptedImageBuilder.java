package cz.fit.bp.fw_author.service;



import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Class that creates pre-encrypted ESP32 firmware image in accordance with esp_encrypted_img
 * https://github.com/espressif/idf-extra-components/blob/e3f56d39f46b62e269ddb328b943b97a107604ad/esp_encrypted_img/tools/esp_enc_img_gen.py#L18
 */
public class EspPreEncryptedImageBuilder {
    private static final byte[] IMG_MAGIC = {(byte) 0xcf, (byte) 0xb6, (byte) 0x88, (byte) 0x07};   //0x0788b6cf little endian

    private static final int GCM_KEY_SIZE = 32;
    private static final int MAGIC_SIZE = 4;
    private static final int ENC_GCM_KEY_SIZE = 384;
    private static final int IV_SIZE = 16;
    private static final int BIN_SIZE_DATA = 4;
    private static final int AUTH_SIZE = 16;
    private static final int RESERVED_HEADER = (512 - (MAGIC_SIZE + ENC_GCM_KEY_SIZE + IV_SIZE + BIN_SIZE_DATA + AUTH_SIZE));


    public static byte[] encryptFirmwareImage(byte[] data, RSAPublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        //generate encryption key for AES-GCM
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(GCM_KEY_SIZE * 8);

        SecretKey aesKey = keyGenerator.generateKey();
        byte[] IV = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);

        byte[] gcmKeyArray = aesKey.getEncoded();
        byte[] encryptedGcmKey;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        encryptedGcmKey = cipher.doFinal(gcmKeyArray);

        byte[] encBinaryAndAuthTag = encryptBinaryAESGCM(data, IV, aesKey);
        if(encBinaryAndAuthTag.length != (data.length + AUTH_SIZE)){
            System.err.println("Something is wrong!!!!!!");
        }

        byte[] authTag = Arrays.copyOfRange(encBinaryAndAuthTag, encBinaryAndAuthTag.length - AUTH_SIZE, encBinaryAndAuthTag.length);
        byte[] encBinary = Arrays.copyOfRange(encBinaryAndAuthTag, 0, encBinaryAndAuthTag.length - AUTH_SIZE);

        return concatByteArrays(encryptedGcmKey, IV, encBinary, authTag);

    }


    private static byte[] encryptBinaryAESGCM(byte[] binary, byte[] IV, SecretKey key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AUTH_SIZE * 8, IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(binary);
        return cipherText;
    }

    private static byte[] concatByteArrays(byte[] encryptedAesGcmKey, byte[] iv, byte[] encryptedBinary, byte[] authTag) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        //write magic bytes in little endian
        baos.write(IMG_MAGIC);

        //write RSA encrypted AES-GCM key
        baos.write(encryptedAesGcmKey);

        //write initialization vector
        baos.write(iv);

        //write length of encrypted in hex (little endian)
        ByteBuffer bb = ByteBuffer.allocate(BIN_SIZE_DATA);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(encryptedBinary.length);
        bb.flip();
        baos.write(bb.array());

        //write auth tag
        baos.write(authTag);

        //write reserved header with zero bytes
        byte[] zeros = new byte[RESERVED_HEADER];
        baos.write(zeros);

        //write encrypted firmware binary
        baos.write(encryptedBinary);

        return baos.toByteArray();

    }

}
