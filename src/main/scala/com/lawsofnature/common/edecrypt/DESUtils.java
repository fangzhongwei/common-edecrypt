package com.lawsofnature.common.edecrypt;


import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Created by fangzhongwei on 2016/11/4.
 */
public class DESUtils {
    private static final String ALGORITHM_PADDING = "DES/CBC/PKCS5Padding";
    private static final String SYS_CHARSET = "UTF-8";
    private static final String INSTANCE_NAME = "DES";

    public static String decrypt(String message, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, SecretKeyFactory.getInstance(INSTANCE_NAME).generateSecret(new DESKeySpec(key.getBytes(SYS_CHARSET))), new IvParameterSpec(key.getBytes(SYS_CHARSET)));
        return new String(cipher.doFinal(HexUtils.hexStr2ByteArray(message)));
    }

    public static String encrypt(String message, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeyFactory.getInstance(INSTANCE_NAME).generateSecret(new DESKeySpec(key.getBytes(SYS_CHARSET))), new IvParameterSpec(key.getBytes(SYS_CHARSET)));
        return HexUtils.byteArray2HexStr(cipher.doFinal(message.getBytes(SYS_CHARSET)));
    }
}