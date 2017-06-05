package com.jxjxgo.common.edecrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

/**
 * 编码工具类
 * 实现aes加密、解密
 */
public class AESUtils {
    /**
     * 算法
     */
    private static final String ALGORITHMSTR = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        String content = "我爱你";
        System.out.println("加密前：" + content);

        final String KEY = "abcdefgabcdefg12";

        System.out.println("加密密钥和解密密钥：" + KEY);

        String encrypt = aesEncrypt(content, KEY);
        System.out.println("加密后：" + encrypt);

        String decrypt = aesDecrypt("8367e105a54da22f79d3a6b47136ba56", KEY);
        System.out.println("解密后：" + decrypt);
    }

    /**
     * hex encode
     *
     * @param bytes 待编码的byte[]
     * @return 编码后的hex code
     */
    public static String byteArray2HexStr(byte[] bytes) {
        return HexUtils.byteArray2HexStr(bytes);
    }

    /**
     * hex decode
     *
     * @param hex 待解码的hex string
     * @return 解码后的byte[]
     * @throws Exception
     */
    public static byte[] hexStr2ByteArray(String hex) throws Exception {
        return HexUtils.hexStr2ByteArray(hex);
    }


    /**
     * AES加密
     *
     * @param content    待加密的内容
     * @param encryptKey 加密密钥
     * @return 加密后的byte[]
     * @throws Exception
     */
    public static byte[] aesEncryptToBytes(String content, String encryptKey) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), "AES"));

        return cipher.doFinal(content.getBytes("UTF-8"));
    }


    /**
     * AES加密为hex string
     *
     * @param content    待加密的内容
     * @param encryptKey 加密密钥
     * @return 加密后的hex string
     * @throws Exception
     */
    public static String aesEncrypt(String content, String encryptKey) throws Exception {
        return byteArray2HexStr(aesEncryptToBytes(content, encryptKey));
    }

    /**
     * AES解密
     *
     * @param encryptBytes 待解密的byte[]
     * @param decryptKey   解密密钥
     * @return 解密后的String
     * @throws Exception
     */
    public static String aesDecryptByBytes(byte[] encryptBytes, String decryptKey) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);

        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), "AES"));
        byte[] decryptBytes = cipher.doFinal(encryptBytes);

        return new String(decryptBytes);
    }


    /**
     * 将hex AES解密
     *
     * @param encryptStr 待解密的hex
     * @param decryptKey 解密密钥
     * @return 解密后的string
     * @throws Exception
     */
    public static String aesDecrypt(String encryptStr, String decryptKey) throws Exception {
        return aesDecryptByBytes(hexStr2ByteArray(encryptStr), decryptKey);
    }
}