package com.lawsofnature.common.edecrypt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by fangzhongwei on 2016/11/14.
 */
public class ThreeDesUtils {
    private static final String Algorithm = "DESede"; //定义 加密算法,可用 DES,DESede,Blowfish

    public static String decrypt3DES(String value, String key) throws Exception {
        final byte[] b = decryptMode(getKeyBytes(key), HexUtils.hexStr2ByteArray(value));
        return new String(b);
    }

    public static String encrypt3DES(String value, String key) throws Exception {
        final String str = HexUtils.byteArray2HexStr(encryptMode(getKeyBytes(key), value.getBytes()));
        return str;
    }
    //计算24位长的密码byte值,首先对原始密钥做MD5算hash值，再用前8位数据对应补全后8位

    public static byte[] getKeyBytes(String strKey) throws Exception {
        if (null == strKey || strKey.length() < 1) throw new Exception("key is null or empty!");
        java.security.MessageDigest alg = java.security.MessageDigest.getInstance("MD5");
        alg.update(strKey.getBytes());
        final byte[] bkey = alg.digest();
        final int start = bkey.length;
        final byte[] bkey24 = new byte[24];
        for (int i = 0; i < start; i++) {
            bkey24[i] = bkey[i];
        }
        for (int i = start; i < 24; i++) {//为了与.net16位key兼容
            bkey24[i] = bkey[i - start];
        }
        return bkey24;
    }

    public static byte[] encryptMode(byte[] keybyte, byte[] src) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //生成密钥
        final SecretKey deskey = new SecretKeySpec(keybyte, Algorithm); //加密
        final Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.ENCRYPT_MODE, deskey);
        return c1.doFinal(src);
    }

    //keybyte为加密密钥，长度为24字节
    //src为加密后的缓冲区
    public static byte[] decryptMode(byte[] keybyte, byte[] src) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //生成密钥
        SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
        //解密
        Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.DECRYPT_MODE, deskey);
        return c1.doFinal(src);
    }


    public static void main(String[] args) throws Exception {
        String key = "ABCD1234";
        String raw = "password";

        String en;
        String rn;

        for (int i = 0; i < 100; i++) {
            final long startTime = System.currentTimeMillis();
            en = encrypt3DES(raw, key);
            System.out.println("加密耗时:" + (System.currentTimeMillis() - startTime));
            System.out.println(en);
            final long startTime2 = System.currentTimeMillis();
            rn = decrypt3DES(en, key);
            System.out.println("解密耗时:" + (System.currentTimeMillis() - startTime2));
            System.out.println(rn);

        }

    }
}
