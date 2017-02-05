package com.jxjxgo.common.edecrypt.rsa;

import com.jxjxgo.common.edecrypt.HexUtils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @author fangzhongwei
 * @since 2015/7/28.
 */
public abstract class RSAHexUtils {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    public static final String SYSTEM_CHARSET = "UTF-8";

    //private static String PUBLIC_KEY = "publicKey";
    //private static String PRIVATE_KEY = "privateKey";

    public static final String PUBLIC_KEY = "30819F300D06092A864886F70D010101050003818D0030818902818100CCD76686077243850EF52548BD4CE250C87904091FF94585395BCA59F9FACB20E2866E0727C861C5F2C45AECECC412855E7B8A9342F0EFA7562FBA2D7927529ED92EF7825144F758A32752FA620CFB1E4061442E157386BECE969981438AC697D50F4BFD5824AA38B66D63BA921E5D4CFFE71DB72479571D5D3B1DAD7FEF4F0B0203010001";
    public static final String PRIVATE_KEY = "30820278020100300D06092A864886F70D0101010500048202623082025E02010002818100CCD76686077243850EF52548BD4CE250C87904091FF94585395BCA59F9FACB20E2866E0727C861C5F2C45AECECC412855E7B8A9342F0EFA7562FBA2D7927529ED92EF7825144F758A32752FA620CFB1E4061442E157386BECE969981438AC697D50F4BFD5824AA38B66D63BA921E5D4CFFE71DB72479571D5D3B1DAD7FEF4F0B020301000102818100AA8E8F66F9BC424BFFF04E630A7B81D51196F1AD475A1E709719BE9ABC71FDC01BDD22B00287EE210BCA428B13790E92CDE0BFB96DFB7F102DCAFF91ED56B88ADBAC410EE29A9A80F8A4F728C70599AC3698BDDBFFC98D584E37F5F6A9490378EA51CEC4D021CE8F5677C32413536D91D1E82644D78A84FB8BB24EA7D14DB541024100FD72AD5DC1A4FD3C79E0EBD54C3E13BECB4011C7A91BF8A386B2289F44D5E1B53B2F9E6F4C65B9086D22F68D34A047CC72544125E604CDE3789B6BF0E6DD4277024100CEE76DA1EF78F54A0C0C44A075685D8CCB3D8CAD84AC76CA7F3FE27EFDC515D11599E705834064AAA6DC309F177FCE64BEB1560843F9ACE3CB1CD9827FF9490D024100D202D1572C1B6BDF4DDAAB705E31DE28ADC0943B0E8CE7F590AA55F0CB9832E3FA7C15DB81C194963FE0C5CDF1FA9223FDE484EB43735DAB8C87B4E4B4584937024100B43EEEC644FDC60A84E6671EB6497E3DFA8C9B324AC388152EB7F3D417B58B2503C1787DD7F2CFFFCEAF41F8469B83AD4666ED00F45EDD1BF14527C3C542E13D0240633C19D4C4767C1B2428F4730E509541CAEB725346B6BE1628752C2C5795084BFFD67D14C8B0C066256DB8B962289CE4BCA3F67C24599FD6255FC87D31097409";


    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 解密由base64编码的私钥
        byte[] keyBytes = HexUtils.hexStr2ByteArray(privateKey);

        // 构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return HexUtils.byteArray2HexStr(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      加密数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

        // 解密由base64编码的公钥
        byte[] keyBytes = HexUtils.hexStr2ByteArray(publicKey);

        // 构造X509EncodedKeySpec对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取公钥匙对象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        // 验证签名是否正常
        return signature.verify(HexUtils.hexStr2ByteArray(sign));
    }

    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = HexUtils.hexStr2ByteArray(key);

        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = HexUtils.hexStr2ByteArray(key);

        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 加密<br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        // 对公钥解密
        byte[] keyBytes = HexUtils.hexStr2ByteArray(key);

        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 加密<br>
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = HexUtils.hexStr2ByteArray(key);

        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 取得私钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return HexUtils.byteArray2HexStr(key.getEncoded());
    }

    /**
     * 取得公钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);

        return HexUtils.byteArray2HexStr(key.getEncoded());
    }

    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey(String seed) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);

        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(seed.getBytes("UTF-8"));
        keyPairGen.initialize(1024, secureRandom);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        // 公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // 私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap(2);

        final String pub = HexUtils.byteArray2HexStr(publicKey.getEncoded());
        System.out.println("Generated public key are the following string:\r\n" + pub);
        System.out.println("Generated private key are the following string:\r\n" + HexUtils.byteArray2HexStr(privateKey.getEncoded()));

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    public static String encryptByPublic(String raw, String publicKey) throws Exception {
        return HexUtils.byteArray2HexStr(encryptByPublicKey(raw.getBytes(SYSTEM_CHARSET), publicKey));
    }

    public static String decryptByPrivate(String chiper, String privateKey) throws Exception {
        return new String(decryptByPrivateKey(HexUtils.hexStr2ByteArray(chiper), privateKey), SYSTEM_CHARSET);
    }

    public static void generateKeys(String seed) {
        try {
            KeyPairGenerator e = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.setSeed(seed.getBytes("UTF-8"));
            e.initialize(1024, secureRandom);
            KeyPair keys = e.genKeyPair();
            PublicKey publicKey = keys.getPublic();
            PrivateKey privateKey = keys.getPrivate();
            System.out.println("Generated public key are the following string:\r\n" + HexUtils.byteArray2HexStr(publicKey.getEncoded()));
            System.out.println("Generated private key are the following string:\r\n" + HexUtils.byteArray2HexStr(privateKey.getEncoded()));
        } catch (Exception var6) {
            var6.printStackTrace();
            System.out.println("Failed...");
        }

    }
}
