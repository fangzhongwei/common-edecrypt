package com.jxjxgo.common.edecrypt.rsa;


import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
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
public abstract class RSABase64Utils extends Coder {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    //private static String PUBLIC_KEY = "publicKey";
    //private static String PRIVATE_KEY = "privateKey";
    
    public static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDv0rdsn5FYPn0EjsCPqDyIsYRawNWGJDRHJBcdCldodjM5bpve+XYb4Rgm36F6iDjxDbEQbp/HhVPj0XgGlCRKpbluyJJt8ga5qkqIhWoOd/Cma1fCtviMUep21hIlg1ZFcWKgHQoGoNX7xMT8/0bEsldaKdwxOlv3qGxWfqNV5QIDAQAB";
    public static final String PRIVATE_KEY = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOUDkSlpaaMpPaI7TiHTBUrv3V31IWtMBvlaKK2o8cF68ZKu03E+EKGQNgfTeejGfvGpuvdd20g4ltDBNZlCR0KVhhKJjh7VsjY8RiaF7yoW/IaiJeVdIXVfW+5Zv2Y/Yb1TmfrokTG4/NnVqpY+KzfZs+2PAXyctp5baKQFKHsrAgMBAAECgYAPBN7eQmWFJ808+Hq1SSuNsJFp+guJB+FlNP559Rx1veRd5E1FnfZlQhnpBXt3Qp1Mp/70/hjFccCiTCmBtZEKswyf1vfzugNJ88+FMOUvwjGwTWEmYiOLrBcyzEzr3QUYeBtfPrt7GTEP9mJoO/uaT37XKbqQnn5GEJB3rS7YEQJBAP2ccCCvqgqjmAA9IM2pxlGC8BkDA3y9wQkx+a/wm1PIWXp5tMyB1p7tZLb6297HwQiydRrV6NwsUfxfqcwB0j0CQQDnK9Cnioz6ShBKexWoZ6ipofEgVrdFpm0AlIUSp5c5NjBu/rgbLtCjZvIdeSHAAj2SKIEds5juOyp9YVqdx+GHAkEAzxTS9c2aMg+8yM0hIO208s/QzwuH6G5k1eZJtCDqI/JfJcOFHswR/DlpWIPjzrga5cgaGOx7tHQ4CbPvSJZgHQJBAJMAdsgDwBBtRpzGVohnmoZ8d4Q0AIlnAovK5jBtqCl2fygmDFck1wIBtdbuL3sVMage37ROf+KGd0eRv/jzoUMCQQDw7OOyfemmRGFazNSHQDUBBnJrHhyKUFmB3xtMWlh0ooCg7cdZ1GsANUONC2WHM+cdR27d+kYrpN3uxaAU8fv+";


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
        byte[] keyBytes = decryptBASE64(privateKey);

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

        return encryptBASE64(signature.sign());
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
        byte[] keyBytes = decryptBASE64(publicKey);

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
        return signature.verify(decryptBASE64(sign));
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
        byte[] keyBytes = decryptBASE64(key);

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
        byte[] keyBytes = decryptBASE64(key);

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
        byte[] keyBytes = decryptBASE64(key);

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
        byte[] keyBytes = decryptBASE64(key);

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

        return encryptBASE64(key.getEncoded());
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

        return encryptBASE64(key.getEncoded());
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

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        final String pub = encryptBASE64(publicKey.getEncoded());
        System.out.println("Generated public key are the following string:\r\n" + pub);
        System.out.println("Generated private key are the following string:\r\n" + encryptBASE64(privateKey.getEncoded()));

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    private static String getRSAPrivateKeyAsNetFormat(byte[] encodedPrivkey) {
        try {
            StringBuffer buff = new StringBuffer(1024);

            PKCS8EncodedKeySpec pvkKeySpec = new PKCS8EncodedKeySpec(
                    encodedPrivkey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey pvkKey = (RSAPrivateCrtKey) keyFactory
                    .generatePrivate(pvkKeySpec);

            buff.append("<RSAKeyValue>");
            buff.append("<Modulus>"
                    + b64encode(removeMSZero(pvkKey.getModulus().toByteArray()))
                    + "</Modulus>");

            buff.append("<Exponent>"
                    + b64encode(removeMSZero(pvkKey.getPublicExponent()
                    .toByteArray())) + "</Exponent>");

            buff.append("<P>"
                    + b64encode(removeMSZero(pvkKey.getPrimeP().toByteArray()))
                    + "</P>");

            buff.append("<Q>"
                    + b64encode(removeMSZero(pvkKey.getPrimeQ().toByteArray()))
                    + "</Q>");

            buff.append("<DP>"
                    + b64encode(removeMSZero(pvkKey.getPrimeExponentP()
                    .toByteArray())) + "</DP>");

            buff.append("<DQ>"
                    + b64encode(removeMSZero(pvkKey.getPrimeExponentQ()
                    .toByteArray())) + "</DQ>");

            buff.append("<InverseQ>"
                    + b64encode(removeMSZero(pvkKey.getCrtCoefficient()
                    .toByteArray())) + "</InverseQ>");

            buff.append("<D>"
                    + b64encode(removeMSZero(pvkKey.getPrivateExponent()
                    .toByteArray())) + "</D>");
            buff.append("</RSAKeyValue>");

            return buff.toString().replaceAll("[ \t\n\r]", "");
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }


    private static String getRSAPublicKeyAsNetFormat(byte[] encodedPrivkey) {
        try {
            StringBuffer buff = new StringBuffer(1024);

            PKCS8EncodedKeySpec pvkKeySpec = new PKCS8EncodedKeySpec(encodedPrivkey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey pukKey=(RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(encodedPrivkey));
// RSAPrivateCrtKey pvkKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(pvkKeySpec);

//PublicKey publicKey =KeyFactory.getInstance("RSA").generatePublic(pvkKeySpec);

            buff.append("<RSAKeyValue>");
            buff.append("<Modulus>"
                    + b64encode(removeMSZero(pukKey.getModulus().toByteArray()))
                    + "</Modulus>");
            buff.append("<Exponent>"
                    + b64encode(removeMSZero(pukKey.getPublicExponent()
                    .toByteArray())) + "</Exponent>");
            buff.append("</RSAKeyValue>");
            return buff.toString().replaceAll("[ \t\n\r]", "");
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    private static byte[] removeMSZero(byte[] data) {
        byte[] data1;
        int len = data.length;
        if (data[0] == 0) {
            data1 = new byte[data.length - 1];
            System.arraycopy(data, 1, data1, 0, len - 1);
        } else
            data1 = data;

        return data1;
    }

    private static String b64encode(byte[] data) {

        String b64str = new String(Base64.encode(data));
        return b64str;
    }

    private static byte[] b64decode(String data) {
        byte[] decodeData = Base64.decode(data);
        return decodeData;
    }


    public static void main(String[] args) throws Exception {
//        System.err.println("公钥加密——私钥解密测试");
//        String inputStr = "中文没有问题";
//        byte[] data = inputStr.getBytes("UTF-8");
//        Map<String, Object> keyMap = RSABase64Utils.initKey("HCB-WJ-RSA-KEYS");
//
//        String publicKey = RSABase64Utils.getPublicKey(keyMap);
//        String privateKey = RSABase64Utils.getPrivateKey(keyMap);
//        byte[] encodedData = RSABase64Utils.encryptByPrivateKey(data, privateKey);
//        String jiamiData = encryptBASE64(encodedData);
//        byte[] decodedData = RSABase64Utils.decryptByPublicKey(encodedData, publicKey);
//
//        String outputStr = new String(decodedData);
//        System.err.println("加密前: " + inputStr + "\n\r" + "加密后：" + jiamiData + "\n\r解密后: " + outputStr);

        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCBUr7xDygvvWvUcmHMFFA8hPrsUqkYG7llU7l0\n" +
                "huojta1YFe2Ag38gdVzhybGN87Wa4Gr0iH7nTnRA+Ou/JvVRua0ACeJbNYvg8Yrob5LQdJ99aHXQ\n" +
                "KrG4GbaBqe5aIwHWmeAwfesp936CA0QgjVE+xU0ffvkFvWNdMlMJH2jtcQIDAQAB";
        String priKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIFSvvEPKC+9a9RyYcwUUDyE+uxS\n" +
                "qRgbuWVTuXSG6iO1rVgV7YCDfyB1XOHJsY3ztZrgavSIfudOdED4678m9VG5rQAJ4ls1i+Dxiuhv\n" +
                "ktB0n31oddAqsbgZtoGp7lojAdaZ4DB96yn3foIDRCCNUT7FTR9++QW9Y10yUwkfaO1xAgMBAAEC\n" +
                "gYARoh6278IjAEj7prz+/qYSGm+8WWkFCIK29juLT/oM9HC2WgcQRt3GpzoK711uZZSVkZQD07i6\n" +
                "AVCIq2g5oC5CzIkSaLOCLZHjhKEdvJkJS36zpeofUkEVDI8a/fYZA3L5LhKOI7hgZ/01Ld0ScNKP\n" +
                "bYfxi3R7lhQ0fUIp9QJhIQJBAMthjvQ6zrk5MDg0wwpolCs8J4KxNXT9C90bSgPKqgxiXdV/xW8C\n" +
                "g+pnfec8yhqh4D+wVa/4yrTSu7dRThfR3FMCQQCiyCYXFtmwsKAJMH3tG2YZB6+bHhDYEm33Rfkq\n" +
                "WR4NkgvfxZjx2EIdqNvqAHQSvgeod3UkUHkRvQTnrd8JEfarAkA+kAQpnO16jN0IbTKSQRlTM230\n" +
                "Bg8rrau4mGxsPiuRI7E5u9RAEcYClVNljo2dI66X6OZy+1VfynN0MM6VBTmBAkEAikyCEBvZ18Q4\n" +
                "M5Z/ZnNgyuM8zw08QldmFi/dAZ21atIqRHQc/Vw+z/Qm4yh/dWz+FKNpYvD765YsFKokVBBvAQJA\n" +
                "RuimDjsmW/Ie+TvlhxuBR4ORm7smh+rZFbgmH9Q/bv7EizhfkhpEMAQvf2kedWONs0//owvYZg4j\n" +
                "9pRRlY7y0A==";
//             String a = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeOAxaEi3BfMuFKX5exN4LodhNvjwRuKw4WqQBw0hcT8NWX9EQvnIwu1wI5IvKqrg59AAdR+lh4N1vjwp6IEwaxLcXvuLEOsOZRsfSlwuOvDAXd2FBMRM5bICwYCwo94p7gUkH1qfl6bE7lATs6veeo16wn9WX5TnAGAMyVMWCBQIDAQAB";
//        final byte[] bytes = encryptByPublicKey("中文｛｝：“。、？》》？》？。aaaaasdfoi0asdfplj'asdfm,l'mvcxzxcvm'lkzxjcvlkxkjcv".getBytes("UTF-8"), pubKey);
        final String chiper = "aZgu7qDmeXzswMD4v+yHD1ucR/szy93I4C+Eawte/kB7zj5MFHxFLc1pRcxoUNlcuRWBhM3olpJxb2ZWEV+vMzbpf/h2ShcqZtIgPTLxMvO79Qw4EOZoYPio5ScR6t0MVKmHPXCqxBXzsdVTWRaRxJRLlFLrzkKWu3UYeDwnbio=";
//        System.out.println(chiper);
        final byte[] bytes1 = decryptByPrivateKey(decryptBASE64(chiper), priKey);
//        System.out.println(new String(bytes1, "UTF-8"));

//        System.out.println(encryptBASE64(encryptByPrivateKey("{}汉字123abc".getBytes(StandardCharsets.UTF_8), priKey)));
//        System.out.println(encryptBASE64(encryptByPublicKey("{}汉字123abc".getBytes(StandardCharsets.UTF_8), pubKey)));

//        generate("ddzAppKey");

        System.out.println(new String(decryptByPublicKey(decryptBASE64(chiper), pubKey), StandardCharsets.UTF_8));

    }

    public static void generate(String seed) {
        try {
            KeyPairGenerator e = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.setSeed(seed.getBytes("UTF-8"));
            e.initialize(1024, secureRandom);
            KeyPair keys = e.genKeyPair();
            PublicKey publicKey = keys.getPublic();
            PrivateKey privateKey = keys.getPrivate();
            final byte[] publicKeyEncoded = publicKey.getEncoded();
            final byte[] privateKeyEncoded = privateKey.getEncoded();
            System.out.println("Generated public key are the following string:\r\n" + encryptBASE64(publicKeyEncoded));
            System.out.println("Generated private key are the following string:\r\n" + encryptBASE64(privateKeyEncoded));
            System.out.println("Generated public .net key are the following string:\r\n" + getRSAPublicKeyAsNetFormat(publicKeyEncoded));
            System.out.println("Generated public .net key are the following string:\r\n" + getRSAPrivateKeyAsNetFormat(privateKeyEncoded));

        } catch (Exception var6) {
            var6.printStackTrace();
            System.out.println("Failed...");
        }
    }
}
