package com.lawsofnature.common.edecrypt.rsa;

import com.lawsofnature.common.edecrypt.ThreeDesUtils;

/**
 * Created by fangzhongwei on 2016/11/14.
 */
public class EDecryptUtils {
    private static final String ENCRYPTED_THREE_DES_KEY = "6ACF8E41C2C1D5B518AEC4B1C6DA726F58CA71C931260E7A607AC20C4BBD831B62EF25AF1D66B25D9E285E451DA98449948431504214D77DC5451196B0A2947F1411595FCBC4C75532B92D83B66C4FB5F8066657AA8B4659CF7D00CEAAAD66A70FE62E4DD0701058C2DF5CC59A528AF1E13B25BD2722E08C36C2C09F6378B8DA";

    public static String encrypt(String raw, String encryptedThreeDesKey, String rsaPrivateKey) throws Exception {
        return ThreeDesUtils.encrypt3DES(raw, RSAHexUtils.decryptByPrivate(encryptedThreeDesKey, rsaPrivateKey));
    }

    public static String decrypt(String cipher, String encryptedThreeDesKey, String rsaPrivateKey) throws Exception {
        return ThreeDesUtils.decrypt3DES(cipher, RSAHexUtils.decryptByPrivate(encryptedThreeDesKey, rsaPrivateKey));
    }
}
