package zing.protocol.algorithm;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {

    /**
     * 生成密钥对
     * @return 密钥对
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    /**
     * 公钥加密
     * @param content 内容
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception
     */
    public static String encrypt(String content, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(content.getBytes("utf8"));
        return Base64.getEncoder().encodeToString(cipherText);
    }


    /**
     * 私钥解密
     * @param content 密文
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception
     */
    public static String decrypt(String content, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(content);
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decriptCipher.doFinal(bytes), "utf8");
    }

    /**
     * 私钥签名
     * @param content 内容
     * @param privateKey 私钥
     * @return 签名
     * @throws Exception
     */
    public static String sign(String content, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(content.getBytes("utf8"));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }


    /**
     * 公钥验证
     * @param content 内容
     * @param signature 签名
     * @param publicKey 公钥
     * @return 验证结果
     * @throws Exception
     */
    public static boolean verify(String content, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(content.getBytes("utf8"));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    /**
     * 公钥或私钥转字符串
     * @param key 钥
     * @return Base64编码的字符串
     */
    public static String key2String(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }


    /**
     * 从字符串获取公钥
     * @param base64 字符串
     * @return 公钥
     */
    public static PublicKey getPublicKey(String base64) {
        byte[] decode = Base64.getDecoder().decode(base64);
        return getPublicKey(decode);
    }


    /**
     * 从字节数组获取公钥
     * @param bytes 字节数组
     * @return 公钥
     */
    public static PublicKey getPublicKey(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从字符串获取私钥
     * @param base64 字符串
     * @return 私钥
     */
    public static PrivateKey getPrivateKey(String base64) {
        byte[] decode = Base64.getDecoder().decode(base64);
        return getPrivateKey(decode);
    }


    /**
     * 从字节数组获取私钥
     * @param bytes 字节数组
     * @return 私钥
     */
    public static PrivateKey getPrivateKey(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

}
