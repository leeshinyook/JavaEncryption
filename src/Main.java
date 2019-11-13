// created by leeshinyook

import java.math.BigInteger;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyFactory;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;



public class Main {

    public static void main(String[] args) throws Exception {

        BigInteger p, q, pMinus1, qMinus1, phi, d, n;
        BigInteger e = BigInteger.valueOf(65537); //2^16 - 1 e생성
        int certainty = 100;
        int BIT_LENGTH = 2048;

        SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
        do {
            p = new BigInteger(BIT_LENGTH, certainty, rand); // p 생성
            pMinus1 = p.subtract(BigInteger.ONE);           // p - 1
        } while (!(pMinus1.gcd(e).equals(BigInteger.ONE))); // (e, p-1) = 1
        do {
            q = new BigInteger(BIT_LENGTH, certainty, rand); // q 생성
            qMinus1 = q.subtract(BigInteger.ONE);           // q - 1
        } while (!(qMinus1.gcd(e).equals(BigInteger.ONE))); // (e, q-1) = 1
        phi = pMinus1.multiply(qMinus1); // phi생성
        n = p.multiply(q); // n 생성
        d = e.modInverse(phi); // d 생성


        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey(); // 대칭키생성
        byte [] text = "This is Secret Sentence".getBytes();
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte [] cipherText = cipher.doFinal(text); // text(평문)을 DES암호화하여 cipherText에 저장.

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(n, e);
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(n, d);
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec); //공개키 생성
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec); //개인키 생성


        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.ENCRYPT_MODE,pubKey); //공개키로 암호화
        byte [] cipherSecretKey = cipher2.doFinal(secretKey.getEncoded()); //대칭키 secret키를 encoded byte형태로 => RSA암호화


        FileOutputStream fos = new FileOutputStream("RSA_SecretKey");
        fos.write(cipherSecretKey); // 암호화된 대칭키를 외부파일에 저장
        fos.close();

        FileInputStream fis = new FileInputStream("RSA_secretKey");
        ByteArrayOutputStream baso = new ByteArrayOutputStream();
        int theByte = 0;
        while ((theByte = fis.read()) != -1) {
            baso.write(theByte);
        }
        fis.close();
        byte [] RSAsecretKey = baso.toByteArray(); // 암호화된 대칭키를 불러온다.
        baso.close();

        cipher2.init(Cipher.DECRYPT_MODE, privKey); // 개인키를 활용한 복호화
        byte[] RSAdecrySecretKey = cipher2.doFinal(RSAsecretKey); // RSA로 복호화하여 대칭키를 휙득

        SecretKey originSecretKey = new SecretKeySpec(RSAdecrySecretKey, 0, RSAdecrySecretKey.length, "DES");
        // byte형태를 다시 secret으로 돌린다.

        cipher.init(Cipher.DECRYPT_MODE, originSecretKey);
        byte [] originText = cipher.doFinal(cipherText);

        System.out.println(new String(text)); // 원본 문장
        System.out.println(new String(originText));
        // 원본문장을 DES암호화 후 이 DES암호화과정에 쓰였던 대칭키(byte형태로 변환후)를 RSA암호화하여 RSA_SecretKey파일로 저장하고 , 이 암호화된 대칭키를 불러와서
        // 개인키로 RSA복호화 과정을 거치고 byte형태였던, 대칭키를 다시 Secret형태로 바꿔준다.
        // 그리고 이 대칭키를 활용해서 DES복호화 과정을 거쳐 원본 문장을 다시 불러온다.
        // 원본문장과 복호화된 문장이 같은지 확인해본다.
        // 결과 : 동일.
    }
}


