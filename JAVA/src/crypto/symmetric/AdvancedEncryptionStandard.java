
package crypto.symmetric;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *
 * @author LUIS DOMINGO RUEDA WILCHES <ingluisruedaw@gmail.com>
 */
public class AdvancedEncryptionStandard 
{
    private final String algorithm;
    
    private final int iterationCount;
    
    private byte[] iv;
    
    private final int keyLength;
    
    private final int maxSalt;
    
    private String password;
    
    private byte[] salt;
    
    private AdvancedEncryptionStandard()
    {
        this.algorithm = "PBKDF2WithHmacSHA256";
        this.iterationCount = 65536;
        this.keyLength = 256;
        this.maxSalt = 16;
    }
    
    public AdvancedEncryptionStandard(String password)
    {        
        this();
        this.iv = this.SecureIv();
        this.password = password;     
        this.salt = this.SecureSalt();
    }
    
    public AdvancedEncryptionStandard(String password, String iv, String salt)
    {        
        this();
        this.iv = iv.getBytes(StandardCharsets.UTF_8);
        this.password = password;     
        this.salt = salt.getBytes(StandardCharsets.UTF_8);
    }
    
    private byte[] SecureIv()
    {   
        byte[] t = new byte[12];
        new SecureRandom().nextBytes(t);
        
        return t;
    }
    
    private byte[] SecureSalt()
    {
        var random = new SecureRandom();       
        byte[] t = new byte[this.maxSalt];
        random.nextBytes(t);
        
        return t;
    }
    
    private Cipher SecureCipher(Boolean crypto)
    {
        try 
        {
            // Generar una clave segura utilizando PBKDF2
            var f = SecretKeyFactory.getInstance(this.algorithm);            
            
            var spec = new PBEKeySpec(
                this.password.toCharArray(), 
                this.salt, 
                this.iterationCount, 
                this.keyLength);
        
            // Crear una instancia de Cipher con el modo GCM
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            var parameterSpec = new GCMParameterSpec(
                    128, 
                    this.iv);
        
            var secretKey = new SecretKeySpec(f.generateSecret(spec)
                    .getEncoded(), "AES");
            
            cipher.init(
                    crypto 
                            ? Cipher.ENCRYPT_MODE
                            : Cipher.DECRYPT_MODE,
                    secretKey, 
                    parameterSpec);
            
            String ivString = Base64.getEncoder().encodeToString(iv);
            String saltString = Base64.getEncoder().encodeToString(salt);
            System.out.println("IV: " + ivString);
            System.out.println("SALT: " + saltString);
        
            return cipher;
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        
        return null;
    }
    
    public String Encode(String textInput)
    {
        try {
            // Cifrar el texto plano
            var e = this.SecureCipher(Boolean.TRUE).doFinal(
                    textInput.getBytes(StandardCharsets.UTF_8));

            // Obtener el texto cifrado y el IV como cadenas Base64
            return Base64.getEncoder().encodeToString(e);            
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        
        return null;
    }
    
    public String Decode(String textInput)
    {
        try
        {
            // Descifrar el texto cifrado
            byte[] decodedBytes = Base64.getDecoder().decode(textInput);
            var cipher = this.SecureCipher(Boolean.FALSE);
            byte[] bytes = cipher.doFinal(decodedBytes);
            return new String(bytes, StandardCharsets.UTF_8);
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        
        return null;
    }
}
