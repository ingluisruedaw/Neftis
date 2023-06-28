
package crypto.hash;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author LUIS DOMINGO RUEDA WILCHES <ingluisruedaw@gmail.com>
 */
public class MessageDigestFive {
    
    private final String algorithm;      
    
    private final int maxLength;
    
    private final int minDefault;
    
    private final int radix;
    
    private String response;
    
    private final int signum;
    
    private final String textInput;
    
    private final String zero;
    
    public MessageDigestFive(String textInput)
    {
        this.algorithm = "MD5";
        this.maxLength = 32;
        this.minDefault = 0;
        this.radix = 16;
        this.response = null;
        this.signum = 1;
        this.textInput = textInput;
        this.zero = "0";        
    }
    
    public String Encode()
    {
        try 
        {
            if(textInput.length() > this.minDefault)
            {
                // Create an instance of MessageDigest with MD5 algorithm
                var md = MessageDigest.getInstance(this.algorithm);

                // Get the byte array of the input string
                var messageDigest = md.digest(this.textInput.getBytes());

                // Convert the byte array to a signum representation
                var r = new BigInteger(
                        this.signum, 
                        messageDigest);

                // Convert the signum representation to a hex string
                this.response = r.toString(this.radix);

                // Pad the hash with leading zeros if necessary
                while (this.response.length() < this.maxLength) 
                {
                    this.response = this.zero + this.response;
                }
            }
            
        } 
        catch (NoSuchAlgorithmException e) 
        {
        }
        
        return this.response;
    }
    
}
