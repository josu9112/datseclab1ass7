import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSA {
	private BigInteger n, e, d;
	
	public RSA(String p, String q, String e) {
		n = new BigInteger(p).multiply(new BigInteger(q));
		BigInteger w = new BigInteger(p).subtract(BigInteger.ONE).multiply(new BigInteger(q).subtract(BigInteger.ONE));
		this.e = new BigInteger(e);
		d = this.e.modInverse(w);
	}
	
	public BigInteger encrypt(BigInteger m) { return m.modPow(e, n); }
	
	public BigInteger decrypt(BigInteger c) { return c.modPow(d, n); }

	public String toString() {
		return "PrivateKey=["+d+", "+n+"], PublicKey=["+e+", "+n+"]";
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {

		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		
		PublicKey publicKey = keyPairGen.genKeyPair().getPublic();
		PrivateKey privateKey = keyPairGen.genKeyPair().getPrivate();
		RSA rsa = new RSA(publicKey.toString(), privateKey.toString(), "12");
	
		
//		byte[] encrypted = 
		
		BigInteger c = rsa.encrypt(new BigInteger("65"));
		System.out.println("enc(65) = " + c);
		System.out.println("dec(c)  = " + rsa.decrypt(c));	
		
	}
}
