package it.saccosilvestri.jsp2p.protocol;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class BobProtocol extends Protocol{
	
	
	
	public BobProtocol(Socket cs, KeyPair kp, X509Certificate c, PublicKey capk) throws IOException {
		super(cs,kp,c,capk);
	}
	

	public SecretKeySpec doService()
			throws CertificateException, IOException, SocketException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, BadNonceException, InvalidKeySpecException {

		System.out.println("B");
		
			// (1) Ricezione del certificato del peer, verifica ed estrazione della chiave pubblica.
			PublicKey pKey = receiveCertificate();
			
			// (2) Invio del certificato del peer
			sendMyCertificate();
			System.out.println("BOB ha inviato il certificato...");		
			System.out.println("BOB -- NA*******");
			// (3) Ricezione di nA
			byte[] nA = readNonce();
			byte[] nonceA = new byte[64];
			Cipher cipher = Cipher.getInstance("RSA","BC");
			cipher.init(Cipher.DECRYPT_MODE, getPrivate());
			nonceA = cipher.doFinal(nA);
			System.out.println("BOB -- CIFAFINAL*******");
		
			// (4) Invio di (nA,nB) cifrati con la chiave pubblica di A
			// Create a secure random number generator
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			// Get 64 random bits
			System.out.println("BOB -- NB*******");
			byte[] nonceB = new byte[64];
			sr.nextBytes(nonceB);
			// encrypt the plaintext using the public key
			cipher.init(Cipher.ENCRYPT_MODE, pKey);
			byte[] ciphredA  = cipher.doFinal(nonceA);
			send(ciphredA);
			byte[] ciphredB = cipher.doFinal(nonceB);
			send(ciphredB);
					
			// (5) Ricezione e verifica di nB
			byte[] nB = readNonce();
			cipher.init(Cipher.DECRYPT_MODE, getPrivate());
			byte[] plainText = cipher.doFinal(nB);
			if(!Arrays.equals(plainText,nonceB))
				throw new BadNonceException();
			
			//(6) Generazione chiave di sessione
			byte[] key = new byte[nonceA.length+nonceB.length];
			System.arraycopy(nonceA, 0, key, 0, nonceA.length);
			System.arraycopy(nonceB, 0, key, nonceA.length, nonceB.length);
			MessageDigest sha = MessageDigest.getInstance("SHA-1","BC");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

			closeStreams();
			
			//(6) Generazione chiave di sessione
			return sessionKey(nonceA, nonceB);

	}

}
