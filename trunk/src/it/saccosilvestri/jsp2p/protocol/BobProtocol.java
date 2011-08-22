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

public class BobProtocol {
	
	private Socket clientSocket;
	private KeyPair keyPair;
	private X509Certificate cert;
	private PublicKey caPublicKey;
	
	public BobProtocol(Socket cs, KeyPair kp, X509Certificate c, PublicKey capk) {
		clientSocket = cs;
		keyPair = kp;
		cert = c;
		caPublicKey = capk;
	}
	
	 private int byteArrayToInt(byte[] b) {
	        int value = 0;
	        for (int i = 0; i < b.length; i++) {
	            value += b[i]*Math.pow(2,i);
	        }
	        if(value<0)
	        	value = -value;
	        return value;
	    }

	public Key doService()
			throws CertificateException, IOException, SocketException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, BadNonceException, InvalidKeySpecException {

		System.out.println("B");
		
			InputStream in = clientSocket.getInputStream();
			OutputStream out = clientSocket.getOutputStream();
			
			// (1) Ricezione del certificato del peer, verifica ed estrazione della chiave pubblica.
		//	byte[] certificate = new byte[length];
		//	in.read(certificate);
			
			CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");		
			//System.out.println("BOB e mo?...");
			X509Certificate retrievedCert = (X509Certificate)fact.generateCertificate(in);
			System.out.println("BOB ha letto il certificato...");
			// Basic validation
			System.out.println("BOB -- Validating dates...");
			cert.checkValidity(new Date());
			System.out.println("Verifying signature...");
			cert.verify(caPublicKey);
			System.out.println("Dates and signature verified.");
			System.out.println("Retrieving PublicKey...");
			PublicKey pKey = retrievedCert.getPublicKey();
			
			// (2) Invio del certificato del peer
			byte[] certBytes = cert.getEncoded();
			//int length = certBytes.length;
			//out.write(length);
			out.write(certBytes);
			out.flush();
			System.out.println("BOB ha inviato il certificato...");
			
			System.out.println("BOB -- NA*******");
			// (3) Ricezione di nA
			byte[] nA;
			byte[] lengthBytes = new byte[1];
			in.read(lengthBytes,0,1);
			int nonceLength = byteArrayToInt(lengthBytes);
			System.out.println("LUNGHEZZA NA SU B DOPO"+nonceLength);
			nA = new byte[nonceLength];
			in.read(nA,0,nonceLength);
			System.out.println("LUNGHEZZA NA SU B"+nA.length);
			//TODO
			//for(int i=0;i<nA.length;i++)
			//	System.out.print(nA[i]);
			//System.out.println("FINENADIB");
			byte[] nonceA = new byte[64];
			System.out.println("BOB -- CIFA*******");
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
			System.out.println("BOB -- QUINDI*******");
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			System.out.println("BOB -- Sto per decifrare na con la private*******");
			nonceA = cipher.doFinal(nA);
			System.out.println("BOB -- CIFAFINAL*******");
		
			// (4) Invio di (nA,nB) cifrati con la chiave pubblica di A
			// Create a secure random number generator
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			// Get 1024 random bits
			System.out.println("BOB -- NB*******");
			byte[] nonceB = new byte[64];
			sr.nextBytes(nonceB);
			// encrypt the plaintext using the public key
			cipher.init(Cipher.ENCRYPT_MODE, pKey);
			byte[] ciphredA  = cipher.doFinal(nonceA);
			byte length = (new Integer(ciphredA.length)).byteValue();
			out.write(length);
			out.write(ciphredA);
			out.flush();
			byte[] ciphredB = cipher.doFinal(nonceB);
			length = (new Integer(ciphredB.length)).byteValue();
			out.write(length);
			out.write(ciphredB);
			out.flush();
					
			// (5) Ricezione e verifica di nB
			byte[] nB;
			lengthBytes = new byte[1];
			in.read(lengthBytes,0,1);
			nonceLength = byteArrayToInt(lengthBytes);
			nB = new byte[nonceLength];
			in.read(nB,0,nonceLength);
			cipher.init(Cipher.DECRYPT_MODE, pKey);
			byte[] plainText = cipher.doFinal(nB);
			if(!Arrays.equals(plainText,nonceB))
				throw new BadNonceException();
			
			// (6) Diffie-Helmann
			// Perform the KeyAgreement
			System.out.println("Performing the KeyAgreement...");
			KeyAgreement ka = KeyAgreement.getInstance("DH", "BC");
			ka.init(keyPair.getPrivate());
			ka.doPhase(pKey, true);		
			// Generate a DES key
			byte[] sessionKeyBytes = ka.generateSecret();
			// Create the session key
			SecretKeyFactory skf = SecretKeyFactory.getInstance("TripleDES", "BC");
			DESedeKeySpec tripleDesSpec = new DESedeKeySpec(sessionKeyBytes);
			SecretKey sessionKey = skf.generateSecret(tripleDesSpec);

			// Chiusura degli stream.
			out.close();
			in.close();

			return sessionKey;

	}

}
