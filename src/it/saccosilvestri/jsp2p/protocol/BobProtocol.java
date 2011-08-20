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
import java.security.KeyPairGenerator;
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

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

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

	public Key doService()
			throws CertificateException, IOException, SocketException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, BadNonceException, InvalidKeySpecException {

		System.out.println("B");
		
			InputStream in = clientSocket.getInputStream();
			OutputStream out = clientSocket.getOutputStream();
			
			//TODO stratagemma per non leggere la lunghezza, dopo leggerla
			byte[] app = cert.getEncoded();
			int length = app.length;
			
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
			out.write(certBytes);
			out.flush();
			System.out.println("BOB ha inviato il certificato...");
			
			System.out.println("BOB -- NA*******");
			// (3) Ricezione di nA
			byte[] nA = new byte[64];
			in.read(nA);
			System.out.println("LUNGHEZZA NA SU B"+nA.length);
			//TODO
			for(int i=0;i<nA.length;i++)
				System.out.print(nA[i]);
			System.out.println("FINENADIB");
			byte[] nonceA = new byte[64];
			System.out.println("BOB -- CIFA*******");
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
			System.out.println("BOB -- QUINDI*******");
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			System.out.println("BOB -- QUIND000*******");
			nonceA = cipher.doFinal(nA);
			System.out.println("BOB -- CIFAFINAL*******");
		
			// (4) Invio di (nA,nB) cifrati con la chiave pubblica di A
			// Create a secure random number generator
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			// Get 1024 random bits
			System.out.println("BOB -- NB*******");
			byte[] nonceB = new byte[64];
			sr.nextBytes(nonceB);
			byte[] cipherText = new byte[64];
			// encrypt the plaintext using the public key
			cipher.init(Cipher.ENCRYPT_MODE, pKey);
			cipherText = cipher.doFinal(nonceA);
			out.write(cipherText);
			out.flush();
			cipherText = cipher.doFinal(nonceB);
			out.write(cipherText);
			out.flush();
					
			// (5) Ricezione e verifica di nB
			byte[] nB = new byte[64];
			in.read(nB);
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
