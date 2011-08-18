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
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Protocol {
	
	Socket clientSocket;
	KeyPair keyPair;
	X509Certificate cert;
	PublicKey caPublicKey;
	
	public Protocol(Socket cs, KeyPair kp, X509Certificate c, PublicKey capk) {
		clientSocket = cs;
		keyPair = kp;
		cert = c;
		caPublicKey = capk;
	}

	public void doService()
			throws CertificateException, IOException, SocketException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, BadNonceException {

			InputStream in = clientSocket.getInputStream();
			OutputStream out = clientSocket.getOutputStream();
			
			// (1) Invio del certificato del peer
			byte[] certBytes = cert.getEncoded();
			out.write(certBytes);
			
			// (2) Ricezione del certificato del peer, verifica ed estrazione della chiave pubblica.
			byte[] certificate = null;
			in.read(certificate);
			CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");			
			X509Certificate retrievedCert = (X509Certificate)fact.generateCertificate(in);
			// Basic validation
			System.out.println("Validating dates...");
			cert.checkValidity(new Date());
			System.out.println("Verifying signature...");
			cert.verify(caPublicKey);
			System.out.println("Dates and signature verified.");
			System.out.println("Retrieving PublicKey...");
			PublicKey pKey = retrievedCert.getPublicKey();
			
			// (3) Invio di un nonce cifrato con pKey
			
			// Create a secure random number generator
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG","BC");
			// Get 1024 random bits
			byte[] nonceA = new byte[1024/8];
			sr.nextBytes(nonceA);
			byte[] cipherText = null;
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
			// encrypt the plaintext using the public key
			cipher.init(Cipher.ENCRYPT_MODE, pKey);
			cipherText = cipher.doFinal(nonceA);
			out.write(cipherText);
			
			// (4) Ricezione di (nA,nB) cifrati con la chiave pubblica
			byte[] nA = new byte[1024/8];
			byte[] nB = new byte[1024/8];
			in.read(nA);
			in.read(nB);
			byte[] plainText = null;
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			plainText = cipher.doFinal(nA);
			if(!Arrays.equals(plainText,nonceA))
				throw new BadNonceException();
			plainText = cipher.doFinal(nB);
			
			
			out.close();
			in.close();

	}

}
