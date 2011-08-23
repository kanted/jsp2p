package it.saccosilvestri.jsp2p.protocol;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AliceProtocol {

	private Socket clientSocket;
	private KeyPair keyPair;
	private X509Certificate cert;
	private PublicKey caPublicKey;

	public AliceProtocol(Socket cs, KeyPair kp, X509Certificate c,
			PublicKey capk) {
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

	public SecretKeySpec doService() throws CertificateException, IOException,
			SocketException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, BadNonceException, InvalidKeySpecException {

		System.out.println("A");
		InputStream in = clientSocket.getInputStream();
		OutputStream out = clientSocket.getOutputStream();
		
		//PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        //BufferedReader in = new BufferedReader(new InputStreamReader(
        	//	clientSocket.getInputStream()));

		// (1) Invio del certificato del peer
		byte[] certBytes = cert.getEncoded();
		//int length = certBytes.length;
		//out.write(length);
		out.write(certBytes);
		out.flush();
		System.out.println("A ha inviato il certificato...");
		
		// (2) Ricezione del certificato del peer, verifica ed estrazione della
		// chiave pubblica.
		//byte[] certificate = new byte[length];//TODO farsi dare la lunghezza
		//in.read(certificate);
		
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate retrievedCert = (X509Certificate) fact
				.generateCertificate(in);
		System.out.println("A ha letto il certificato...");
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
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		// Get 1024 random bits
		byte[] nonceA = new byte[64];
		sr.nextBytes(nonceA);
		Cipher cipher = Cipher.getInstance("RSA", "BC");
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		System.out.println("ALICE -- NA*******");
		byte[] cipherText  = cipher.doFinal(nonceA);
		System.out.println("LUNGHEZZA NA SU A"+cipherText.length);
		//TODO
		byte length = (new Integer(cipherText.length)).byteValue();
		out.write(length);
		out.write(cipherText);
		out.flush();
		
		//System.out.println("Sono A e STAMPO Na:");
		//TODO
		//for(int i=0;i<cipherText.length;i++)
		//	System.out.print(cipherText[i]);
		//System.out.println("FINENA");
		System.out.println("ALICE -- NA+NB*******");
		// (4) Ricezione di (nA,nB) cifrati con la mia chiave pubblica
		System.out.println("ALICE -- ReadNa*******");
		byte[] lengthBytes = new byte[1];
		in.read(lengthBytes,0,1);
		int nonceLength = byteArrayToInt(lengthBytes);
		System.out.println("LUNGHEZZA NA SU Ac DOPO"+nonceLength);
		byte[] nA = new byte[nonceLength];
		in.read(nA,0,nonceLength);
		System.out.println("ALICE -- ReadNb*******");
		lengthBytes = new byte[1];
		in.read(lengthBytes,0,1);
		nonceLength = byteArrayToInt(lengthBytes);
		byte[] nB = new byte[nonceLength];
		in.read(nB,0,nonceLength);
		System.out.println("ALICE -- QUINDI111*******");
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		System.out.println("ALICE -- QUINDI222*******");
		byte[] plainText = cipher.doFinal(nA);
		System.out.println("ALICE -- CIFO*******");
		if (!Arrays.equals(plainText, nonceA))
			throw new BadNonceException();
		byte[] nonceB = cipher.doFinal(nB);
		
		// (5) Invio di nB cifrato con la chiave pubblica di B
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		byte[] ciphredB = cipher.doFinal(nonceB);
		length = (new Integer(ciphredB.length)).byteValue();
		out.write(length);
		out.write(ciphredB);
		out.flush();

/*		// (6) Diffie-Helmann
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
		SecretKey sessionKey = skf.generateSecret(tripleDesSpec);*/
		
		//(6) Generazione chiave di sessione
		byte[] key = new byte[nonceA.length+nonceB.length];
		System.arraycopy(nonceA, 0, key, 0, nonceA.length);
		System.arraycopy(nonceB, 0, key, nonceA.length, nonceB.length);
		MessageDigest sha = MessageDigest.getInstance("SHA-1","BC");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

		// Chiusura degli stream.
		out.close();
		in.close();

		return secretKeySpec;

	}

}
