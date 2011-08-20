package it.saccosilvestri.jsp2p.protocol;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
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
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class AliceProtocol {

	/**
	 * Static variables for 1024 bit Diffie-Hellman algorithm.
	 * 
	 * This is required to have matching moduli between client and server. The
	 * values are unimport, they simply must match. Ideally, everyone would
	 * agree on standard moduli, like SKIP, the Simple Key management for
	 * Internet Protocols spec.
	 * 
	 * You can get more info from http://www.skip.org
	 */
	private static final byte SKIP_1024_MODULUS_BYTES[] = { (byte) 0xF4,
			(byte) 0x88, (byte) 0xFD, (byte) 0x58, (byte) 0x4E, (byte) 0x49,
			(byte) 0xDB, (byte) 0xCD, (byte) 0x20, (byte) 0xB4, (byte) 0x9D,
			(byte) 0xE4, (byte) 0x91, (byte) 0x07, (byte) 0x36, (byte) 0x6B,
			(byte) 0x33, (byte) 0x6C, (byte) 0x38, (byte) 0x0D, (byte) 0x45,
			(byte) 0x1D, (byte) 0x0F, (byte) 0x7C, (byte) 0x88, (byte) 0xB3,
			(byte) 0x1C, (byte) 0x7C, (byte) 0x5B, (byte) 0x2D, (byte) 0x8E,
			(byte) 0xF6, (byte) 0xF3, (byte) 0xC9, (byte) 0x23, (byte) 0xC0,
			(byte) 0x43, (byte) 0xF0, (byte) 0xA5, (byte) 0x5B, (byte) 0x18,
			(byte) 0x8D, (byte) 0x8E, (byte) 0xBB, (byte) 0x55, (byte) 0x8C,
			(byte) 0xB8, (byte) 0x5D, (byte) 0x38, (byte) 0xD3, (byte) 0x34,
			(byte) 0xFD, (byte) 0x7C, (byte) 0x17, (byte) 0x57, (byte) 0x43,
			(byte) 0xA3, (byte) 0x1D, (byte) 0x18, (byte) 0x6C, (byte) 0xDE,
			(byte) 0x33, (byte) 0x21, (byte) 0x2C, (byte) 0xB5, (byte) 0x2A,
			(byte) 0xFF, (byte) 0x3C, (byte) 0xE1, (byte) 0xB1, (byte) 0x29,
			(byte) 0x40, (byte) 0x18, (byte) 0x11, (byte) 0x8D, (byte) 0x7C,
			(byte) 0x84, (byte) 0xA7, (byte) 0x0A, (byte) 0x72, (byte) 0xD6,
			(byte) 0x86, (byte) 0xC4, (byte) 0x03, (byte) 0x19, (byte) 0xC8,
			(byte) 0x07, (byte) 0x29, (byte) 0x7A, (byte) 0xCA, (byte) 0x95,
			(byte) 0x0C, (byte) 0xD9, (byte) 0x96, (byte) 0x9F, (byte) 0xAB,
			(byte) 0xD0, (byte) 0x0A, (byte) 0x50, (byte) 0x9B, (byte) 0x02,
			(byte) 0x46, (byte) 0xD3, (byte) 0x08, (byte) 0x3D, (byte) 0x66,
			(byte) 0xA4, (byte) 0x5D, (byte) 0x41, (byte) 0x9F, (byte) 0x9C,
			(byte) 0x7C, (byte) 0xBD, (byte) 0x89, (byte) 0x4B, (byte) 0x22,
			(byte) 0x19, (byte) 0x26, (byte) 0xBA, (byte) 0xAB, (byte) 0xA2,
			(byte) 0x5E, (byte) 0xC3, (byte) 0x55, (byte) 0xE9, (byte) 0x2F,
			(byte) 0x78, (byte) 0xC7 };

	private static final BigInteger MODULUS = new BigInteger(1,
			SKIP_1024_MODULUS_BYTES);
	private static final BigInteger BASE = BigInteger.valueOf(2);
	private static final DHParameterSpec PARAMETER_SPEC = new DHParameterSpec(
			MODULUS, BASE);

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

	public Key doService() throws CertificateException, IOException,
			SocketException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, BadNonceException, InvalidKeySpecException {

		InputStream in = clientSocket.getInputStream();
		OutputStream out = clientSocket.getOutputStream();
		
		//PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        //BufferedReader in = new BufferedReader(new InputStreamReader(
        	//	clientSocket.getInputStream()));

		// (1) Invio del certificato del peer
		byte[] certBytes = cert.getEncoded();
		out.write(certBytes);
		out.flush();

		// (2) Ricezione del certificato del peer, verifica ed estrazione della
		// chiave pubblica.
		byte[] certificate = {};
		in.read(certificate);
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate retrievedCert = (X509Certificate) fact
				.generateCertificate(in);
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
		byte[] cipherText = {};
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		System.out.println("ALICE -- NA*******");
		cipherText = cipher.doFinal(nonceA);
		System.out.println("LUNGHEZZA NA SU A"+cipherText.length);
		//TODO
		out.write(cipherText);
		out.flush();
		//TODO
		for(int i=0;i<cipherText.length;i++)
			System.out.print(cipherText[i]);
		System.out.println("FINENA");
		System.out.println("ALICE -- NA+NB*******");
		// (4) Ricezione di (nA,nB) cifrati con la mia chiave pubblica
		byte[] nA = new byte[64];
		byte[] nB = new byte[64];
		in.read(nA);
		in.read(nB);
		byte[] plainText = {};
		System.out.println("ALICE -- QUINDI111*******");
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		System.out.println("ALICE -- QUINDI222*******");
		plainText = cipher.doFinal(nA);
		System.out.println("ALICE -- CIFO*******");
		if (!Arrays.equals(plainText, nonceA))
			throw new BadNonceException();
		plainText = cipher.doFinal(nB);

		// (5) Invio di nB cifrato con la chiave pubblica di B
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		cipherText = cipher.doFinal(plainText);
		out.write(cipherText);
		out.flush();

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
