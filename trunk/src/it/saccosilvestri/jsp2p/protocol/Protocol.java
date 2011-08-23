package it.saccosilvestri.jsp2p.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

public class Protocol {

	private Socket clientSocket;
	private KeyPair keyPair;
	private X509Certificate cert;
	private PublicKey caPublicKey;
	InputStream in;
	OutputStream out;
	
	protected Protocol (Socket cs, KeyPair kp, X509Certificate c, PublicKey capk) throws IOException{
		clientSocket = cs;
		keyPair = kp;
		cert = c;
		caPublicKey = capk;
		in = clientSocket.getInputStream();
		out = clientSocket.getOutputStream();
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
	
	protected void sendMyCertificate () throws IOException, CertificateEncodingException {
		byte[] certBytes = cert.getEncoded();
		out.write(certBytes);
		out.flush();
    }
	
	protected PublicKey receiveCertificate() throws CertificateException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate retrievedCert = (X509Certificate) fact
				.generateCertificate(in);
		System.out.println("Controllo la data.");
		cert.checkValidity(new Date());
		System.out.println("Controllo la firma.");
		cert.verify(caPublicKey);
		System.out.println("Controlli eseguiti correttamente.");
		System.out.println("Ritorno la chiave pubblica.");
		return retrievedCert.getPublicKey();
	}
	
	protected void send(byte[] toSend) throws IOException{
		byte length = (new Integer(toSend.length)).byteValue();
		out.write(length);
		out.write(toSend);
		out.flush();
	}
	
	protected byte[] readNonce() throws IOException{
		byte[] lengthBytes = new byte[1];
		in.read(lengthBytes,0,1);
		int nonceLength = byteArrayToInt(lengthBytes);
		byte[] nonce = new byte[nonceLength];
		in.read(nonce,0,nonceLength);
		return nonce;
	}
	
	protected Key getPrivate(){
		return keyPair.getPrivate();
	}
	
	protected SecretKeySpec sessionKey(byte[] nonceA, byte[] nonceB) throws NoSuchAlgorithmException, NoSuchProviderException{
		byte[] key = new byte[nonceA.length+nonceB.length];
		System.arraycopy(nonceA, 0, key, 0, nonceA.length);
		System.arraycopy(nonceB, 0, key, nonceA.length, nonceB.length);
		MessageDigest sha = MessageDigest.getInstance("SHA-1","BC");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit
		return new SecretKeySpec(key, "AES");

	}
	
	protected void closeStreams() throws IOException{
		// Chiusura degli stream.
		out.close();
		in.close();
	}
	
}
