package it.saccosilvestri.jsp2p.utility;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import org.bouncycastle.openssl.PEMWriter;

public class FileUtility {

	public static void saveKeyToFile(String fileName, BigInteger mod, BigInteger exp)
			throws IOException {
		ObjectOutputStream out = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			out.writeObject(mod);
			out.writeObject(exp);
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			out.close();
		}
	}
	
	public static KeyPair readKeysFromFiles(String publicKeyFileName,
			String privateKeyFileName) throws IOException {
		ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(
				new FileInputStream(publicKeyFileName)));
		try {
			BigInteger m = (BigInteger) in.readObject();
			BigInteger e = (BigInteger) in.readObject();
			RSAPublicKeySpec pub = new RSAPublicKeySpec(m, e);
			KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
			PublicKey publicKey = fact.generatePublic(pub);
			in = new ObjectInputStream(new BufferedInputStream(
					new FileInputStream(privateKeyFileName)));
			m = (BigInteger) in.readObject();
			e = (BigInteger) in.readObject();
			RSAPrivateKeySpec priv = new RSAPrivateKeySpec(m, e);
			PrivateKey privateKey = fact.generatePrivate(priv);

			return new KeyPair(publicKey, privateKey);

		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			in.close();
		}
	}
}
