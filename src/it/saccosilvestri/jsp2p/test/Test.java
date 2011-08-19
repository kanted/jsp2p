package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.exceptions.BadNonceException;
import it.saccosilvestri.jsp2p.exceptions.UnreachableCAConfigurationFileException;
import it.saccosilvestri.jsp2p.exceptions.WrongCAConfigurationFileSyntaxException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Test {
	
	private static int NUM_PEER;

	public static void initialization()
			throws UnreachableCAConfigurationFileException,
			FileNotFoundException, IOException, WrongCAConfigurationFileSyntaxException
			{

		String configurationFilePath = new String("CA.conf");
		Properties configFile = new Properties();
		// Controllo che il file di configurazione esista e si possa aprire in
		// lettura.
		File file = new File(configurationFilePath);
		if (!file.canRead()) {
			throw new UnreachableCAConfigurationFileException();
		}
		configFile.load(new FileInputStream(configurationFilePath));
		try {
			NUM_PEER = 2;//TODO Integer.parseInt(configFile.getProperty("NUM_PEER"));
		} catch (Exception e) {
			throw new WrongCAConfigurationFileSyntaxException();
		}
	}

	public static void main(String[] args) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, BadNonceException, UnreachableCAConfigurationFileException, WrongCAConfigurationFileSyntaxException  {
		

		/* Lettura del file di configurazione */
		System.out.println("Initialization...");
		initialization();
		
		CertificationAuthority ca = new CertificationAuthority();
		System.out.println("Starting simulation");
		for(int i=0;i<NUM_PEER;i++){
			KeyPair kp = ca.generateCertificate(i);
			TestThread a = new TestThread ("certificate_for_peer_"+i+".crt","ca_certificate.crt",6000+i,true,kp);
		}
		for(int i=0;i<NUM_PEER;i++){
			KeyPair kp = ca.generateCertificate(i);
			TestThread b = new TestThread ("certificate_for_peer_"+i+".crt","ca_certificate.crt",6000+i,false,kp);
		}
	}

}
