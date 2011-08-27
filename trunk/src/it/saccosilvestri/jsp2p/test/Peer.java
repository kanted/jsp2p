package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.exceptions.UnreachableCAConfigurationFileException;
import it.saccosilvestri.jsp2p.exceptions.WrongCAConfigurationFileSyntaxException;
import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;
import it.saccosilvestri.jsp2p.utility.ConfigurationFileUtility;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class Peer {

	private static int NUM_PEER;
	private static int i;
	private static KeyPair kp;
	
	public Peer(int i, KeyPair kp){
		this.i=i;
		this.kp=kp;
	}

	public static void main(String[] args) {

		try {

			int port = Integer.parseInt(args[0]);
			if(port<1024||port>65535){
				System.out.println("Attenzione. Inserire un numero di porta valido.");
				return;
			}
			
			System.out.println("Starting peer "+i);
			System.out.println("Recuperando il certificato per il peer "+i);
			FileInputStream f = new FileInputStream("ca_certificate.crt"); //TODO magari path nel file di conf.
			CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
			X509Certificate caCert = (X509Certificate) fact.generateCertificate(f);
			f = new FileInputStream("certificate_for_peer_"+i);
			X509Certificate peerCert = (X509Certificate) fact
					.generateCertificate(f);
			// Un peer è sia alice che bob contemporaneamente.
			AliceThread a = new AliceThread(peerCert, caCert, port, kp); 
			BobThread b = new BobThread(peerCert, caCert, port, kp);

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}

}
