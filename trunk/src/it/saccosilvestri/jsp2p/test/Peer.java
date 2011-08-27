package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.exceptions.UnreachableCAConfigurationFileException;
import it.saccosilvestri.jsp2p.exceptions.WrongCAConfigurationFileSyntaxException;
import it.saccosilvestri.jsp2p.utility.ConfigurationFileUtility;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
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
			
			AliceThread a = new AliceThread("certificate_for_peer_0" //TODO FARE BENE + i
						+ ".crt", "ca_certificate.crt", port, true, kp);
			
			
		
				BobThread b = new BobThread("certificate_for_peer_1" //TODO FARE BENE +i
						+ ".crt", "ca_certificate.crt", port, false, kp);

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}

}
