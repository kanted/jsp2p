package it.saccosilvestri.jsp2p.exceptions;

import it.saccosilvestri.jsp2p.logging.LogManager;
import java.security.cert.CertificateException;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class WrongSubjectDNException extends CertificateException {

	public String getMessage() {
		return "Certificate Subject DN is different from the one expected.";
	}
	
	public WrongSubjectDNException(){
		LogManager.currentLogger.error("Certificate Subject DN is different from the one expected.");
	}
}
