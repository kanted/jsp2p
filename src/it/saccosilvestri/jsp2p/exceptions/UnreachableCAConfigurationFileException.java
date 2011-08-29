package it.saccosilvestri.jsp2p.exceptions;

import it.saccosilvestri.jsp2p.logging.LogManager;


/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class UnreachableCAConfigurationFileException extends Exception {

	public String getMessage() {
		return "CA Configuration File not found or not readable";

	}
	
	public UnreachableCAConfigurationFileException (){
		LogManager.currentLogger.fatal("CA Configuration File not found or not readable");
	}
}
