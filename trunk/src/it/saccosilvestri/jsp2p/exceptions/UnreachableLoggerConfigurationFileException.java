package it.saccosilvestri.jsp2p.exceptions;

import it.saccosilvestri.jsp2p.logging.LogManager;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class UnreachableLoggerConfigurationFileException extends Exception {

	public String getMessage() {
		return "Logger configuration File not found or not readable";
	}
	
	public UnreachableLoggerConfigurationFileException (){
		LogManager.currentLogger.fatal("Logger configuration File not found or not readable");
	}
}
