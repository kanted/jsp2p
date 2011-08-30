package it.saccosilvestri.jsp2p.logging;

import it.saccosilvestri.jsp2p.exceptions.UnreachableLoggerConfigurationFileException;

import java.io.File;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

/**
* @brief Servizio di logging.
* @author Sacco Cosimo & Silvestri Davide
*/

public class LogManager {
	
	/**
     * Logger del servizio.
     */
    public static Logger currentLogger = null;

    /**
     * Metodo per l'inizializzazione del currentLogger
     */
    public static void initialization(String fileName) throws UnreachableLoggerConfigurationFileException {

        // Controllo che il file di configurazione esista e si possa aprire in lettura.
        File file = new File(fileName);
        if (!file.canRead()) {

                throw new UnreachableLoggerConfigurationFileException();
        }

        // Carico il file di configurazione.
        PropertyConfigurator.configure(fileName);

        // Ottengo un'instanza del logger.
        currentLogger = Logger.getLogger(LogManager.class);

    }


}
