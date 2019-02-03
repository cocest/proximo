/*
 * Using winston to log and display errors on console
 * when necessary. Some errors is logged to a file(s) in logs folder
 * 
 * Author: Attamah Celestine .C.
 * Date: 2/3/2019
 * 
 */

const winston = require('winston');

let logger = winston.createLogger({
    level: 'error',
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.printf(({
            timestamp,
            level,
            message
        }) => {
            return `${timestamp} ${level}: ${message}`;
        })
    ),
    defaultMeta: {
        service: 'Proximo-server'
    },
    transports: [
        // Write all logs error (and below) to `app.log`.
        new winston.transports.File({
            filename: '../logs/app.log',
            level: 'error'
        })
    ]
});

// If we're not in production then log to the console 
if (global.gConfig.config_id != 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.printf(({timestamp, level, message, stack}) => {
                // check to display error and stack trace
                if (global.gConfig.DEBUG_MODE == 'ON') {
                    return `${timestamp} ${level}: ${stack}`;

                } else { // server debug is turned off
                    return `${timestamp} ${level}: ${message}`;
                }
            })
        )
    }));
}

// add to global variables
global.gLogger = logger;