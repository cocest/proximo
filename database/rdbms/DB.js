/*
 * This initialise and load abtraction layer for database, 
 * DBMS abtraction layer that is loaded is base on settings on config.js file.
 * 
 * Note: config.js have to be loaded first, otherwise it will not 
 * find the settings to initialise and load needed abstraction
 * 
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: 12/26/2018
 * 
 */

let loaded_driver;

// load DBMS abstraction layer or driver
switch (global.gConfig.db.driver_name) {
    case 'mysql':
        loaded_driver = require('../drivers/mysql');
        break;

    // load other abstraction or drivers here

    default:
    // shouldn't be here
}

// add to global variables
global.gDB = loaded_driver;
