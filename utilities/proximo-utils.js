/*
 * Utitlies or helper function for Proximo
 *
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: __/__/__
 * 
 */

const proximo_model = require('../models/proximo-model');
var validator = require('validator');

class Utilities {
    constructor() {
        //Empty
    }

    /*
     * //
     */
    static compareToHashDataInDB(tableName, searches, ...args) {
        proximo_model.test();
        
        return new Promise((resolve) => {
            //iterate through the searches
            searches.forEach(search => {
                let { column, search } = search;
            });

            //executed successfully
            resolve();

            //throw new Error('Error occured');
        });
    }
}

//export the object that contains the utility functions
module.exports = Utilities;