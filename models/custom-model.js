/*
 * This module contain utility or helper functions to manage,
 * set and retrieve data from database.
 * 
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: __/__/__
 * 
 */

 class Model {
     static getHashData(tableName, tableColumn, searches) {
         //get hash password
        let hash_password = gDB.get(tableName, [tableColumn], a);
        
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

 module.exports = Model;