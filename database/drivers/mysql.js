/*
 * This is an abstraction layer for mysql
 * 
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: 12/26/2018
 * 
 */

const mysql = require('mysql');

// initialise mysql connection
const pool = mysql.createPool(
    {
        connectionLimit: global.gConfig.db.connection_limit,
        database: global.gConfig.db.database,
        host: global.gConfig.db.host,
        user: global.gConfig.db.username,
        password: global.gConfig.db.password
    }
);

// Class that contains MySQL's query helper function
class MySQL {
    static query(sql, ...args) {
        // get connection from pool
        pool.getConnection((err, conn) => {
            if (err) throw err; // not connected

            if (args.length < 2) { // no binding
                conn.query(sql, (error, results, fileds) => {
                    // when done with the connection, release it.
                    conn.release();

                    // handle error after the release.
                    if (error) {
                        // return error to caller
                        args[0](error, results);

                    } else {
                        // reformat the result to recommended format if necessary
                        // code here

                        // return result to caller
                        args[0](null, results);
                    }
                });

            } else { // bind values to sql
                conn.query(sql, args[0], (error, results, fileds) => {
                    // when done with the connection, release it.
                    conn.release();

                    // handle error after the release.
                    if (error) {
                        // return error to caller
                        args[1](error, results);

                    } else {
                        // reformat the result to recommended format if necessary
                        // code here

                        // return result to caller
                        args[1](null, results);
                    }
                });
            }
        });
    }
}

module.exports = MySQL;