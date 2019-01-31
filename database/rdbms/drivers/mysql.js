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
const pool = mysql.createPool({
    connectionLimit: global.gConfig.db.connection_limit,
    database: global.gConfig.db.database,
    host: global.gConfig.db.host,
    user: global.gConfig.db.username,
    password: global.gConfig.db.password,
    supportBigNumbers: true
});

// Class that contains MySQL's query helper function
class MySQL {
    static query(sql, ...args) {
        return new Promise((resolve, reject) => {
            // get connection from pool
            pool.getConnection((err, conn) => {
                if (err) return reject(err); // not connected

                if (args.length > 0) { // bind values to sql
                    conn.query(sql, args[0], (err, results) => {
                        // when done with the connection, release it.
                        conn.release();

                        // handle error after the release.
                        if (err) return reject(err);

                        // reformat the result to recommended format if necessary
                        // code here

                        // result
                        return resolve(results);
                    });

                } else { // no binding
                    conn.query(sql, (err, results) => {
                        // when done with the connection, release it.
                        conn.release();

                        // handle error after the release.
                        if (err) return reject(err);

                        // reformat the result to recommended format if necessary
                        // code here

                        // result
                        return resolve(results);
                    });
                }
            });
        });
    }

    static transaction(...queries) {
        return new Promise((resolve, reject) => {
            // get connection from pool
            pool.getConnection((err, conn) => {
                if (err) return reject(err); // not connected

                if (queries.length < 1) return reject(new Error('No query pass as an argument'));

                // start transaction
                conn.beginTransaction(err => {
                    if (err) {
                        return conn.rollback(function () {
                            reject(error);
                        });
                    }

                    //start the execution
                    executeQueries(0);

                    function executeQueries(counter) {
                        conn.query(queries[counter].query, queries[counter].post, err, results => {
                            if (err) {
                                return conn.rollback(function () {
                                    reject(err);
                                });
                            }

                            // check if is last executed query
                            if (counter + 1 == queries.length) {
                                conn.commit(err => {
                                    if (err) {
                                        return conn.rollback(function () {
                                            reject(err);
                                        });
                                    }

                                    resolve(results);
                                });

                            } else { // there still queries to be executed
                                executeQueries(counter + 1);
                            }
                        });
                    }
                });
            });
        });
    }
}

module.exports = MySQL;