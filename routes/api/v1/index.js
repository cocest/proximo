/*
 * REST API VERSION 1
 */

const express = require('express');
const custom_utils = require('../../../utilities/custom-utils');
const path = require('path');
const url_parse = require('url-parse');
const body_parser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rand_token = require('rand-token');
const zxcvbn = require('zxcvbn');
const node_mailer = require('nodemailer');
const validator = require('validator');
const ejs = require('ejs');
const fs = require('fs');
const multer = require('multer');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.resolve(__dirname, gConfig.TEMP_FILE_STORAGE_PATH));
    },
    filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now());
    }
});
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 2 * 1024 * 1024
    }
}).single('upload');
const uploads = multer({
    storage: storage,
    limits: {
        fileSize: 2 * 1024 * 1024
    }
}).array('uploads', 4);
const aws = require('aws-sdk');
const sharp = require('sharp');
const file_type = require('file-type');
const smart_crop = require('smartcrop-sharp');

const router = express.Router();

// check and validate access token (JWT)
router.use(custom_utils.validateToken);

// check if user's account has been verified
router.use((req, res, next) => {
    // set variable
    if (!req.user) {
        req.user = {
            account_verified: null
        };

    } else {
        req.user.account_verified = null;
    }

    // check if OAuth2 JWT role is user
    if (req.user.access_token.role != 'user') {
        // is not user, don't check if account is verified
        return next();
    }

    // Redis access key
    const access_key = 'accountverified:' + req.user.access_token.user_id;

    // check if the key has been set
    gRedisClient.get(access_key, (err, reply) => {
        if (err) {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        }

        // reply is null when the key is not defined
        if (reply) { // key exist
            // check if user's account has been verified
            if (reply == 1) {
                req.user.account_verified = 1;

            } else { // account not verified
                req.user.account_verified = 0;
            }

            return next();
        }

        // key doesn't exist
        // get user's account verified status and save it to Redis
        gDB.query(
            'SELECT accountActivated FROM user WHERE userID = ? LIMIT 1',
            [req.user.access_token.user_id]
        ).then(results => {
            gRedisClient.set(access_key, results[0].accountActivated, 'EX', 60 * 5, (err, reply) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // check if user's account is verified
                if (results[0].accountActivated == 1) {
                    req.user.account_verified = 1;

                } else { // account not verified
                    req.user.account_verified = 0;
                }

                return next();
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    });
});

// rate limit incomming request
router.use((req, res, next) => {
    // check if rate limiting for each user request is enable
    if (gConfig.rate_limit_enabled) { // is on
        // check if the key is set, if not create new key
        gRedisClient.mget(
            [
                'ratest:' + req.user.access_token.user_id,
                'ratect:' + req.user.access_token.user_id
            ],
            (err, replies) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                if (replies[0]) { // first key exist
                    let start_time = parseInt(replies[0]);
                    let counter = parseInt(replies[1]);
                    let duration = Date.now() - start_time; // in milliseconds

                    // rate limit request
                    if (duration >= gConfig.rate_limit_time_window) { // check if time window has been reached
                        // reset start time and request counter
                        let multi = gRedisClient.multi();
                        multi.set('ratest:' + req.user.access_token.user_id, Date.now(), 'EX', req.user.access_token.exp);
                        multi.set('ratect:' + req.user.access_token.user_id, 1, 'EX', req.user.access_token.exp);
                        multi.exec((err, replies) => {
                            if (err) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            }

                            // set the response header
                            res.setHeader('X-RateLimit-Limit', gConfig.rate_limit);
                            res.setHeader('X-RateLimit-Remaining', gConfig.rate_limit - 1);
                            res.setHeader('X-RateLimit-Reset', Date.now() + gConfig.rate_limit_time_window); // UTC milliseconds since epoch time

                            next(); // move to next process
                        });

                    } else if (counter % (gConfig.rate_limit + 1) == 0) { // number of request per time window frame reached
                        let wait = gConfig.rate_limit_time_window - duration;

                        // send json error message to client
                        res.status(429);
                        res.setHeader('Retry-After', wait); // in milliseconds
                        res.json({
                            error_code: "limit_exceeded",
                            message: "API rate limit exceeded"
                        });

                        return;

                    } else { // increment request counter by one
                        gRedisClient.incr('ratect:' + req.user.access_token.user_id, (err, reply) => {
                            if (err) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            }

                            // set the response header
                            res.setHeader('X-RateLimit-Limit', gConfig.rate_limit);
                            res.setHeader('X-RateLimit-Remaining', gConfig.rate_limit - counter);
                            res.setHeader('X-RateLimit-Reset', start_time + gConfig.rate_limit_time_window); // UTC milliseconds since epoch time

                            next(); // move to next process
                        });
                    }

                } else { // set new key
                    let multi = gRedisClient.multi();
                    multi.set('ratest:' + req.user.access_token.user_id, Date.now(), 'EX', req.user.access_token.exp);
                    multi.set('ratect:' + req.user.access_token.user_id, 1, 'EX', req.user.access_token.exp);
                    multi.exec((err, replies) => {
                        if (err) {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;
                        }

                        // set the response header
                        res.setHeader('X-RateLimit-Limit', gConfig.rate_limit);
                        res.setHeader('X-RateLimit-Remaining', gConfig.rate_limit - 1);
                        res.setHeader('X-RateLimit-Reset', Date.now() + gConfig.rate_limit_time_window); // UTC milliseconds since epoch time

                        next(); // move to next process
                    });
                }
            });

    } else { // is off
        next(); // move to next
    }
});

// parse application/x-www-form-urlencoded parser
router.use(body_parser.urlencoded({
    extended: false
}));

// parse application/json
router.use(body_parser.json());

// create new user
router.post('/users', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if these fields are provided and valid: 
    // firstName, lastName, email, dateOfBirth, password and gender.

    const invalid_inputs = [];

    // allow name of this format "O'Reiley" and "Proximo"
    if (!req.body.firstName) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "firstName",
            message: "Firstname has to be defined"
        });

    } else if (!/^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.firstName)) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "firstName",
            message: "Firstname is not acceptable"
        });
    }

    if (!req.body.lastName) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "lastName",
            message: "Lastname has to be defined"
        });

    } else if (!/^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.lastName)) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "lastName",
            message: "Lastname is not acceptable"
        });
    }

    const dob = req.body.dateOfBirth ? req.body.dateOfBirth.split('-') : null;

    if (!req.body.dateOfBirth) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "dateOfBirth",
            message: "Date of birth has to be defined"
        });

    } else if (!(dob.length == 3 && custom_utils.validateDate({
        year: dob[0],
        month: dob[1],
        day: dob[2]
    }))) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "dateOfBirth",
            message: "Date of birth is invalid"
        });
    }

    if (!req.body.password) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "password",
            message: "Password has to be defined"
        });

    } else if (zxcvbn(req.body.password).score < 2) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "password",
            message: "Password is too weak"
        });
    }

    if (!req.body.gender) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "gender",
            message: "Gender has to be defined"
        });

    } else if (!/^(male|female|others)$/.test(req.body.gender)) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "gender",
            message: "Invalid gender"
        });
    }

    if (!req.body.email) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "email",
            message: "Email has to be defined"
        });

        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_field",
            errors: invalid_inputs,
            message: "Field(s) value not acceptable"
        });

        return;

    } else if (validator.isEmail(req.body.email)) {
        // generate hash of 40 characters length from user's email address 
        let search_email_hash = crypto.createHash("sha1").update(req.body.email, "binary").digest("hex");

        // check if email doesn't exist
        gDB.query('SELECT 1 FROM user WHERE searchEmailHash = ? LIMIT 1', [search_email_hash]).then(results => {
            if (results.length > 0) { // the SQL query is fast enough
                // email has been used by another user
                invalid_inputs.push({
                    error_code: "input_exist",
                    field: "email",
                    message: "Email address has been claimed"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;

            } else {
                // hash user's password before storing to database
                bcrypt.hash(req.body.password, 10).then(hash => {
                    // generate hash of 40 characters length from user's email address 
                    const search_email_hash = crypto.createHash("sha1").update(req.body.email, "binary").digest("hex");

                    // store user's information to database
                    gDB.transaction(
                        {
                            query: 'INSERT INTO user (firstName, lastName, emailAddress, searchEmailHash, dateOfBirth, gender) VALUES (?, ?, ?, ?, ?, ?)',
                            post: [
                                req.body.firstName,
                                req.body.lastName,
                                req.body.email,
                                search_email_hash,
                                req.body.dateOfBirth,
                                req.body.gender
                            ]
                        }, {
                            query: 'SELECT @user_id:=userID FROM user WHERE searchEmailHash = ? LIMIT 1',
                            post: [search_email_hash]
                        }, {
                            query: 'INSERT INTO userauthentication (userID, searchEmailHash, password) VALUES (@user_id, ?, ?)',
                            post: [
                                search_email_hash,
                                hash
                            ]
                        })
                        .then(results => {
                            gDB.query('SELECT userID FROM user WHERE searchEmailHash = ? LIMIT 1', [search_email_hash]).then(results => {
                                res.status(201);
                                res.json({
                                    user_id: results[0].userID,
                                    message: "New user created successfully"
                                });

                                return;
                            });
                        })
                        .catch(reason => {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', reason.message, {
                                stack: reason.stack
                            });

                            return;
                        });

                }).catch(reason => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', reason.message, {
                        stack: reason.stack
                    });

                    return;
                });
            }

        }).catch(reason => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', reason.message, {
                stack: reason.stack
            });

            return;
        });

    } else { // not valid
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "email",
            message: "Email is not acceptable"
        });

        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_field",
            errors: invalid_inputs,
            message: "Field(s) value not acceptable"
        });

        return;
    }
});

// update some user's signup information
router.put('/users/:user_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if some field contain invalid data
    const invalid_inputs = [];

    if (req.body.firstName && !/^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.firstName)) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "firstName",
            message: "Firstname is not acceptable"
        });
    }

    if (req.body.lastName && !/^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.lastName)) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "lastName",
            message: "Lastname is not acceptable"
        });
    }

    const dob = req.body.dateOfBirth ? req.body.dateOfBirth.split('-') : null;

    if (dob && !(dob.length == 3 && custom_utils.validateDate({
        year: dob[0],
        month: dob[1],
        day: dob[2]
    }))) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "dateOfBirth",
            message: "Date of birth is invalid"
        });
    }

    if (req.body.email && !validator.isEmail(req.body.email)) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "email",
            message: "Email is not acceptable"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_field",
            errors: invalid_inputs,
            message: "Field(s) value not acceptable"
        });

        return;
    }

    // update some user's profile information 
    let field_count = 0;
    let update_account_info = false;
    let query = 'UPDATE user SET ';
    let post = [];

    if (req.body.firstName) {
        query += 'firstName = ?';
        post.push(req.body.firstName);

        field_count++;
        update_account_info = true;
    }

    if (req.body.lastName) {
        if (field_count < 1) {
            query += 'lastName = ?';
            post.push(req.body.lastName);

        } else {
            query += ', lastName = ?';
            post.push(req.body.lastName);
        }

        field_count++;
        update_account_info = true;
    }

    if (req.body.dateOfBirth) {
        if (field_count < 1) {
            query += 'dateOfBirth = ?';
            post.push(req.body.dateOfBirth);

        } else {
            query += ', dateOfBirth = ?';
            post.push(req.body.dateOfBirth);
        }

        field_count++;
        update_account_info = true;
    }

    // check if email is not provided
    if (!req.body.email) {
        if (!update_account_info) {
            return res.status(200).send();
        }

        // last part of query
        query += ' WHERE userID = ? LIMIT 1';
        post.push(req.params.user_id);

        // update user's account information
        gDB.query(query, post).then(results => {
            return res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });


    } else { // email is provided
        // generate hash of 40 characters length from user's email address 
        const search_email_hash = crypto.createHash("sha1").update(req.body.email, "binary").digest("hex");

        // check if email has been used by another
        gDB.query(
            'SELECT userID, emailAddress FROM user WHERE searchEmailHash = ? LIMIT 1',
            [search_email_hash]
        ).then(results => {
            // email has been used
            if (results.length > 0 && results[0].userID != req.params.user_id) {
                invalid_inputs.push({
                    error_code: "input_exist",
                    field: "email",
                    message: "Email address has been claimed"
                });

                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // check if this is a user's new email address
            if (results.length < 1 || results[0].emailAddress != req.body.email) {
                // set sql update query for email
                query += ', emailAddress = ?, accountActivated = ?';
                post.push(req.body.email);
                post.push(0);

                update_account_info = true;
            }

            // last part of query
            query += ' WHERE userID = ? LIMIT 1';
            post.push(req.params.user_id);

            if (!update_account_info) {
                return res.status(200).send();
            }

            // update user's account information
            gDB.query(query, post).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }
});

// update user's sign-in password
router.post('/users/:user_id/updatePassword', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if some field contain invalid data
    const invalid_inputs = [];

    if (!req.body.currentPassword) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "currentPassword",
            message: "Password has to be defined"
        });
    }

    if (!req.body.newPassword) {
        invalid_inputs.push({
            error_code: "undefined_input",
            field: "newPassword",
            message: "password has to be defined"
        });

    } else if (zxcvbn(req.body.newPassword).score < 2) {
        invalid_inputs.push({
            error_code: "invalid_input",
            field: "newPassword",
            message: "Password is too weak"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0 && !req.body.currentPassword) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_field",
            errors: invalid_inputs,
            message: "Field(s) value not acceptable"
        });

        return;
    }

    // check if current password is correct
    gDB.query(
        'SELECT password FROM userauthentication WHERE userID = ? LIMIT 1',
        [req.params.user_id]
    ).then(results => {
        // compare password to hash in database
        bcrypt.compare(req.body.currentPassword, results[0].password).then(hash_res => {
            if (!hash_res) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "currentPassword",
                    message: "Password is incorrect"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // hash user's password before storing to database
            bcrypt.hash(req.body.newPassword, 10).then(hash => {
                // update user's password
                gDB.query(
                    'UPDATE userauthentication SET password = ? WHERE userID = ? LIMIT 1',
                    [hash, req.params.user_id]
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(reason => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', reason.message, { stack: reason.stack });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// generate sign-in password for the user that lost their password
router.post('/users/:user_id/generateSignInPassword', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // get user's email address
    gDB.query(
        'SELECT firstName, emailAddress FROM user WHERE userID = ? LIMIT 1',
        [req.params.user_id]
    ).then(results => {
        // generate eight digit unique id
        const gen_password = rand_token.generate(8);

        // hash generated password before storing to database
        bcrypt.hash(gen_password, 10).then(hash => {
            // send email first
            // set up the relative path
            let file_path = path.resolve(__dirname, '../views/signinpassword.ejs');

            // temporary store rendered file as string
            let rendered_file_str;

            ejs.renderFile(
                file_path, {
                    username: results[0].firstName,
                    password: gen_password,
                    year: (new Date()).getFullYear()
                }, (err, str) => {
                    rendered_file_str = str;
                }
            );

            // set up the mailer
            let transporter = node_mailer.createTransport({
                host: gConfig.SMTP_SERVER,
                port: gConfig.SMTP_PORT,
                secure: true,
                auth: {
                    user: gConfig.SMTP_USERNAME,
                    pass: gConfig.SMTP_PASSWORD
                }
            });

            let mail_options = {
                from: `"Proximonet" <${gConfig.SMTP_FROM}>`,
                to: results[0].emailAddress,
                subject: 'Your account sign-in password',
                html: rendered_file_str
            };

            transporter.sendMail(mail_options, (err, info) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Message can't be sent"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // check if email is rejected
                if (info.rejected.length > 0) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Email was rejected by the server"
                    });

                    return;

                } else { // email sent successfully
                    // update user's password
                    gDB.query(
                        'UPDATE userauthentication SET password = ? WHERE userID = ? LIMIT 1',
                        [hash, req.params.user_id]
                    ).then(results => {
                        return res.status(200).send();

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                }
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// validate registration fields or inputs
router.post('/user/validateSignUpInputs', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;

    } else {
        const invalid_inputs = [];

        if (req.body.firstName && !/^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.firstName)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "firstName",
                message: "Firstname is not acceptable"
            });
        }

        if (req.body.lastName && !/^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.lastName)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "lastName",
                message: "Lastname is not acceptable"
            });
        }

        if (req.body.dateOfBirth) {
            let dob = req.body.dateOfBirth.split('-');

            if (!(dob.length == 3 && custom_utils.validateDate({
                year: dob[0],
                month: dob[1],
                day: dob[2]
            }))) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "dateOfBirth",
                    message: "Date of birth is invalid"
                });
            }
        }

        if (req.body.password && zxcvbn(req.body.password).score < 2) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "password",
                message: "Password is too weak"
            });
        }

        if (req.body.email && validator.isEmail(req.body.email)) {
            // generate hash of 40 characters length from user's email address 
            let search_email_hash = crypto.createHash("sha1").update(req.body.email, "binary").digest("hex");

            // check if email has been claimed
            gDB.query(
                'SELECT 1 FROM user WHERE searchEmailHash = ? LIMIT 1',
                [search_email_hash]
            ).then(results => {
                if (results.length > 0) { // the SQL query is fast enough
                    // email has been used by another user
                    invalid_inputs.push({
                        error_code: "input_exist",
                        field: "email",
                        message: "Email address has been claimed"
                    });
                }

                // check if any input is invalid
                if (invalid_inputs.length > 0) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "invalid_field",
                        errors: invalid_inputs,
                        message: "Field(s) value not acceptable"
                    });

                    return;

                } else {
                    return res.status(200).send();
                }

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        } else if (req.body.email) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "email",
                message: "Email is not acceptable"
            });

            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs,
                message: "Field(s) value not acceptable"
            });

            return;

        } else {
            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;

            } else {
                return res.status(200).send();
            }
        }

    }
});

// send verification code to user's email address
router.post('/users/:id/email/sendVerification', custom_utils.allowedScopes(['write:users', 'write:users:all']), (req, res) => {
    // check if id is interger
    if (/^\d+$/.test(req.params.id)) {
        // get user email address
        gDB.query('SELECT firstName, emailAddress, accountActivated FROM user WHERE userID = ? LIMIT 1', [req.params.id]).then(results => {
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "match_not_found",
                    message: "User id doesn't match any"
                });

                return;

            } else if (results[0].accountActivated == 0) { // check if account is not activated
                let access_key = 'emailverification:' + req.params.id;

                // check if key does not exist or has been expired
                gRedisClient.get(access_key, (err, reply) => {
                    if (err) {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    }

                    // reply is null when the key is missing
                    if (reply) { // key exist
                        res.status(425);
                        res.json({
                            error_code: "too_early",
                            message: "Activation code still exist"
                        });

                        return;

                    } else { // key doesn't exist
                        // generate six digit verification code
                        let verification_code = rand_token.generate(6, '0123456789');

                        // set up the relative path
                        let file_path = path.resolve(__dirname, '../views/emailVerification.ejs');

                        let rendered_file_str;

                        ejs.renderFile(
                            file_path, {
                                username: results[0].firstName,
                                code: verification_code,
                                year: (new Date()).getFullYear()
                            }, (err, str) => {
                                rendered_file_str = str;
                            }
                        );

                        // set up the mailer
                        let transporter = node_mailer.createTransport({
                            host: gConfig.SMTP_SERVER,
                            port: gConfig.SMTP_PORT,
                            secure: true,
                            auth: {
                                user: gConfig.SMTP_USERNAME,
                                pass: gConfig.SMTP_PASSWORD
                            }
                        });

                        let mail_options = {
                            from: `"Proximonet" <${gConfig.SMTP_FROM}>`,
                            to: results[0].emailAddress,
                            subject: 'Email Verification',
                            html: rendered_file_str
                        };

                        transporter.sendMail(mail_options, (err, info) => {
                            if (err) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Message can't be sent"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            }

                            // check if email is rejected
                            if (info.rejected.length > 0) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Email was rejected by the server"
                                });

                                return;

                            } else { // email sent successfully
                                // expiration set to 10 minutes
                                let code_expiration = 60 * 10;

                                // store the verification code to database (redis) with
                                gRedisClient.set(access_key, verification_code, 'EX', code_expiration, (err, replay) => {
                                    if (err) {
                                        res.status(500);
                                        res.json({
                                            error_code: "internal_error",
                                            message: "Internal error"
                                        });

                                        // log the error to log file
                                        gLogger.log('error', err.message, {
                                            stack: err.stack
                                        });

                                        return;

                                    } else {
                                        res.status(201);
                                        res.json({
                                            code_expiration: code_expiration
                                        });

                                        return;
                                    }
                                });
                            }
                        });
                    }
                });

            } else { // account is already activated
                res.status(409);
                res.json({
                    error_code: "already_processed",
                    message: "Action has been performed"
                });

                return;
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// confirm verification entered by the user
router.post('/users/:id/email/confirmVerification', custom_utils.allowedScopes(['write:users', 'write:users:all']), (req, res) => {
    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if id is interger
    if (/^\d+$/.test(req.params.id)) {
        if (!req.body.code) {
            res.status(400);
            res.json({
                error_code: "invalid_request",
                message: "Bad request"
            });

            return;
        }

        let access_key = 'emailverification:' + req.params.id;

        // get stored verification code
        gRedisClient.get(access_key, (err, reply) => {
            if (err) {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // reply is null when the key is missing
            if (!reply) { // key doesn't exist
                res.status(404);
                res.json({
                    error_code: "data_not_found",
                    message: "Activation code not defined or expired"
                });

                return;

            } else { // key exist
                // check if code match
                if (reply == req.body.code) {
                    // activate user account
                    gDB.query(
                        'UPDATE user SET accountActivated = 1 WHERE userID = ? LIMIT 1',
                        [req.params.id]
                    ).then(results => {
                        return res.status(200).send();

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                } else { // activation code supplied by user is wrong
                    res.status(406);
                    res.json({
                        error_code: "invalid_code_match",
                        message: "Invalid activation code"
                    });

                    return;
                }
            }
        });

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// check account status
router.get('/users/:user_id/accountStatus', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // get user's account state
    gDB.query(
        'SELECT accountActivated FROM user WHERE userID = ? LIMIT 1',
        [req.params.user_id]
    ).then(results => {
        res.status(200);
        res.json({
            account_verified: results[0].accountActivated
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// upload profile picture for the user
router.post('/users/:user_id/profile/picture', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    //check if user pass area to crop and pass query is correct
    if (req.query.crop && !/^(\d+,\d+,\d+|auto)$/.test(req.query.crop)) {
        res.status(400);
        res.json({
            error_code: "invalid_query",
            message: "URL query is invalid"
        });

        return;
    }

    upload(req, res, (err) => {
        // check if enctype is multipart form data
        if (!req.is('multipart/form-data')) {
            res.status(415);
            res.json({
                error_code: "invalid_request_body",
                message: "Encode type not supported"
            });

            return;
        }

        // check if file contain data
        if (!req.file) {
            res.status(400);
            res.json({
                error_code: "invalid_request",
                message: "Bad request"
            });

            return;
        }

        // A Multer error occurred when uploading
        if (err instanceof multer.MulterError) {
            if (err.code == 'LIMIT_FILE_SIZE') {
                res.status(400);
                res.json({
                    error_code: "size_exceeded",
                    message: "Image your uploading exceeded allowed size"
                });

                return;
            }

            // other multer errors
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;

        } else if (err) { // An unknown error occurred when uploading
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        }

        let file_path = req.file.path; // uploaded file location
        const save_image_ext = 'png';

        // read uploaded image as buffer
        let image_buffer = fs.readFileSync(file_path);

        // check file type and if is supported
        let supported_images = [
            'jpg',
            'png',
            'gif',
            'jp2'
        ];

        // read minimum byte from buffer required to determine file mime
        let file_mime = file_type(Buffer.from(image_buffer, 0, file_type.minimumBytes));

        if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
            // delete the uploaded file
            fs.unlinkSync(file_path);

            res.status(406);
            res.json({
                error_code: "unsupported_format",
                message: "Uploaded image is not supported"
            });

            return;
        }

        // set aws s3 access credentials
        aws.config.update({
            apiVersion: '2006-03-01',
            accessKeyId: gConfig.AWS_ACCESS_ID,
            secretAccessKey: gConfig.AWS_SECRET_KEY,
            region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
        });

        const s3 = new aws.S3();

        // process the image
        const processImage = crop => {
            //crop the image
            sharp(image_buffer)
                .extract({
                    left: crop.x,
                    top: crop.y,
                    width: crop.width,
                    height: crop.height
                })
                .toBuffer()
                .then(outputBuffer => {
                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    // resize the image to required sizes
                    const resize = size => {
                        return new Promise((resolve, rejected) => {
                            sharp(outputBuffer)
                                .resize(size, size, {
                                    withoutEnlargement: true
                                })
                                .toFormat(save_image_ext)
                                .toBuffer()
                                .then(buffer => {
                                    // resolve the promise
                                    resolve({
                                        size,
                                        buffer
                                    });
                                })
                                .catch(err => {
                                    rejected(err);
                                });
                        });
                    };

                    Promise.all([280, 120, 50].map(resize)).then(datas => {
                        // save the resized image to aws s3 bucket
                        // upload each file
                        const uploadImage = pass_data => {
                            return new Promise((resolve, rejected) => {
                                const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;

                                const upload_params = {
                                    Bucket: gConfig.AWS_S3_BUCKET_NAME,
                                    Body: pass_data.buffer,
                                    Key: 'user/images/profile/' + object_unique_name,
                                    ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                                };

                                s3.upload(upload_params, (err, data) => {
                                    if (err) {
                                        rejected(err);

                                    } else {
                                        resolve([pass_data.size, data]); // file uploaded successfully
                                    }
                                });
                            });
                        };

                        Promise.all(datas.map(uploadImage)).then(datas => {
                            // convert datas to map
                            const dm = new Map(datas);

                            //store profile image position to database
                            gDB.query(
                                'UPDATE user SET profilePictureSmallURL = ?, profilePictureMediumURL = ?, profilePictureBigURL = ? WHERE userID = ? LIMIT 1',
                                [
                                    url_parse(dm.get(50).Location, true).pathname.replace('/', ''),
                                    url_parse(dm.get(120).Location, true).pathname.replace('/', ''),
                                    url_parse(dm.get(280).Location, true).pathname.replace('/', ''),
                                    req.params.user_id
                                ]
                            ).then(results => {
                                res.status(200);
                                res.json({
                                    image: {
                                        big: dm.get(280).Location,
                                        medium: dm.get(120).Location,
                                        small: dm.get(50).Location
                                    }
                                });

                                return;

                            }).catch(err => {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            });

                        }).catch(err => {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;
                        });

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                })
                .catch(err => {
                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
        };

        // get crop rectangle for uploaded profile picture
        const getCropRect = call => {
            //check if user pass area to crop
            if (req.query.crop && /^\d+,\d+,\d+$/.test(req.query.crop)) {
                let temp_crop = req.query.crop.split(',');

                call({
                    x: temp_crop[0],
                    y: temp_crop[1],
                    width: temp_crop[2],
                    height: temp_crop[2]
                });

            } else { // user set crop to auto or crop not defined
                // return area to crop taking object or face into consideration
                smart_crop.crop(image_buffer, {
                    width: 100,
                    height: 100,
                    minScale: 1,
                    ruleOfThirds: true
                }).then(result => {
                    call(result.topCrop);

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }
        };

        // check if profile pictures exist and delete them before new upload
        gDB.query(
            'SELECT profilePictureSmallURL, profilePictureMediumURL, profilePictureBigURL FROM user WHERE userID = ? LIMIT 1',
            [req.params.user_id]).then(results => {
                //check if it exist
                if (results[0].profilePictureSmallURL) {
                    // initialise objects to delete
                    const deleteParam = {
                        Bucket: gConfig.AWS_S3_BUCKET_NAME,
                        Delete: {
                            Objects: [
                                {
                                    Key: results[0].profilePictureSmallURL
                                },
                                {
                                    Key: results[0].profilePictureMediumURL
                                },
                                {
                                    Key: results[0].profilePictureBigURL
                                }
                            ]
                        }
                    };

                    s3.deleteObjects(deleteParam, (err, data) => {
                        if (err) {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;

                        } else {
                            getCropRect(processImage);
                        }
                    });

                } else { // doesn't exist
                    getCropRect(processImage);
                }

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
    });
});

// get user's profile pictures
router.get('/users/:user_id/profile/picture', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if pass query is valid
    if (req.query.size && !/^(big|medium|small)$/.test(req.query.size)) {
        res.status(400);
        res.json({
            error_code: "invalid_query",
            message: "URL query is invalid"
        });

        return;
    }

    // set image to retrieve
    const image_size = req.query.size ? req.query.size : 'medium';

    // mysql fields
    const query_fields = {
        'big': 'profilePictureBigURL',
        'medium': 'profilePictureMediumURL',
        'small': 'profilePictureSmallURL'
    };

    // get image relative path from database
    gDB.query(
        'SELECT ?? FROM user WHERE userID = ? LIMIT 1',
        [query_fields[image_size], req.params.user_id]
    ).then(results => {
        // check if image exist
        if (results[0][query_fields[image_size]]) {
            res.status(200);
            res.json({
                image: {
                    url: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0][query_fields[image_size]],
                    size: image_size
                }
            });

            return;

        } else {
            res.status(200);
            res.json({
                image: null
            });

            return;
        }

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// set user's profile information
router.put('/users/:user_id/profile', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if some field contain valid data
    const invalid_inputs = [];

    if (req.body.bio) {
        if (typeof req.body.bio != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "bio",
                message: "data type not supported"
            });

        } else if (req.body.bio.length > 500) { // check if about exceed 500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "bio",
                message: "bio exceed maximum allowed text"
            });
        }
    }

    if (req.body.about) {
        if (typeof req.body.about != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "about",
                message: "data type not supported"
            });

        } else if (req.body.about.length > 1500) { // check if about exceed 1500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "about",
                message: "about exceed maximum allowed text"
            });
        }
    }

    // check if any field is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_field",
            errors: invalid_inputs,
            message: "Field(s) value is invalid"
        });

        return;
    }

    // update some user's profile information 
    let query = 'UPDATE user SET ';
    let post = [];
    let input_count = 0;

    // check if bio is provided
    if (req.body.bio) {
        query += 'bio = ?';
        post.push(req.body.bio.trim());
        input_count++;
    }

    // check if about is provided
    if (req.body.about) {
        if (input_count < 1) {
            query += 'about = ?';
            query_post.push(req.body.about);

        } else {
            query += ', about = ?';
            query_post.push(req.body.about);
        }

        input_count++;
    }

    //last part of query
    query += ' WHERE userID = ? LIMIT 1';
    post.push(req.params.user_id);

    gDB.query(query, post).then(results => {
        return res.status(200).send();

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get user's profile information
router.get('/users/:user_id/profile', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    const permitted_fields = [
        'bio',
        'about'
    ];

    let query = 'SELECT ';

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && permitted_fields.find(q => q == elem)) {
                if (permitted_field_count == 0) {
                    query += `${elem}`;

                } else {
                    query += `, ${elem}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            query = 'SELECT bio, about FROM user WHERE userID = ? LIMIT 1';

        } else {
            query += ' FROM user WHERE userID = ? LIMIT 1';
        }

    } else { // no fields selection
        query += 'SELECT bio, about FROM user WHERE userID = ? LIMIT 1';
    }

    // get user's profile information
    gDB.query(query, [req.params.user_id]).then(results => {
        // send result to client
        res.status(200);
        res.json(results[0]);

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get categories for article or news
router.get('/publications/:publication_type/categories', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check if publication_type is article or news
    if (!/^(article|news)$/.test(req.params.publication_type)) {
        res.status(404);
        res.json({
            error_code: "file_not_found",
            message: "File not found"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    const table_name = req.params.publication_type + '_categories';

    // retrieve categories from database
    gDB.query('SELECT categoryID AS id, categoryTitle AS category FROM ??', [table_name]).then(results => {
        res.status(200);
        res.json({
            categories: results
        });

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack

        });

        return;
    });
});

// get areas users can publish content
router.get('/publishLocation/:location', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check the location
    if (!/^(countries|regions)$/.test(req.params.location)) {
        res.status(404);
        res.json({
            error_code: "file_not_found",
            message: "File not found"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // set limit and offset
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    let country_id = req.query.countryID;
    const invalid_inputs = [];

    // check if query is valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    if (country_id && !/^\d+$/.test(country_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "countryID",
            message: "value must be integer"
        });
    }

    // check if any query is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    if (pass_limit && pass_limit < limit) {
        limit = pass_limit;
    }

    if (pass_offset) {
        offset = pass_offset;
    }

    // total count of rows in countries table
    gDB.query('SELECT COUNT(*) AS total FROM ??', ['map_' + req.params.location]).then(count_results => {
        if (req.params.location == 'countries') {
            // select countries from database
            gDB.query(
                `SELECT countryID AS id, name AS country FROM map_countries LIMIT ${limit} OFFSET ${offset}`
            ).then(results => {
                res.status(200);
                res.json({
                    countries: results,
                    metadata: {
                        result_set: {
                            count: results.length,
                            offset: offset,
                            limit: limit,
                            total: count_results[0].total
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        } else { // regions
            // get country to select regions from
            if (country_id) {
                gDB.query(
                    `SELECT regionID AS id, name AS region FROM map_regions WHERE countryID = ? LIMIT ${limit} OFFSET ${offset}`,
                    [country_id]
                ).then(results => {
                    res.status(200);
                    res.json({
                        regions: results,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: count_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            } else {
                // select regions from database
                gDB.query(`SELECT regionID AS id, name AS region FROM map_regions LIMIT ${limit} OFFSET ${offset}`).then(results => {
                    res.status(200);
                    res.json({
                        regions: results,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: count_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }
        }
    });
});

// get a region or nearest region if user is not in any launch region on map
router.get('/map/region', custom_utils.allowedScopes(['read:map']), (req, res) => {
    // validate pass in query values
    const invalid_inputs = [];

    if (!req.query.lat) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "lat",
            message: "lat has to be defined"
        });

    } else if (!/^(\d+.\d+|\d+)$/.test(req.query.lat)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "lat",
            message: "lat value is invalid"
        });
    }

    if (!req.query.long) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "long",
            message: "long has to be defined"
        });

    } else if (!/^(\d+.\d+|\d+)$/.test(req.query.long)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "long",
            message: "long value is invalid"
        });
    }

    // check if any query is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    // longitude and latitude
    const position = { x: req.query.long, y: req.query.lat };
    let cont_bounds;
    let cont_polys;
    let temp_cont_polys = [];
    let region_found = false;
    let closest_region;
    let shortest_distance1;
    let shortest_distance2;
    let loop_quit = false;

    // utility function to process region
    const utilRegion = countryID => {
        return new Promise((resolve, reject) => {
            // found which country user's lat and long fall into
            gDB.query(
                'SELECT regionID, name, polygons, bounds FROM map_regions WHERE countryID = ?',
                [countryID]
            ).then(results => {
                // check which region user location fall into
                for (let k = 0; k < results.length; k++) {
                    //convert string to javascript object
                    cont_bounds = JSON.parse(results[k].bounds);
                    cont_polys = JSON.parse(results[k].polygons);

                    // temporary store the parse polygons
                    temp_cont_polys.push(cont_polys);

                    // check for region user's position fall into
                    if (custom_utils.pointInsideRect(position, cont_bounds) &&
                        custom_utils.pointInsidePolygon(position, cont_polys)) {
                        //send user's location to client
                        res.status(200);
                        res.json({
                            location_id: results[k].regionID,
                            location_name: results[k].name
                        });

                        region_found = true;
                        break;
                    }
                }

                // check if region is not found
                if (!region_found) {
                    // check for which region is closer to user's location
                    shortest_distance1 = custom_utils.pointDistanceFromObj(position, temp_cont_polys[0]);
                    closest_region = results[0];

                    for (let n = 1; n < results.length; n++) {
                        // calculate the distance of region from user's current position
                        shortest_distance2 = custom_utils.pointDistanceFromObj(position, temp_cont_polys[n]);

                        // replace with smaller distance
                        if (shortest_distance2 < shortest_distance1) {
                            shortest_distance1 = shortest_distance2;
                            closest_region = results[n];
                        }
                    }

                    // return result of closest region to client
                    res.status(200);
                    res.json({
                        location_id: closest_region.regionID,
                        location_name: closest_region.name
                    });
                }

                // signal loop break
                resolve(true);

            }).catch(err => {
                reject(err);
            });
        });
    };

    // utility function to process countries
    const utilCountry = continentID => {
        return new Promise((resolve, reject) => {
            // found which country user's lat and long fall into
            gDB.query(
                'SELECT countryID, polygons, bounds FROM map_countries WHERE continentID = ?',
                [continentID]
            ).then(results => {
                async function processRegions() {
                    // check which country user location fall into
                    for (let j = 0; j < results.length; j++) {
                        // check if is to quit
                        if (loop_quit) break;

                        //convert string to javascript object
                        cont_bounds = JSON.parse(results[j].bounds);
                        cont_polys = JSON.parse(results[j].polygons);

                        // check if user doesn't fall into any country
                        if (!(custom_utils.pointInsideRect(position, cont_bounds) &&
                            custom_utils.pointInsidePolygon(position, cont_polys))) {

                            continue;
                        }

                        await utilRegion(results[j].countryID).then(exit_loop => {
                            // check to signall loop break
                            if (exit_loop) loop_quit = true;

                        }).catch(err => {
                            // signall loop break
                            loop_quit = true;

                            // send back response
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });
                        });
                    }

                    // check if quit is false
                    if (!loop_quit) {
                        //  service not available at user's location
                        res.status(404);
                        res.json({
                            error_code: "unsupported_location",
                            message: "Service not available at the location"
                        });
                    }

                    // signal loop break
                    resolve(true);
                };

                processRegions();

            }).catch(err => {
                reject(err);
            });
        });
    };


    // found which continent user's long and lat fall into
    gDB.query('SELECT continentID, polygons, bounds FROM map_continents').then(results => {
        async function processCountries() {
            // check which continet user location fall into
            for (let i = 0; i < results.length; i++) {
                // check if is to quit
                if (loop_quit) break;

                //convert string to javascript object
                cont_bounds = JSON.parse(results[i].bounds);
                cont_polys = JSON.parse(results[i].polygons);

                // check if user doesn't fall into any continent
                if (!(custom_utils.pointInsideRect(position, cont_bounds) &&
                    custom_utils.pointInsidePolygon(position, cont_polys))) {

                    continue;
                }

                await utilCountry(results[i].continentID).then(exit_loop => {
                    // check to signall loop break
                    if (exit_loop) loop_quit = true;

                }).catch(err => {
                    // signall loop break
                    loop_quit = true;

                    // send back response
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });
                });
            }

            // check if quit is false
            if (!loop_quit) {
                //  service not available at user's location
                res.status(404);
                res.json({
                    error_code: "unsupported_location",
                    message: "Service not available at the location"
                });
            }
        };

        processCountries();

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

/*
 * save newly created news or article to draft and return a 
 * unique id that identified the draft
 */
router.post('/users/:user_id/drafts', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if some field contain valid data
    let invalid_inputs = [];

    // check if query is valid
    if (!req.query.publication) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "publication",
            message: "publication has to be defined"
        });

    } else if (!/^(news|article)$/.test(req.query.publication)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "publication",
            message: "publication value is invalid"
        });
    }

    if (!req.query.categoryID) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "categoryID",
            message: "categoryID has to be defined"
        });

    } else if (!/^\d+$/.test(req.query.categoryID)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });

    } else {
        // check if category id exist
        gDB.query(
            'SELECT categoryTitle FROM ?? WHERE categoryID = ? LIMIT 1',
            [req.query.publication + '_categories', req.query.categoryID]
        ).then(results => {
            if (results.length < 1) { // the SQL query is fast enough
                // category does not exist
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "categoryID",
                    message: "categoryID doesn't exist"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs,
                    message: "Query(s) value is invalid"
                });

                return;
            }

            // re-define array to clear previous data
            invalid_inputs = [];

            // check if featured image URL is valid if is provided
            if (req.body.featuredImageURL && validator.isURL(req.body.featuredImageURL)) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "featuredImageURL",
                    message: "URL is invalid"
                });
            }

            // check body data type if is provided
            if (req.body.title && typeof req.body.title != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "title",
                    message: "title is not acceptable"
                });

            } else if (req.body.title && req.body.title.length > 150) { // check if title exceed 150 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "title",
                    message: "title exceed maximum allowed text"
                });
            }

            // check body data type if is provided
            if (req.body.content && typeof req.body.content != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "content",
                    message: "content is not acceptable"
                });
            }

            // check body data type if is provided
            if (req.body.highlight && typeof req.body.highlight != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "highlight",
                    message: "highlight is not acceptable"
                });

            } else if (req.body.highlight && req.body.highlight.length > 500) { // check if highlight exceed 500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "highlight",
                    message: "highlight exceed maximum allowed text"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // generate sixten digit unique id
            const draft_id = rand_token.generate(16);

            // save news or article to user's draft
            gDB.query(
                'INSERT INTO draft (draftID, userID, categoryID, category, publication, ' +
                'featuredImageURL, title, highlight, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    draft_id,
                    req.params.user_id,
                    req.query.categoryID,
                    results[0].categoryTitle,
                    req.query.publication,
                    req.body.featuredImageURL ? req.body.featuredImageURL : '',
                    req.body.title ? req.body.title : '',
                    req.body.highlight ? req.body.highlight : '',
                    req.body.content ? req.body.content : '',
                ]
            ).then(results => {
                res.status(201);
                res.json({
                    draft_id: draft_id
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }
});

/*
 * Add news to draft for edit and return
 * unique id that identified the draft
 * 
 * For already published news, you can't change it location
 */
router.post('/users/:user_id/news/:news_id/edit', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is valid
    if (!(/^\d+$/.test(req.params.user_id) && /^\d+$/.test(req.params.news_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // generate sixten digit unique id
    const draft_id = rand_token.generate(16);

    gDB.query(
        'SELECT categoryID, featuredImageURL, title, ' +
        'highlight, content FROM news WHERE newsID = ? AND userID = ? LIMIT 1',
        [req.params.news_id, req.params.user_id]
    ).then(news_results => {
        // check if article exist 
        if (news_results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News can't be found"
            });

            return;
        }

        // get publication category name
        gDB.query(
            'SELECT categoryTitle FROM news_categories WHERE categoryID = ? LIMIT 1',
            [news_results[0].categoryID]
        ).then(category_results => {
            // copy data to draft
            gDB.query(
                'INSERT INTO draft (draftID, userID, categoryID, category, publication, featuredImageURL, ' +
                'title, highlight, content, published, publishedContentID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    draft_id,
                    req.params.user_id,
                    news_results[0].categoryID,
                    category_results[0].categoryTitle,
                    'news',
                    news_results[0].featuredImageURL,
                    news_results[0].title,
                    news_results[0].highlight,
                    news_results[0].content,
                    1, // already published
                    req.params.news_id
                ]
            ).then(results => {
                res.status(201);
                res.json({
                    draft_id: draft_id,
                    draft: {
                        publication: 'news',
                        category: category_results[0].categoryTitle,
                        featured_image_url: news_results[0].featuredImageURL,
                        title: news_results[0].title,
                        highlight: news_results[0].highlight,
                        content: news_results[0].content
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

/*
 * Add article to draft for edit and return
 * unique id that identified the draft
 * 
 * For already published articles, you can't change it location
 */
router.post('/users/:user_id/articles/:article_id/edit', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is valid
    if (!(/^\d+$/.test(req.params.user_id) && /^\d+$/.test(req.params.article_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // generate sixten digit unique id
    const draft_id = rand_token.generate(16);

    gDB.query(
        'SELECT categoryID, featuredImageURL, title, ' +
        'highlight, content FROM articles WHERE articleID = ? AND userID = ? LIMIT 1',
        [req.params.article_id, req.params.user_id]
    ).then(article_results => {
        // check if article exist 
        if (article_results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News can't be found"
            });

            return;
        }

        // get publication category name
        gDB.query(
            'SELECT categoryTitle FROM article_categories WHERE categoryID = ? LIMIT 1',
            [article_results[0].categoryID]
        ).then(category_results => {
            // copy data to draft
            gDB.query(
                'INSERT INTO draft (draftID, userID, categoryID, category, publication, featuredImageURL, ' +
                'title, highlight, content, published, publishedContentID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    draft_id,
                    req.params.user_id,
                    article_results[0].categoryID,
                    category_results[0].categoryTitle,
                    'article',
                    article_results[0].featuredImageURL,
                    article_results[0].title,
                    article_results[0].highlight,
                    article_results[0].content,
                    1, // already published
                    req.params.news_id
                ]
            ).then(results => {
                // since article highlight is autogenerated don't return it to client for edit
                res.status(201);
                res.json({
                    draft_id: draft_id,
                    draft: {
                        publication: 'article',
                        category: category_results[0].categoryTitle,
                        featured_image_url: article_results[0].featuredImageURL,
                        title: article_results[0].title,
                        highlight: article_results[0].highlight,
                        content: article_results[0].content
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// update content save to draft
router.put('/users/:user_id/drafts/:draft_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    if (!(/^\d+$/.test(req.params.user_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.draft_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if draft exist
    gDB.query(
        'SELECT 1 FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
        [req.params.draft_id, req.params.user_id]
    ).then(results => {
        // check if draft exist 
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Draft does not exist"
            });

            return;
        }

        // check if some field contain valid data
        const invalid_inputs = [];

        // check if featured image URL is valid if is provided
        if (req.body.featuredImageURL && validator.isURL(req.body.featuredImageURL)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "featuredImageURL",
                message: "URL is invalid"
            });
        }

        // check body data type if is provided
        if (req.body.title && typeof req.body.title != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "title",
                message: "title is not acceptable"
            });

        } else if (req.body.title && req.body.title.length > 150) { // check if title exceed 150 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "title",
                message: "title exceed maximum allowed text"
            });
        }

        // check body data type if is provided
        if (req.body.highlight && typeof req.body.highlight != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "highlight",
                message: "highlight is not acceptable"
            });

        } else if (req.body.highlight && req.body.highlight.length > 500) { // check if highlight exceed 500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "highlight",
                message: "highlight exceed maximum allowed text"
            });
        }

        // check body data type if is provided
        if (req.body.content && typeof req.body.content != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "content",
                message: "content is not acceptable"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs,
                message: "Field(s) value not acceptable"
            });

            return;
        }

        // prepare query for update
        let query = 'UPDATE draft SET ';
        let post = [];
        let input_count = 0;

        // check if featuredImageURL is provided
        if (req.body.featuredImageURL) {
            query += 'featuredImageURL = ?';
            post.push(req.body.featuredImageURL);
            input_count++;
        }

        // check if title is provided
        if (req.body.title) {
            if (input_count < 1) {
                query += 'title = ?';
                query_post.push(req.body.title);

            } else {
                query += ', title = ?';
                query_post.push(req.body.title);
            }

            input_count++;
        }

        // check if highlight is provided
        if (req.body.highlight) {
            if (input_count < 1) {
                query += 'highlight = ?';
                query_post.push(req.body.highlight);

            } else {
                query += ', highlight = ?';
                query_post.push(req.body.highlight);
            }

            input_count++;
        }

        // check if content is provided
        if (req.body.content) {
            if (input_count < 1) {
                query += 'content = ?';
                query_post.push(req.body.content);

            } else {
                query += ', content = ?';
                query_post.push(req.body.content);
            }

            input_count++;
        }

        // last part of query
        query += ' WHERE draftID = ? LIMIT 1';
        post.push(req.params.draft_id);

        // save article to user's draft
        gDB.query(query, post).then(results => {
            return res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(reason => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', reason.message, {
            stack: reason.stack
        });

        return;
    });
});

// retrieve a publication saved to user's draft
router.get('/users/:user_id/drafts/:draft_id', custom_utils.allowedScopes(['read:users']), (req, res) => {
    if (!(/^\d+$/.test(req.params.user_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.draft_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    const mappped_field_name = new Map([
        ['publication', 'publication'],
        ['category', 'category'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['content', 'content'],
        ['time', 'time']
    ]);
    let query = 'SELECT ';

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    query += `${mappped_field_name.get(elem)}`;

                } else {
                    query += `, ${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            query = 'SELECT publication, category, featuredImageURL AS featured_image_url, title, highlight, content, time ' +
                'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';

        } else {
            query += ' FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';
        }

    } else { // no fields selection
        query += 'publication, category, featuredImageURL AS featured_image_url, title, highlight, content, time ' +
            'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';
    }

    // get publication saved to draft
    gDB.query(query, [req.params.draft_id, req.params.user_id]).then(results => {
        // check if there is result
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Draft can't be found"
            });

            return;
        }

        // send result to client
        res.status(200);
        res.json(results[0]);

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// retrieve all publication saved to user's draft
router.get('/users/:user_id/drafts', custom_utils.allowedScopes(['read:users']), (req, res) => {
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // set limit and offset
    let limit = 50;
    let offset = 0;
    let publication = req.query.publication;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const invalid_inputs = [];

    // check if query is valid
    // check if publication is defined and valid
    if (publication && !/^(news|article)$/.test(publication)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "publication",
            message: "publication value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    if (pass_limit && pass_limit < limit) {
        limit = pass_limit;
    }

    if (pass_offset) {
        offset = pass_offset;
    }

    const mappped_field_name = new Map([
        ['publication', 'publication'],
        ['category', 'category'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['time', 'time']
    ]);
    let select_query = 'SELECT draftID AS draft_id';
    let select_post = [];
    let count_query = 'SELECT COUNT(*) AS total FROM draft ';
    let count_post = [];

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `, ${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, ${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            select_query = 'SELECT draftID AS draft_id, publication, category, featuredImageURL AS featured_image_url, title, highlight, time FROM draft ';

        } else {
            select_query += ' FROM draft ';
        }

    } else { // no fields selection
        select_query += ', publication, category, featuredImageURL AS featured_image_url, title, highlight, time FROM draft ';
    }

    // user publication
    select_query += 'WHERE userID = ? ';
    select_post.push(req.params.user_id);

    // count query
    count_query += 'WHERE userID = ? ';
    count_post.push(req.params.user_id);

    // set the type of publication to retrieve
    if (publication) {
        // publication to select
        select_query += 'AND publication = ? ';
        select_post.push(publication);

        // coount query
        count_query += 'AND publication = ? ';
        count_post.push(publication);
    }

    // last drafting should come first
    select_query += 'ORDER BY time DESC ';

    // set limit and offset
    select_query += `LIMIT ${limit} OFFSET ${offset}`;

    // get metadata for user's publication
    gDB.query(count_query, count_post).then(count_results => {
        // get publication saved to draft
        gDB.query(select_query, select_post).then(results => {
            // send result to client
            res.status(200);
            res.json({
                drafts: results,
                metadata: {
                    result_set: {
                        count: results.length,
                        offset: offset,
                        limit: limit,
                        total: count_results[0].total
                    }
                }
            });

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// deleting a draft
router.delete('/users/:user_id/drafts/:draft_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    if (!(/^\d+$/.test(req.params.user_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.draft_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get all the uploaded media contents during drafting of publication
    gDB.query(
        'SELECT mediaRelativePath FROM draft_media_contents WHERE userID = ? AND draftID = ?',
        [req.params.user_id, req.params.draft_id]
    ).then(results => {
        let delete_objs = [];

        // add object(s) to delete
        for (let i = 0; i < results.length; i++) {
            delete_objs.push({ Key: results[i].mediaRelativePath });
        }

        // set aws s3 access credentials
        aws.config.update({
            apiVersion: '2006-03-01',
            accessKeyId: gConfig.AWS_ACCESS_ID,
            secretAccessKey: gConfig.AWS_SECRET_KEY,
            region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
        });

        const s3 = new aws.S3();

        // initialise objects to delete
        const deleteParam = {
            Bucket: gConfig.AWS_S3_BUCKET_NAME,
            Delete: {
                Objects: delete_objs
            }
        };

        s3.deleteObjects(deleteParam, (err, data) => {
            if (err) {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // delete a draft and all the related contents
            gDB.transaction(
                {
                    query: 'DELETE FROM draft WHERE draftID = ? AND userID = ?',
                    post: [
                        req.params.draft_id,
                        req.params.user_id
                    ]
                },
                {
                    query: 'DELETE FROM draft_media_contents WHERE draftID = ? AND userID = ?',
                    post: [
                        req.params.draft_id,
                        req.params.user_id
                    ]
                },
                {
                    query: 'DELETE FROM delete_media_contents WHERE draftID = ? AND userID = ?',
                    post: [
                        req.params.draft_id,
                        req.params.user_id
                    ]
                }
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// deleting all user's draft
router.delete('/users/:user_id/drafts', custom_utils.allowedScopes(['write:users']), (req, res) => {
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get all the uploaded media contents during drafting of publication
    gDB.query(
        'SELECT mediaRelativePath FROM draft_media_contents WHERE userID = ?',
        [req.params.user_id]
    ).then(results => {
        let delete_objs = [];

        // add object(s) to delete
        for (let i = 0; i < results.length; i++) {
            delete_objs.push({ Key: results[i].mediaRelativePath });
        }

        // set aws s3 access credentials
        aws.config.update({
            apiVersion: '2006-03-01',
            accessKeyId: gConfig.AWS_ACCESS_ID,
            secretAccessKey: gConfig.AWS_SECRET_KEY,
            region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
        });

        const s3 = new aws.S3();

        // initialise objects to delete
        const deleteParam = {
            Bucket: gConfig.AWS_S3_BUCKET_NAME,
            Delete: {
                Objects: delete_objs
            }
        };

        s3.deleteObjects(deleteParam, (err, data) => {
            if (err) {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // delete all draft and all the related contents
            gDB.transaction(
                {
                    query: 'DELETE FROM draft WHERE userID = ?',
                    post: [
                        req.params.user_id
                    ]
                },
                {
                    query: 'DELETE FROM draft_media_contents WHERE userID = ?',
                    post: [
                        req.params.user_id
                    ]
                },
                {
                    query: 'DELETE FROM delete_media_contents WHERE userID = ?',
                    post: [
                        req.params.user_id
                    ]
                }
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// upload media contents for publication
router.post('/drafts/:draft_id/medias', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if draft id is valid
    if (!/^[a-zA-Z0-9]{16}$/.test(req.params.draft_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // check if draft exist
    gDB.query(
        'SELECT publication FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
        [req.params.draft_id, req.user.access_token.user_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Draft can't be found"
            });

            return;
        }

        upload(req, res, (err) => {
            // check if enctype is multipart form data
            if (!req.is('multipart/form-data')) {
                res.status(415);
                res.json({
                    error_code: "invalid_request_body",
                    message: "Encode type not supported"
                });

                return;
            }

            // check if file contain data
            if (!req.file) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "Bad request"
                });

                return;
            }

            // A Multer error occurred when uploading
            if (err instanceof multer.MulterError) {
                if (err.code == 'LIMIT_FILE_SIZE') {
                    res.status(400);
                    res.json({
                        error_code: "size_exceeded",
                        message: "Image your uploading exceeded allowed size"
                    });

                    return;
                }

                // other multer errors
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;

            } else if (err) { // An unknown error occurred when uploading
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            let file_path = req.file.path; // uploaded file location
            let file_name = req.file.originalname;
            const save_image_ext = 'png';

            // read uploaded image as buffer
            let image_buffer = fs.readFileSync(file_path);

            // check file type and if is supported
            let supported_images = [
                'jpg',
                'png',
                'gif',
                'jp2'
            ];

            // read minimum byte from buffer required to determine file mime
            let file_mime = file_type(Buffer.from(image_buffer, 0, file_type.minimumBytes));

            if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                // delete the uploaded file
                fs.unlinkSync(file_path);

                res.status(406);
                res.json({
                    error_code: "unsupported_format",
                    message: "Uploaded image is not supported"
                });

                return;
            }

            // resize the image if it exceeded the maximum resolution
            sharp(image_buffer)
                .resize({
                    height: 1080, // resize image using the set height
                    withoutEnlargement: true
                })
                .toFormat(save_image_ext)
                .toBuffer()
                .then(outputBuffer => {
                    // no higher than 1080 pixels
                    // and no larger than the input image

                    // upload buffer to aws s3 bucket
                    // set aws s3 access credentials
                    aws.config.update({
                        apiVersion: '2006-03-01',
                        accessKeyId: gConfig.AWS_ACCESS_ID,
                        secretAccessKey: gConfig.AWS_SECRET_KEY,
                        region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                    });

                    const s3 = new aws.S3();
                    const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;
                    let dir_name;

                    // check if is news or article
                    if (results[0].publication == 'news') { // news
                        dir_name = 'news';

                    } else { // article
                        dir_name = 'article';
                    }

                    const upload_params = {
                        Bucket: gConfig.AWS_S3_BUCKET_NAME,
                        Body: outputBuffer,
                        Key: dir_name + '/images/big/' + object_unique_name,
                        ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                    };

                    s3.upload(upload_params, (err, data) => {
                        // delete the uploaded file
                        fs.unlinkSync(file_path);

                        if (err) {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;
                        }

                        if (data) { // file uploaded successfully
                            // generate 32 digit unique id
                            const image_id = rand_token.generate(32);
                            let img_path = dir_name + '/images/big/' + object_unique_name;

                            // save file metadata and location to database
                            gDB.query(
                                'INSERT INTO draft_media_contents (draftID, userID, mediaID, mediaRelativePath, ' +
                                'mediaOriginalName, mediaType, mediaExt) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                [
                                    req.params.draft_id,
                                    req.user.access_token.user_id,
                                    image_id,
                                    img_path,
                                    file_name,
                                    file_mime.mime.split('/')[0],
                                    save_image_ext,
                                ]
                            ).then(results => {
                                // send result to client
                                res.status(200);
                                res.json({
                                    image_id: image_id,
                                    image: {
                                        big: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/big/${object_unique_name}`,
                                        medium: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/medium/${object_unique_name}`,
                                        small: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/small/${object_unique_name}`,
                                        tiny: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/tiny/${object_unique_name}`
                                    }
                                });

                            }).catch(err => {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            });
                        }
                    });
                })
                .catch(err => {
                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete uploaded media content for publication
router.delete('/drafts/:draft_id/medias/:media_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if all the pass id in the URL is valid
    if (!(/^[a-zA-Z0-9]{16}$/.test(req.params.draft_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.media_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // check if draft exist
    gDB.query(
        'SELECT publication FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
        [req.params.draft_id, req.user.access_token.user_id]
    ).then(draft_results => {
        if (draft_results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Draft can't be found"
            });

            return;
        }

        // schedule media content that will be deleted during publication
        const deleteMediaContent = (rel_path, call_back) => {
            gDB.query(
                'INSERT INTO delete_media_contents (draftID, userID, publication, mediaID, mediaRelativePath) VALUES (?, ?, ?, ?, ?)',
                [
                    req.params.draft_id,
                    req.user.access_token.user_id,
                    draft_results[0].publication,
                    req.params.media_id,
                    rel_path
                ]
            ).then(results => {
                call_back();

            }).catch(err => {
                // check if is a duplicate error
                if (err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                    return res.status(200).send();
                }

                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        };

        // get media content to be delete in database
        gDB.query(
            'SELECT mediaRelativePath FROM draft_media_contents WHERE mediaID = ? LIMIT 1',
            [req.params.media_id]
        ).then(results => {
            if (results.length < 1) {
                // media can't be found in this table, check another table
                let table_name;

                // check if is news or article
                if (draft_results[0].publication == 'news') { // news
                    table_name = 'news_media_contents';

                } else { // article
                    table_name = 'article_media_contents';
                }

                gDB.query(
                    'SELECT mediaRelativePath FROM ?? WHERE mediaID = ? LIMIT 1',
                    [table_name, req.params.media_id]
                ).then(results => {
                    // check if media exist
                    if (results.length < 1) {
                        res.status(404);
                        res.json({
                            error_code: "file_not_found",
                            message: "Media can't be found"
                        });

                        return;
                    }

                    // delete media in AWS S3 bucket
                    deleteMediaContent(results[0].mediaRelativePath, () => {
                        return res.status(200).send();
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            } else {
                // delete media in AWS S3 bucket
                deleteMediaContent(results[0].mediaRelativePath, () => {
                    // delete media content in "draft_media_contents"
                    gDB.query(
                        'DELETE FROM draft_media_contents WHERE mediaID = ? LIMIT 1',
                        [req.params.media_id]
                    ).then(results => {
                        return res.status(200).send();

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// publish publication save to draft and return the id
router.put('/users/:user_id/drafts/:draft_id/publish', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is integer
    if (!(/^\d+$/.test(req.params.user_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.draft_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // check if field(s) contain valid data
    const invalid_inputs = [];

    // check if query is valid
    if (req.query.restrict && !/^(true|false)$/.test(req.query.restrict)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "restrict",
            message: "restrict value is invalid"
        });
    }

    if (!req.query.locationID) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "locationID",
            message: "locationID has to be defined"
        });

    } else if (!/^\d+$/.test(req.query.locationID)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });

    } else {
        // check if location id exist and retrieve countryID and continentID
        gDB.query(
            'SELECT countryID, continentID FROM map_regions WHERE regionID = ? LIMIT 1', [req.query.locationID]
        ).then(region_results => {
            if (region_results.length < 1) {
                // location id does not exist
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "locationID",
                    message: "locationID doesn't exist"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs,
                    message: "Query(s) value is invalid"
                });

                return;
            }

            // fetch article stored in draft
            gDB.query(
                'SELECT categoryID, publication, featuredImageURL, title, highlight, content, published, ' +
                'publishedContentID FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
                [req.params.draft_id, req.params.user_id]
            ).then(draft_results => {
                // check if draft exist 
                if (draft_results.length < 1) {
                    res.status(404);
                    res.json({
                        error_code: "file_not_found",
                        message: "Draft can't be found"
                    });

                    return;
                }

                // check if title is provided
                if (draft_results[0].title.trim().length < 1) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "field_is_empty",
                        message: "Title for publication not provided"
                    });

                    return;
                }

                // check if highlight is provided
                if (draft_results[0].highlight.trim().length < 1) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "field_is_empty",
                        message: "Highlight for publication not provided"
                    });

                    return;
                }

                // check if content is provided
                if (draft_results[0].content.trim().length < 1) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "field_is_empty",
                        message: "Body for publication not provided"
                    });

                    return;
                }

                let table_name;
                let table_id_name;
                let mc_table_name;

                // check if is news or article
                if (draft_results[0].publication == 'news') { // news
                    table_name = 'news';
                    table_id_name = 'newsID';
                    mc_table_name = 'news_media_contents';

                } else { // article
                    table_name = 'articles';
                    table_id_name = 'articleID';
                    mc_table_name = 'article_media_contents';
                }

                let sql_transaction = []; // sql transaction
                let del_objects = [];

                // get media contents to be deleted
                gDB.query(
                    'SELECT mediaRelativePath FROM delete_media_contents WHERE draftID = ? AND userID = ?',
                    [req.params.draft_id, req.params.user_id]
                ).then(dmc_results => {
                    if (dmc_results.length > 0) {
                        // add media content to be deleted
                        sql_transaction.push({
                            query: 'DELETE FROM delete_media_contents WHERE draftID = ?',
                            post: [req.params.draft_id]
                        });

                        // object(s) in AWS S3 to be deleted
                        for (let i = 0; i < dmc_results.length; i++) {
                            del_objects.push({ Key: dmc_results[i].mediaRelativePath });
                        }
                    }

                    // get all the uploaded media contents during write-up or editing
                    gDB.query(
                        'SELECT * FROM draft_media_contents WHERE draftID = ?',
                        [req.params.draft_id]
                    ).then(draft_mc_results => {
                        if (draft_mc_results.length > 0) {
                            // add media content to be deleted
                            sql_transaction.push({
                                query: 'DELETE FROM draft_media_contents WHERE draftID = ?',
                                post: [req.params.draft_id]
                            });
                        }

                        // publish write-up or edit
                        const publishContentInDraft = () => {
                            let sql_query;
                            let sql_post;

                            // check if this article is published first time
                            if (draft_results[0].published == 0) { // has not been published
                                sql_query =
                                    'INSERT INTO ?? (userID, categoryID, continentID, countryID, regionID, restrictedToLocation, ' +
                                    'featuredImageURL, title, highlight, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

                                sql_post = [
                                    table_name,
                                    req.params.user_id,
                                    draft_results[0].categoryID,
                                    region_results[0].continentID,
                                    region_results[0].countryID,
                                    req.query.locationID,
                                    req.query.restrict ? { 'true': 1, 'false': 0 }[req.query.restrict] : 0,
                                    draft_results[0].featuredImageURL,
                                    draft_results[0].title,
                                    draft_results[0].highlight,
                                    draft_results[0].content
                                ];

                            } else { // has been published
                                sql_query =
                                    'UPDATE ?? SET featuredImageURL = ?, ' +
                                    'title = ?, highlight = ?, content = ? WHERE ?? = ?';

                                sql_post = [
                                    table_name,
                                    draft_results[0].featuredImageURL,
                                    draft_results[0].title,
                                    draft_results[0].highlight,
                                    draft_results[0].content,
                                    table_id_name,
                                    draft_results[0].publishedContentID
                                ];
                            }

                            // publish content
                            gDB.query(sql_query, sql_post).then(pc_results => {
                                let publication_id;

                                if (draft_results[0].published == 0) {
                                    publication_id = pc_results.insertId;

                                } else {
                                    publication_id = draft_results[0].publishedContentID;
                                }

                                // add media content to be inserted into database
                                let insert_values = [];

                                for (let i = 0; i < draft_mc_results.length; i++) {
                                    insert_values.push([
                                        publication_id,
                                        draft_mc_results[i].userID,
                                        draft_mc_results[i].mediaID,
                                        draft_mc_results[i].mediaRelativePath,
                                        draft_mc_results[i].mediaOriginalName,
                                        draft_mc_results[i].mediaType,
                                        draft_mc_results[i].mediaExt]);
                                }

                                sql_transaction.push({
                                    query: 'INSERT INTO ?? (??, userID, mediaID, mediaRelativePath, ' +
                                        'mediaOriginalName, mediaType, mediaExt) VALUES ?',
                                    post: [mc_table_name, table_id_name, insert_values]
                                });

                                // execute the transaction
                                gDB.transaction(...sql_transaction).then(results => {
                                    res.status(201);
                                    res.json({
                                        publication_id: publication_id
                                    });

                                    return;

                                }).catch(err => {
                                    // delete newly inserted row for news or article
                                    if (draft_results[0].published == 0) {
                                        gDB.query(
                                            'DELETE FROM ?? WHERE ?? = ? LIMIT 1',
                                            [table_name, table_id_name, publication_id]
                                        ).then(results => {
                                            res.status(503).send();

                                            // log the error to log file
                                            gLogger.log('error', err.message, {
                                                stack: err.stack
                                            });

                                            return;

                                        }).catch(err => {
                                            res.status(503).send();

                                            // log the error to log file
                                            gLogger.log('error', err.message, {
                                                stack: err.stack
                                            });

                                            return;
                                        });

                                    } else {
                                        res.status(503).send();

                                        // log the error to log file
                                        gLogger.log('error', err.message, {
                                            stack: err.stack
                                        });

                                        return;
                                    }
                                });

                            }).catch(err => {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            });
                        };

                        // check if their is object(s) to delete
                        if (del_objects.length > 0) {
                            // set aws s3 access credentials
                            aws.config.update({
                                apiVersion: '2006-03-01',
                                accessKeyId: gConfig.AWS_ACCESS_ID,
                                secretAccessKey: gConfig.AWS_SECRET_KEY,
                                region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                            });

                            const s3 = new aws.S3();

                            // initialise objects to delete
                            const deleteParam = {
                                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                                Delete: { Objects: del_objects }
                            };

                            s3.deleteObjects(deleteParam, (err, data) => {
                                if (err) {
                                    res.status(500);
                                    res.json({
                                        error_code: "internal_error",
                                        message: "Internal error"
                                    });

                                    // log the error to log file
                                    gLogger.log('error', err.message, {
                                        stack: err.stack
                                    });

                                    return;

                                }

                                publishContentInDraft();
                            });

                        } else {
                            publishContentInDraft();
                        }

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }
});

// get all the user's published news
router.get('/users/:user_id/news', custom_utils.allowedScopes(['read:users']), (req, res) => {
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // set limit and offset
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const category_id = req.query.categoryID;
    const invalid_inputs = [];

    // check if query is defined and valid
    if (category_id && !/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    if (pass_limit && pass_limit < limit) {
        limit = pass_limit;
    }

    if (pass_offset) {
        offset = pass_offset;
    }

    const mappped_field_name = new Map([
        ['category', 'categoryID AS category_id'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['time', 'time']
    ]);
    let select_query = 'SELECT A.newsID AS id, ';
    let select_post = [];
    let count_query = 'SELECT COUNT(*) AS total FROM news ';
    let count_post = [];

    // check if is valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `A.${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, A.${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            select_query =
                'SELECT A.newsID AS id, A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, ' +
                'A.title, A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                'B.profilePictureMediumURL, B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID ';

        } else {
            select_query +=
                ', B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                'FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID ';
        }

    } else { // no fields selection
        select_query +=
            'A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, ' +
            'A.title, A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
            'B.profilePictureMediumURL, B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID ';
    }

    // user publication
    select_query += 'WHERE A.userID = ? ';
    select_post.push(req.params.user_id);

    // count query
    count_query += 'WHERE userID = ? ';
    count_post.push(req.params.user_id);

    // set the category
    if (category_id) {
        // category to select
        select_query += 'AND A.categoryID = ? ';
        select_post.push(category_id);

        // coount query
        count_query += 'AND categoryID = ? ';
        count_post.push(category_id);
    }

    // last published news should come first
    select_query += 'ORDER BY A.time DESC ';

    // set limit and offset
    select_query += `LIMIT ${limit} OFFSET ${offset}`;

    // get metadata for user's publication
    gDB.query(count_query, count_post).then(count_results => {
        // get publication
        gDB.query(select_query, select_post).then(results => {
            for (let i = 0; i < results.length; i++) {
                // check if user has a profile picture
                if (results[i].profilePictureSmallURL) {
                    // add user to results
                    results[i].user = {
                        id: results[i].userID,
                        name: results[i].lastName + ' ' + results[i].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    results[i].user = {
                        id: results[i].userID,
                        name: results[i].lastName + ' ' + results[i].firstName,
                        image: null
                    };
                }

                // remove keys
                delete results[i].userID;
                delete results[i].firstName;
                delete results[i].lastName;
                delete results[i].profilePictureSmallURL;
                delete results[i].profilePictureMediumURL;
                delete results[i].profilePictureBigURL;
            }

            // send result to client
            res.status(200);
            res.json({
                news: results,
                metadata: {
                    result_set: {
                        count: results.length,
                        offset: offset,
                        limit: limit,
                        total: count_results[0].total
                    }
                }
            });

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the user's published article
router.get('/users/:user_id/articles', custom_utils.allowedScopes(['read:users']), (req, res) => {
    if (!/^\d+$/.test(req.params.user_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // set limit and offset
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const category_id = req.query.categoryID;
    const invalid_inputs = [];

    // check if query is defined and valid
    if (category_id && !/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    if (pass_limit && pass_limit < limit) {
        limit = pass_limit;
    }

    if (pass_offset) {
        offset = pass_offset;
    }

    const mappped_field_name = new Map([
        ['category', 'categoryID AS category_id'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['time', 'time']
    ]);
    let select_query = 'SELECT A.articleID AS id, ';
    let select_post = [];
    let count_query = 'SELECT COUNT(*) AS total FROM articles ';
    let count_post = [];

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `A.${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, A.${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            select_query =
                'SELECT A.articleID AS id, A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, ' +
                'A.title, A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                'B.profilePictureMediumURL, B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID ';

        } else {
            select_query +=
                ', B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                'FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID ';
        }

    } else { // no fields selection
        select_query +=
            'A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, ' +
            'A.title, A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
            'B.profilePictureMediumURL, B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID ';
    }

    // user publication
    select_query += 'WHERE A.userID = ? ';
    select_post.push(req.params.user_id);

    // count query
    count_query += 'WHERE userID = ? ';
    count_post.push(req.params.user_id);

    // set the category
    if (category_id) {
        // category to select
        select_query += 'AND A.categoryID = ? ';
        select_post.push(category_id);

        // coount query
        count_query += 'AND categoryID = ? ';
        count_post.push(category_id);
    }

    // last published news should come first
    select_query += 'ORDER BY A.time DESC ';

    // set limit and offset
    select_query += `LIMIT ${limit} OFFSET ${offset}`;

    // get metadata for user's publication
    gDB.query(count_query, count_post).then(count_results => {
        // get publication
        gDB.query(select_query, select_post).then(results => {
            for (let i = 0; i < results.length; i++) {
                // check if user has a profile picture
                if (results[i].profilePictureSmallURL) {
                    // add user to results
                    results[i].user = {
                        id: results[i].userID,
                        name: results[i].lastName + ' ' + results[i].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    results[i].user = {
                        id: results[i].userID,
                        name: results[i].lastName + ' ' + results[i].firstName,
                        image: null
                    };
                }

                // remove keys
                delete results[i].userID;
                delete results[i].firstName;
                delete results[i].lastName;
                delete results[i].profilePictureSmallURL;
                delete results[i].profilePictureMediumURL;
                delete results[i].profilePictureBigURL;
            }

            // send result to client
            res.status(200);
            res.json({
                articles: results,
                metadata: {
                    result_set: {
                        count: results.length,
                        offset: offset,
                        limit: limit,
                        total: count_results[0].total
                    }
                }
            });

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete published news
router.delete('/users/:user_id/news/:news_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    if (!(/^\d+$/.test(req.params.user_id) && /^\d+$/.test(req.params.news_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // check if news exist. Just return 200 OK if doesn't exist
    gDB.query(
        'SELECT 1 FROM news WHERE newsID = ? AND userID = ? LIMIT 1',
        [req.params.news_id, req.params.user_id]
    ).then(results => {
        if (results.length < 1) {
            return res.status(200).send();
        }

        // get all the uploaded media content
        gDB.query(
            'SELECT mediaRelativePath FROM news_media_contents WHERE newsID = ? AND userID = ?',
            [req.params.news_id, req.params.user_id]
        ).then(results => {
            let delete_objs = [];

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].mediaRelativePath });
            }

            // check if there is object to delete
            if (delete_objs.length > 0) {
                // set aws s3 access credentials
                aws.config.update({
                    apiVersion: '2006-03-01',
                    accessKeyId: gConfig.AWS_ACCESS_ID,
                    secretAccessKey: gConfig.AWS_SECRET_KEY,
                    region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                });

                const s3 = new aws.S3();

                // initialise objects to delete
                const deleteParam = {
                    Bucket: gConfig.AWS_S3_BUCKET_NAME,
                    Delete: {
                        Objects: delete_objs
                    }
                };

                s3.deleteObjects(deleteParam, (err, data) => {
                    if (err) {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    }

                    // delete news and all the related contents
                    gDB.transaction(
                        {
                            query: 'DELETE FROM news WHERE newsID = ? AND userID = ?',
                            post: [
                                req.params.news_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM news_media_contents WHERE newsID = ? AND userID = ?',
                            post: [
                                req.params.news_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM news_likes WHERE newsID = ? AND userID = ?',
                            post: [
                                req.params.news_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM news_dislikes WHERE newsID = ? AND userID = ?',
                            post: [
                                req.params.news_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM news_comments WHERE newsID = ?',
                            post: [req.params.news_id]
                        }
                    ).then(results => {
                        return res.status(200).send();

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                });

            } else {
                // delete news and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM news WHERE newsID = ? AND userID = ?',
                        post: [
                            req.params.news_id,
                            req.params.user_id
                        ]
                    },
                    {
                        query: 'DELETE FROM news_likes WHERE newsID = ? AND userID = ?',
                        post: [
                            req.params.news_id,
                            req.params.user_id
                        ]
                    },
                    {
                        query: 'DELETE FROM news_dislikes WHERE newsID = ? AND userID = ?',
                        post: [
                            req.params.news_id,
                            req.params.user_id
                        ]
                    },
                    {
                        query: 'DELETE FROM news_comments WHERE newsID = ?',
                        post: [req.params.news_id]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete published article
router.delete('/users/:user_id/articles/:article_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    if (!(/^\d+$/.test(req.params.user_id) && /^\d+$/.test(req.params.article_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if is accessing the right user or as a logged in user
    if (!req.params.user_id == req.user.access_token.user_id) {
        res.status(401);
        res.json({
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // check if article exist. Just return 200 OK if doesn't exist
    gDB.query(
        'SELECT 1 FROM articles WHERE articleID = ? AND userID = ? LIMIT 1',
        [req.params.article_id, req.params.user_id]
    ).then(results => {
        if (results.length < 1) {
            return res.status(200).send();
        }

        // get all the uploaded media content
        gDB.query(
            'SELECT mediaRelativePath FROM article_media_contents WHERE articleID = ? AND userID = ?',
            [req.params.article_id, req.params.user_id]
        ).then(results => {
            let delete_objs = [];

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].mediaRelativePath });
            }

            // check if there is object to delete
            if (delete_objs.length > 0) {
                // set aws s3 access credentials
                aws.config.update({
                    apiVersion: '2006-03-01',
                    accessKeyId: gConfig.AWS_ACCESS_ID,
                    secretAccessKey: gConfig.AWS_SECRET_KEY,
                    region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                });

                const s3 = new aws.S3();

                // initialise objects to delete
                const deleteParam = {
                    Bucket: gConfig.AWS_S3_BUCKET_NAME,
                    Delete: {
                        Objects: delete_objs
                    }
                };

                s3.deleteObjects(deleteParam, (err, data) => {
                    if (err) {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    }

                    // delete news and all the related contents
                    gDB.transaction(
                        {
                            query: 'DELETE FROM articles WHERE articleID = ? AND userID = ?',
                            post: [
                                req.params.article_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM article_media_contents WHERE articleID = ? AND userID = ?',
                            post: [
                                req.params.article_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM article_likes WHERE articleID = ? AND userID = ?',
                            post: [
                                req.params.article_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM article_dislikes WHERE articleID = ? AND userID = ?',
                            post: [
                                req.params.article_id,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM article_comments WHERE articleID = ?',
                            post: [req.params.article_id]
                        }
                    ).then(results => {
                        return res.status(200).send();

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                });

            } else {
                // delete news and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM articles WHERE articleID = ? AND userID = ?',
                        post: [
                            req.params.article_id,
                            req.params.user_id
                        ]
                    },
                    {
                        query: 'DELETE FROM article_likes WHERE articleID = ? AND userID = ?',
                        post: [
                            req.params.article_id,
                            req.params.user_id
                        ]
                    },
                    {
                        query: 'DELETE FROM article_dislikes WHERE articleID = ? AND userID = ?',
                        post: [
                            req.params.article_id,
                            req.params.user_id
                        ]
                    },
                    {
                        query: 'DELETE FROM article_comments WHERE articleID = ?',
                        post: [req.params.article_id]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// retrieve a news
router.get('/news/:id', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;

    }

    const mappped_field_name = new Map([
        ['category', 'categoryID AS category_id'],
        ['continent', 'continentID AS continent_id'],
        ['country', 'countryID AS country_id'],
        ['region', 'regionID AS region_id'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['content', 'content'],
        ['time', 'time']
    ]);
    let query = 'SELECT ';

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    query += `A.${mappped_field_name.get(elem)}`;

                } else {
                    query += `, A.${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            query =
                'SELECT A.categoryID AS category_id, A.continentID AS continent_id, A.countryID AS country_id, ' +
                'A.regionID AS region_id, A.featuredImageURL AS featured_image_url, ' +
                'A.title, A.highlight, A.content, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                'B.profilePictureMediumURL, B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.newsID = ?';

        } else {
            query +=
                ', B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                'FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.newsID = ?';
        }

    } else { // no fields selection
        query +=
            'A.categoryID AS category_id, A.continentID AS continent_id, A.countryID AS country_id, ' +
            'A.regionID AS region_id, A.featuredImageURL AS featured_image_url, ' +
            'A.title, A.highlight, A.content, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
            'B.profilePictureMediumURL, B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.newsID = ?';
    }

    // get publication
    gDB.query(query, [req.params.id]).then(results => {
        // check if there is result
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News can't be found"
            });

            return;
        }

        // check if user has a profile picture
        if (results[0].profilePictureSmallURL) {
            // add user to results
            results[0].user = {
                id: results[0].userID,
                name: results[0].lastName + ' ' + results[0].firstName,
                image: {
                    big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureBigURL,
                    medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureMediumURL,
                    small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureSmallURL
                }
            };

        } else {
            // add user to results
            results[0].user = {
                id: results[0].userID,
                name: results[0].lastName + ' ' + results[0].firstName,
                image: null
            };
        }

        // remove keys
        delete results[0].userID;
        delete results[0].firstName;
        delete results[0].lastName;
        delete results[0].profilePictureSmallURL;
        delete results[0].profilePictureMediumURL;
        delete results[0].profilePictureBigURL;

        // send result to client
        res.status(200);
        res.json(results[0]);

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// retrieve an article
router.get('/articles/:id', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    const mappped_field_name = new Map([
        ['category', 'categoryID AS category_id'],
        ['continent', 'continentID AS continent_id'],
        ['country', 'countryID AS country_id'],
        ['region', 'regionID AS region_id'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['content', 'content'],
        ['time', 'time']
    ]);
    let query = 'SELECT ';

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    query += `A.${mappped_field_name.get(elem)}`;

                } else {
                    query += `, A.${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            query =
                'SELECT A.categoryID AS category_id, A.continentID AS continent_id, A.countryID AS country_id, ' +
                'A.regionID AS region_id, A.featuredImageURL AS featured_image_url, ' +
                'A.title, A.highlight, A.content, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                'B.profilePictureMediumURL, B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ?';

        } else {
            query +=
                ', B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                'FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ?';
        }

    } else { // no fields selection
        query +=
            'A.categoryID AS category_id, A.continentID AS continent_id, A.countryID AS country_id, ' +
            'A.regionID AS region_id, A.featuredImageURL AS featured_image_url, ' +
            'A.title, A.highlight, A.content, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
            'B.profilePictureMediumURL, B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ?';
    }

    // get publication
    gDB.query(query, [req.params.id]).then(results => {
        // check if there is result
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article can't be found"
            });

            return;
        }

        // check if user has a profile picture
        if (results[0].profilePictureSmallURL) {
            // add user to results
            results[0].user = {
                id: results[0].userID,
                name: results[0].lastName + ' ' + results[0].firstName,
                image: {
                    big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureBigURL,
                    medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureMediumURL,
                    small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureSmallURL
                }
            };

        } else {
            // add user to results
            results[0].user = {
                id: results[0].userID,
                name: results[0].lastName + ' ' + results[0].firstName,
                image: null
            };
        }

        // remove keys
        delete results[0].userID;
        delete results[0].firstName;
        delete results[0].lastName;
        delete results[0].profilePictureSmallURL;
        delete results[0].profilePictureMediumURL;
        delete results[0].profilePictureBigURL;

        // send result to client
        res.status(200);
        res.json(results[0]);

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// search news
router.get('/news', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // set limit and offset
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const location_id = req.query.locationID;
    const category_id = req.query.categoryID;
    const pref_location_id = req.query.prefLocationID;
    let search = req.query.search;
    const invalid_inputs = [];

    // check if query location ID is provided
    if (!location_id) {
        invalid_inputs.push({
            error_code: "undefined_value",
            field: "locationID",
            message: "locationID is not provided"
        });

    } else if (!/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if query is defined and valid
    if (pref_location_id && !/^\d+$/.test(pref_location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "prefLocationID",
            message: "prefLocationID value is invalid"
        });
    }

    // check if query is defined and valid
    if (category_id && !/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    //check if region with location id exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id]).then(results => {
        if (results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if set preferred location id exist if provided
        gDB.query(
            'SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1',
            [pref_location_id ? pref_location_id : 0]
        ).then(results => {
            // check if prefLocationID is provided
            if (pref_location_id && results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "prefLocationID",
                    message: "prefLocationID value is invalid"
                });
            }

            //check if category exist
            gDB.query(
                'SELECT 1 FROM news_categories WHERE categoryID = ? LIMIT 1',
                [category_id ? category_id : 0]
            ).then(results => {
                if (category_id && results.length < 1) {
                    invalid_inputs.push({
                        error_code: "invalid_value",
                        field: "categoryID",
                        message: "categoryID value is invalid"
                    });
                }

                // check if any input is invalid
                if (invalid_inputs.length > 0) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "invalid_query",
                        errors: invalid_inputs,
                        message: "Query(s) value is invalid"
                    });

                    return;
                }

                if (pass_limit && pass_limit < limit) {
                    limit = pass_limit;
                }

                if (pass_offset) {
                    offset = pass_offset;
                }

                const mappped_field_name = new Map([
                    ['category', 'categoryID AS category_id'],
                    ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
                    ['title', 'title'],
                    ['highlight', 'highlight'],
                    ['time', 'time']
                ]);
                let select_query = 'SELECT A.newsID AS id, ';
                let select_post = [];
                let count_query = 'SELECT COUNT(*) AS total FROM news ';
                let count_post = [];

                // check if valid and required fields is given
                if (req.query.fields) {
                    // split the provided fields
                    let req_fields = req.query.fields.split(',');
                    let permitted_field_count = 0;
                    let field_already_exist = [];

                    req_fields.forEach(elem => {
                        if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                            if (permitted_field_count == 0) {
                                select_query += `A.${mappped_field_name.get(elem)}`;

                            } else {
                                select_query += `, A.${mappped_field_name.get(elem)}`;
                            }

                            field_already_exist.push(elem);
                            permitted_field_count++; // increment by one
                        }
                    });

                    if (permitted_field_count < 1) {
                        select_query =
                            'SELECT A.newsID AS id, A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, A.title, ' +
                            'A.highlight, A.time, B.firstName, B.userID, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                            'B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID ';

                    } else {
                        select_query +=
                            ', B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                            'B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID ';
                    }

                } else { // no fields selection
                    select_query +=
                        ' A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, A.title, ' +
                        'A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                        'B.profilePictureBigURL FROM news AS A LEFT JOIN user AS B ON A.userID = B.userID ';
                }

                // from all published location
                if (!pref_location_id) {
                    select_query += 'WHERE (A.regionID = ? OR A.restrictedToLocation = ?) ';
                    select_post.push(location_id);
                    select_post.push(0);

                    // count query
                    count_query += 'WHERE (regionID = ? OR restrictedToLocation = ?) ';
                    count_post.push(location_id);
                    count_post.push(0);

                } else { // from set preferred location
                    select_query += 'WHERE A.regionID = ? ';
                    select_post.push(pref_location_id);

                    // count query
                    count_query += 'WHERE regionID = ? ';
                    count_post.push(pref_location_id);
                }

                // check if preferred location is provided and not equal to each other
                if (pref_location_id && location_id != pref_location_id) {
                    select_query += 'AND A.restrictedToLocation = ? ';
                    select_post.push(0);

                    // count query
                    count_query += 'AND restrictedToLocation = ? ';
                    count_post.push(0);
                }

                // category to retrieve or search
                if (category_id) {
                    // category to select
                    select_query += 'AND A.categoryID = ? ';
                    select_post.push(category_id);

                    // count query
                    count_query += 'AND categoryID = ? ';
                    count_post.push(category_id);
                }

                // check if user pass in search query
                if (search) {
                    let temp_search = ' ' + decodeURIComponent(search.toString()).trim() + ' ';
                    temp_search = temp_search.replace(/\s+/g, ' % ').trim();

                    select_query += `AND A.title LIKE '${temp_search}' `;
                    count_query += `AND title LIKE '${temp_search}' `;
                }

                // last published news should come first
                select_query += 'ORDER BY A.time DESC ';

                // set limit and offset
                select_query += `LIMIT ${limit} OFFSET ${offset}`;

                // get metadata for user's publication
                gDB.query(count_query, count_post).then(count_results => {
                    // get publication
                    gDB.query(select_query, select_post).then(results => {
                        for (let i = 0; i < results.length; i++) {
                            // check if user has a profile picture
                            if (results[i].profilePictureSmallURL) {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: {
                                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                    }
                                };

                            } else {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: null
                                };
                            }

                            // remove keys
                            delete results[i].userID;
                            delete results[i].firstName;
                            delete results[i].lastName;
                            delete results[i].profilePictureSmallURL;
                            delete results[i].profilePictureMediumURL;
                            delete results[i].profilePictureBigURL;
                        }

                        // send result to client
                        res.status(200);
                        res.json({
                            news: results,
                            metadata: {
                                result_set: {
                                    count: results.length,
                                    offset: offset,
                                    limit: limit,
                                    total: count_results[0].total
                                }
                            }
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// search article
router.get('/articles', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // set limit and offset
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const location_id = req.query.locationID;
    const category_id = req.query.categoryID;
    const pref_location_id = req.query.prefLocationID;
    let search = req.query.search;
    const invalid_inputs = [];

    // check if query location ID is provided
    if (!location_id) {
        invalid_inputs.push({
            error_code: "undefined_value",
            field: "locationID",
            message: "locationID is not provided"
        });

    } else if (!/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if query is defined and valid
    if (pref_location_id && !/^\d+$/.test(pref_location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "prefLocationID",
            message: "prefLocationID value is invalid"
        });
    }

    // check if query is defined and valid
    if (category_id && !/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs,
            message: "Query(s) value is invalid"
        });

        return;
    }

    //check if region with location id exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id]).then(results => {
        if (results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if set preferred location id exist if provided
        gDB.query(
            'SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1',
            [pref_location_id ? pref_location_id : 0]
        ).then(results => {
            // check if prefLocationID is provided
            if (pref_location_id && results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "prefLocationID",
                    message: "prefLocationID value is invalid"
                });
            }

            //check if category exist
            gDB.query(
                'SELECT 1 FROM article_categories WHERE categoryID = ? LIMIT 1',
                [category_id ? category_id : 0]
            ).then(results => {
                if (category_id && results.length < 1) {
                    invalid_inputs.push({
                        error_code: "invalid_value",
                        field: "categoryID",
                        message: "categoryID value is invalid"
                    });
                }

                // check if any input is invalid
                if (invalid_inputs.length > 0) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "invalid_query",
                        errors: invalid_inputs,
                        message: "Query(s) value is invalid"
                    });

                    return;
                }

                if (pass_limit && pass_limit < limit) {
                    limit = pass_limit;
                }

                if (pass_offset) {
                    offset = pass_offset;
                }

                const mappped_field_name = new Map([
                    ['category', 'categoryID AS category_id'],
                    ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
                    ['title', 'title'],
                    ['highlight', 'highlight'],
                    ['time', 'time']
                ]);
                let select_query = 'SELECT A.articleID AS id, ';
                let select_post = [];
                let count_query = 'SELECT COUNT(*) AS total FROM articles ';
                let count_post = [];

                // check if valid and required fields is given
                if (req.query.fields) {
                    // split the provided fields
                    let req_fields = req.query.fields.split(',');
                    let permitted_field_count = 0;
                    let field_already_exist = [];

                    req_fields.forEach(elem => {
                        if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                            if (permitted_field_count == 0) {
                                select_query += `A.${mappped_field_name.get(elem)}`;

                            } else {
                                select_query += `, A.${mappped_field_name.get(elem)}`;
                            }

                            field_already_exist.push(elem);
                            permitted_field_count++; // increment by one
                        }
                    });

                    if (permitted_field_count < 1) {
                        select_query =
                            'SELECT A.newsID AS id, A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, A.title, ' +
                            'A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                            'B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID ';

                    } else {
                        select_query +=
                            ', B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                            'B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID ';
                    }

                } else { // no fields selection
                    select_query +=
                        ' A.categoryID AS category_id, A.featuredImageURL AS featured_image_url, A.title, ' +
                        'A.highlight, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                        'B.profilePictureBigURL FROM articles AS A LEFT JOIN user AS B ON A.userID = B.userID ';
                }

                // from all published location
                if (!pref_location_id) {
                    select_query += 'WHERE (A.regionID = ? OR A.restrictedToLocation = ?) ';
                    select_post.push(location_id);
                    select_post.push(0);

                    // count query
                    count_query += 'WHERE (regionID = ? OR restrictedToLocation = ?) ';
                    count_post.push(location_id);
                    count_post.push(0);

                } else { // from set preferred location
                    select_query += 'WHERE A.regionID = ? ';
                    select_post.push(pref_location_id);

                    // count query
                    count_query += 'WHERE regionID = ? ';
                    count_post.push(pref_location_id);
                }

                // check if preferred location is provided and not equal to each other
                if (pref_location_id && location_id != pref_location_id) {
                    select_query += 'AND A.restrictedToLocation = ? ';
                    select_post.push(0);

                    // count query
                    count_query += 'AND restrictedToLocation = ? ';
                    count_post.push(0);
                }

                // category to retrieve or search
                if (category_id) {
                    // category to select
                    select_query += 'AND A.categoryID = ? ';
                    select_post.push(category_id);

                    // count query
                    count_query += 'AND categoryID = ? ';
                    count_post.push(category_id);
                }

                // check if user pass in search query
                if (search) {
                    let temp_search = ' ' + decodeURIComponent(search.toString()).trim() + ' ';
                    temp_search = temp_search.replace(/\s+/g, ' % ').trim();

                    select_query += `AND A.title LIKE '${temp_search}' `;
                    count_query += `AND title LIKE '${temp_search}' `;
                }

                // last published news should come first
                select_query += 'ORDER BY A.time DESC ';

                // set limit and offset
                select_query += `LIMIT ${limit} OFFSET ${offset}`;

                // get metadata for user's publication
                gDB.query(count_query, count_post).then(count_results => {
                    // get publication
                    gDB.query(select_query, select_post).then(results => {
                        for (let i = 0; i < results.length; i++) {
                            // check if user has a profile picture
                            if (results[i].profilePictureSmallURL) {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: {
                                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                    }
                                };

                            } else {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: null
                                };
                            }

                            // remove keys
                            delete results[i].userID;
                            delete results[i].firstName;
                            delete results[i].lastName;
                            delete results[i].profilePictureSmallURL;
                            delete results[i].profilePictureMediumURL;
                            delete results[i].profilePictureBigURL;
                        }

                        // send result to client
                        res.status(200);
                        res.json({
                            articles: results,
                            metadata: {
                                result_set: {
                                    count: results.length,
                                    offset: offset,
                                    limit: limit,
                                    total: count_results[0].total
                                }
                            }
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// like published news
router.post('/news/:news_id/likes', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if user has dislike this news and delete user dislike
        gDB.query(
            'DELETE FROM news_dislikes WHERE newsID = ? AND userID = ? LIMIT 1',
            [req.params.news_id, user_id]
        ).then(results => {
            // add user to like table
            gDB.query(
                'INSERT INTO news_likes (newsID, userID) VALUES (?, ?)',
                [req.params.news_id, user_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                // check if is a duplicate error
                if (err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                    return res.status(200).send();
                }

                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// like published article
router.post('/articles/:article_id/likes', custom_utils.allowedScopes(['write:article', 'write:article:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if user has dislike this news and delete user dislike
        gDB.query(
            'DELETE FROM article_dislikes WHERE articleID = ? AND userID = ? LIMIT 1',
            [req.params.article_id, user_id]
        ).then(results => {
            // add user to like table
            gDB.query(
                'INSERT INTO article_likes (articleID, userID) VALUES (?, ?)',
                [req.params.article_id, user_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                // check if is a duplicate error
                if (err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                    return res.status(200).send();
                }

                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

//undo like for published news
router.delete('/news/:news_id/like', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // undo user like
        gDB.query(
            'DELETE FROM news_likes WHERE newsID = ? AND userID = ? LIMIT 1',
            [req.params.news_id, user_id]
        ).then(results => {
            res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

//undo like for published article
router.delete('/articles/:article_id/like', custom_utils.allowedScopes(['write:article', 'write:article:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // undo user like
        gDB.query(
            'DELETE FROM article_likes WHERE articleID = ? AND userID = ? LIMIT 1',
            [req.params.article_id, user_id]
        ).then(results => {
            res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get like metadata information for news
router.get('/news/:news_id/likes', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // retrieve metadata information
        gDB.query(
            'SELECT COUNT(*) AS total FROM news_likes WHERE newsID = ?',
            [req.params.news_id]
        ).then(count_results => {
            // check if user have like this news
            gDB.query(
                'SELECT 1 FROM news_likes WHERE newsID = ? AND userID = ? LIMIT 1',
                [req.params.news_id, user_id]
            ).then(results => {
                // send result to client
                res.status(200);
                res.json({
                    metadata: {
                        total: count_results[0].total,
                        user_reaction: {
                            liked: results.length > 0 ? 1 : 0
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get like metadata information for article
router.get('/articles/:article_id/likes', custom_utils.allowedScopes(['read:article', 'read:article:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // retrieve metadata information
        gDB.query(
            'SELECT COUNT(*) AS total FROM article_likes WHERE articleID = ?',
            [req.params.news_id]
        ).then(count_results => {
            // check if user have like this article
            gDB.query(
                'SELECT 1 FROM article_likes WHERE articleID = ? AND userID = ? LIMIT 1',
                [req.params.news_id, user_id]
            ).then(results => {
                // send result to client
                res.status(200);
                res.json({
                    metadata: {
                        total: count_results[0].total,
                        user_reaction: {
                            liked: results.length > 0 ? 1 : 0
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// dislike published news
router.post('/news/:news_id/dislikes', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if user has like this news and delete user like
        gDB.query(
            'DELETE FROM news_likes WHERE newsID = ? AND userID = ? LIMIT 1',
            [req.params.news_id, user_id]
        ).then(results => {
            // add user to dislike table
            gDB.query(
                'INSERT INTO news_dislikes (newsID, userID) VALUES (?, ?)',
                [req.params.news_id, user_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                // check if is a duplicate error
                if (err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                    return res.status(200).send();
                }

                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// dislike published article
router.post('/articles/:article_id/dislikes', custom_utils.allowedScopes(['write:article', 'write:article:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if user has like this news and delete user like
        gDB.query(
            'DELETE FROM article_likes WHERE articleID = ? AND userID = ? LIMIT 1',
            [req.params.article_id, user_id]
        ).then(results => {
            // add user to dislike table
            gDB.query(
                'INSERT INTO article_dislikes (articleID, userID) VALUES (?, ?)',
                [req.params.article_id, user_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                // check if is a duplicate error
                if (err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                    return res.status(200).send();
                }

                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

//undo dislike for published news
router.delete('/news/:news_id/dislike', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // undo user dislike
        gDB.query(
            'DELETE FROM news_dislikes WHERE newsID = ? AND userID = ? LIMIT 1',
            [req.params.news_id, user_id]
        ).then(results => {
            res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

//undo dislike for published article
router.delete('/articles/:article_id/dislike', custom_utils.allowedScopes(['write:article', 'write:article:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // undo user dislike
        gDB.query(
            'DELETE FROM article_dislikes WHERE articleID = ? AND userID = ? LIMIT 1',
            [req.params.article_id, user_id]
        ).then(results => {
            res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get dislike metadata information for news
router.get('/news/:news_id/dislikes', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // retrieve metadata information
        gDB.query(
            'SELECT COUNT(*) AS total FROM news_dislikes WHERE newsID = ?',
            [req.params.news_id]
        ).then(count_results => {
            // check if user have dislike this news
            gDB.query(
                'SELECT 1 FROM news_dislikes WHERE newsID = ? AND userID = ? LIMIT 1',
                [req.params.news_id, user_id]
            ).then(results => {
                // send result to client
                res.status(200);
                res.json({
                    metadata: {
                        total: count_results[0].total,
                        user_reaction: {
                            disliked: results.length > 0 ? 1 : 0
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get dislike metadata information for article
router.get('/articles/:article_id/dislikes', custom_utils.allowedScopes(['read:article', 'read:article:all']), (req, res) => {
    // check if id is valid
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // get user ID from access token
    const user_id = req.user.access_token.user_id;

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // retrieve metadata information
        gDB.query(
            'SELECT COUNT(*) AS total FROM article_dislikes WHERE articleID = ?',
            [req.params.article_id]
        ).then(count_results => {
            // check if user have dislike this article
            gDB.query(
                'SELECT 1 FROM article_dislikes WHERE articleID = ? AND userID = ? LIMIT 1',
                [req.params.article_id, user_id]
            ).then(results => {
                // send result to client
                res.status(200);
                res.json({
                    metadata: {
                        total: count_results[0].total,
                        user_reaction: {
                            disliked: results.length > 0 ? 1 : 0
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// post comment for a news
router.post('/news/:news_id/comments', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if some field contain valid data
        const invalid_inputs = [];

        if (!req.body.comment) {
            invalid_inputs.push({
                error_code: "undefined_data",
                field: "comment",
                message: "comment has to be defined"
            });

        } else if (!(typeof req.body.comment == 'string' && req.body.comment.trim().length > 0)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "comment",
                message: "comment is not acceptable"
            });

        } else if (req.body.comment.trim().length > 1500) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "comment",
                message: "comment exceed maximum allowed text"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs,
                message: "Field(s) value not acceptable"
            });

            return;
        }

        // generate sixten digit unique id
        const comment_id = rand_token.generate(16);

        // insert comment into database
        gDB.query(
            'INSERT INTO news_comments (newsID, commentID, userID, ' +
            'comment) VALUES (?, ?, ?, ?)',
            [
                req.params.news_id,
                comment_id,
                req.user.access_token.user_id,
                req.body.comment.trim()
            ]
        ).then(results => {
            res.status(201);
            res.json({
                comment_id: comment_id
            });

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// post comment for an article
router.post('/articles/:article_id/comments', custom_utils.allowedScopes(['write:articles', 'write:articles:all']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if some field contain valid data
        const invalid_inputs = [];

        if (!req.body.comment) {
            invalid_inputs.push({
                error_code: "undefined_data",
                field: "comment",
                message: "comment has to be defined"
            });

        } else if (!(typeof req.body.comment == 'string' && req.body.comment.trim().length > 0)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "comment",
                message: "comment is not acceptable"
            });

        } else if (req.body.comment.trim().length > 1500) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "comment",
                message: "comment exceed maximum allowed text"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs,
                message: "Field(s) value not acceptable"
            });

            return;
        }

        // generate sixten digit unique id
        const comment_id = rand_token.generate(16);

        // insert comment into database
        gDB.query(
            'INSERT INTO article_comments (articleID, commentID, userID, ' +
            'comment) VALUES (?, ?, ?, ?)',
            [
                req.params.article_id,
                comment_id,
                req.user.access_token.user_id,
                req.body.comment.trim()
            ]
        ).then(results => {
            res.status(201);
            res.json({
                comment_id: comment_id
            });

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get comment for a news
router.get('/news/:news_id/comments/:cmt_id', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.news_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    //get comment from database
    gDB.query(
        'SELECT userID, comment, replyCount, time FROM news_comments WHERE newsID = ? AND commentID = ? LIMIT 1',
        [req.params.news_id, req.params.cmt_id]
    ).then(cmt_results => {
        // check if there is result
        if (cmt_results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Comment can't be found"
            });

            return;
        }

        // get user's information that commented
        gDB.query(
            'SELECT firstName, lastName, profilePictureSmallURL, profilePictureMediumURL, profilePictureBigURL FROM user WHERE userID = ? LIMIT 1',
            [cmt_results[0].userID]
        ).then(results => {
            // check if user has a profile picture
            if (results[0].profilePictureSmallURL) {
                // prepare the results
                res.status(200);
                res.json({
                    comment: cmt_results[0].comment,
                    reply_count: cmt_results[0].replyCount,
                    time: cmt_results[0].time,
                    user: {
                        id: cmt_results[0].userID,
                        name: results[0].lastName + ' ' + results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureSmallURL
                        }
                    }
                });

            } else {
                // prepare the results
                res.status(200);
                res.json({
                    comment: cmt_results[0].comment,
                    reply_count: cmt_results[0].replyCount,
                    time: cmt_results[0].time,
                    user: {
                        id: cmt_results[0].userID,
                        name: results[0].lastName + ' ' + results[0].firstName,
                        image: null
                    }
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get comment for an article
router.get('/articles/:article_id/comments/:cmt_id', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.article_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    //get comment from database
    gDB.query(
        'SELECT userID, comment, replyCount, time FROM article_comments WHERE articleID = ? AND commentID = ? LIMIT 1',
        [req.params.article_id, req.params.cmt_id]
    ).then(cmt_results => {
        // check if there is result
        if (cmt_results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Comment can't be found"
            });

            return;
        }

        // get user's information that commented
        gDB.query(
            'SELECT firstName, lastName, profilePictureSmallURL, profilePictureMediumURL, profilePictureBigURL FROM user WHERE userID = ? LIMIT 1',
            [cmt_results[0].userID]
        ).then(results => {
            // check if user has a profile picture
            if (results[0].profilePictureSmallURL) {
                // prepare the results
                res.status(200);
                res.json({
                    comment: cmt_results[0].comment,
                    reply_count: cmt_results[0].replyCount,
                    time: cmt_results[0].time,
                    user: {
                        id: cmt_results[0].userID,
                        name: results[0].lastName + ' ' + results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureSmallURL
                        }
                    }
                });

            } else {
                // prepare the results
                res.status(200);
                res.json({
                    comment: cmt_results[0].comment,
                    reply_count: cmt_results[0].replyCount,
                    time: cmt_results[0].time,
                    user: {
                        id: cmt_results[0].userID,
                        name: results[0].lastName + ' ' + results[0].firstName,
                        image: null
                    }
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the comment for a news
router.get('/news/:news_id/comments', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // set limit and offset
        let limit = 50;
        let offset = 0;
        let pass_limit = req.query.limit;
        let pass_offset = req.query.offset;
        const invalid_inputs = [];

        // check if query is valid
        if (pass_limit && !/^\d+$/.test(pass_limit)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "limit",
                message: "value must be integer"
            });
        }

        if (pass_offset && !/^\d+$/.test(pass_offset)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "offset",
                message: "value must be integer"
            });
        }

        // check if any query is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_query",
                errors: invalid_inputs,
                message: "Query(s) value is invalid"
            });

            return;
        }

        if (pass_limit && pass_limit < limit) {
            limit = pass_limit;
        }

        if (pass_offset) {
            offset = pass_offset;
        }

        // get total count of comment with "replyToCommentID" equal to -1
        gDB.query(
            'SELECT COUNT(*) AS total FROM news_comments WHERE newsID = ? AND replyToCommentID = ?',
            [req.params.news_id, -1]
        ).then(cmt_results => {
            // get all comment
            gDB.query(
                'SELECT A.commentID, A.comment, A.replyCount, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                'B.profilePictureBigURL FROM news_comments AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.newsID = ? ' +
                `AND A.replyToCommentID = ? ORDER BY A.time DESC LIMIT ${limit} OFFSET ${offset}`,
                [
                    req.params.news_id,
                    -1
                ]
            ).then(results => {
                let comments = [];
                for (let i = 0; i < results.length; i++) {
                    // check if user has a profile picture
                    if (results[i].profilePictureSmallURL) {
                        comments.push({
                            comment: results[i].comment,
                            id: results[i].commentID,
                            reply_count: results[i].replyCount,
                            time: results[i].time,
                            user: {
                                id: results[i].userID,
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: {
                                    big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                    medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                    small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                }
                            }
                        });

                    } else {
                        comments.push({
                            comment: results[i].comment,
                            id: results[i].commentID,
                            reply_count: results[i].replyCount,
                            time: results[i].time,
                            user: {
                                id: results[i].userID,
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: null
                            }
                        });
                    }
                }

                // send results to client
                res.status(200);
                res.json({
                    comments: comments,
                    metadata: {
                        result_set: {
                            count: results.length,
                            offset: offset,
                            limit: limit,
                            total: cmt_results[0].total
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the comment for an article
router.get('/articles/:article_id/comments', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // set limit and offset
        let limit = 50;
        let offset = 0;
        let pass_limit = req.query.limit;
        let pass_offset = req.query.offset;
        const invalid_inputs = [];

        // check if query is valid
        if (pass_limit && !/^\d+$/.test(pass_limit)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "limit",
                message: "value must be integer"
            });
        }

        if (pass_offset && !/^\d+$/.test(pass_offset)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "offset",
                message: "value must be integer"
            });
        }

        // check if any query is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_query",
                errors: invalid_inputs,
                message: "Query(s) value is invalid"
            });

            return;
        }

        if (pass_limit && pass_limit < limit) {
            limit = pass_limit;
        }

        if (pass_offset) {
            offset = pass_offset;
        }

        // get total count of comment with "replyToCommentID" equal to -1
        gDB.query(
            'SELECT COUNT(*) AS total FROM article_comments WHERE articleID = ? AND replyToCommentID = ?',
            [req.params.article_id, -1]
        ).then(cmt_results => {
            // get all comment
            gDB.query(
                'SELECT A.commentID, A.comment, A.replyCount, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                'B.profilePictureBigURL FROM article_comments AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ? ' +
                `AND A.replyToCommentID = ? ORDER BY A.time DESC LIMIT ${limit} OFFSET ${offset}`,
                [
                    req.params.article_id,
                    -1
                ]
            ).then(results => {
                let comments = [];
                for (let i = 0; i < results.length; i++) {
                    // check if user has a profile picture
                    if (results[i].profilePictureSmallURL) {
                        comments.push({
                            comment: results[i].comment,
                            id: results[i].commentID,
                            reply_count: results[i].replyCount,
                            time: results[i].time,
                            user: {
                                id: results[i].userID,
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: {
                                    big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                    medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                    small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                }
                            }
                        });

                    } else {
                        comments.push({
                            comment: results[i].comment,
                            id: results[i].commentID,
                            reply_count: results[i].replyCount,
                            time: results[i].time,
                            user: {
                                id: results[i].userID,
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: null
                            }
                        });
                    }
                }

                // send results to client
                res.status(200);
                res.json({
                    comments: comments,
                    metadata: {
                        result_set: {
                            count: results.length,
                            offset: offset,
                            limit: limit,
                            total: cmt_results[0].total
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// post reply for comment for a news
router.post('/news/:news_id/comments/:cmt_id/replies', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.news_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT 1 FROM news_comments WHERE newsID = ? AND commentID = ? LIMIT 1',
            [req.params.news_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                // article doesn't exist
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // check if some field contain valid data
            const invalid_inputs = [];

            if (!req.body.comment) {
                invalid_inputs.push({
                    error_code: "undefined_data",
                    field: "comment",
                    message: "comment has to be defined"
                });

            } else if (!(typeof req.body.comment == 'string' && req.body.comment.trim().length > 0)) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment is not acceptable"
                });

            } else if (req.body.comment.trim().length > 1500) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment exceed maximum allowed text"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // generate sixten digit unique id
            const comment_id = rand_token.generate(16);

            // insert comment into database
            gDB.transaction(
                {
                    query: 'UPDATE news_comments SET replyCount = replyCount + 1 WHERE newsID = ? AND commentID = ? LIMIT 1',
                    post: [
                        req.params.news_id,
                        req.params.cmt_id
                    ]
                },
                {
                    query: 'INSERT INTO news_comments (newsID, commentID, userID, ' +
                        'comment, replyToCommentID) VALUES (?, ?, ?, ?, ?)',
                    post: [
                        req.params.news_id,
                        comment_id,
                        req.user.access_token.user_id,
                        req.body.comment.trim(),
                        req.params.cmt_id
                    ]
                }
            ).then(results => {
                res.status(201);
                res.json({
                    comment_id: comment_id
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// post reply for comment for an article
router.post('/articles/:article_id/comments/:cmt_id/replies', custom_utils.allowedScopes(['write:articles', 'write:articles:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.article_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT 1 FROM article_comments WHERE articleID = ? AND commentID = ? LIMIT 1',
            [req.params.article_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                // article doesn't exist
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // check if some field contain valid data
            const invalid_inputs = [];

            if (!req.body.comment) {
                invalid_inputs.push({
                    error_code: "undefined_data",
                    field: "comment",
                    message: "comment has to be defined"
                });

            } else if (!(typeof req.body.comment == 'string' && req.body.comment.trim().length > 0)) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment is not acceptable"
                });

            } else if (req.body.comment.trim().length > 1500) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment exceed maximum allowed text"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // generate sixten digit unique id
            const comment_id = rand_token.generate(16);

            // insert comment into database
            gDB.transaction(
                {
                    query: 'UPDATE article_comments SET replyCount = replyCount + 1 WHERE articleID = ? AND commentID = ? LIMIT 1',
                    post: [
                        req.params.article_id,
                        req.params.cmt_id
                    ]
                },
                {
                    query: 'INSERT INTO article_comments (articleID, commentID, userID, ' +
                        'comment, replyToCommentID) VALUES (?, ?, ?, ?, ?)',
                    post: [
                        req.params.article_id,
                        comment_id,
                        req.user.access_token.user_id,
                        req.body.comment.trim(),
                        req.params.cmt_id
                    ]
                }
            ).then(results => {
                res.status(201);
                res.json({
                    comment_id: comment_id
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the replies for a comment (news)
router.get('/news/:news_id/comments/:cmt_id/replies', custom_utils.allowedScopes(['read:news', 'read:news:all']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.news_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // news doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT 1 FROM news_comments WHERE newsID = ? AND commentID = ? LIMIT 1',
            [req.params.news_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                // news doesn't exist
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // set limit and offset
            let limit = 50;
            let offset = 0;
            let pass_limit = req.query.limit;
            let pass_offset = req.query.offset;
            const invalid_inputs = [];

            // check if query is valid
            if (pass_limit && !/^\d+$/.test(pass_limit)) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "limit",
                    message: "value must be integer"
                });
            }

            if (pass_offset && !/^\d+$/.test(pass_offset)) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "offset",
                    message: "value must be integer"
                });
            }

            // check if any query is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs,
                    message: "Query(s) value is invalid"
                });

                return;
            }

            if (pass_limit && pass_limit < limit) {
                limit = pass_limit;
            }

            if (pass_offset) {
                offset = pass_offset;
            }

            // count the replies to a comment
            gDB.query(
                'SELECT COUNT(*) AS total FROM news_comments WHERE newsID = ? AND replyToCommentID = ?',
                [req.params.news_id, req.params.cmt_id]
            ).then(cmt_results => {
                // get all comment
                gDB.query(
                    'SELECT A.commentID, A.comment, A.replyCount, A.time, B.userID, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                    'B.profilePictureBigURL FROM news_comments AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.newsID = ? ' +
                    `AND A.replyToCommentID = ? ORDER BY A.time DESC LIMIT ${limit} OFFSET ${offset}`,
                    [
                        req.params.news_id,
                        req.params.cmt_id
                    ]
                ).then(results => {
                    let comments = [];
                    for (let i = 0; i < results.length; i++) {
                        // check if user has a profile picture
                        if (results[i].profilePictureSmallURL) {
                            comments.push({
                                comment: results[i].comment,
                                id: results[i].commentID,
                                reply_count: results[i].replyCount,
                                time: results[i].time,
                                user: {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: {
                                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                    }
                                }
                            });

                        } else {
                            comments.push({
                                comment: results[i].comment,
                                id: results[i].commentID,
                                reply_count: results[i].replyCount,
                                time: results[i].time,
                                user: {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: null
                                }
                            });
                        }
                    }

                    // send results to client
                    res.status(201);
                    res.json({
                        comments: comments,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: cmt_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the replies for a comment (article)
router.get('/articles/:article_id/comments/:cmt_id/replies', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // check if user id is integer
    if (!/^\d+$/.test(req.params.article_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT 1 FROM article_comments WHERE articleID = ? AND commentID = ? LIMIT 1',
            [req.params.article_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                // article doesn't exist
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // set limit and offset
            let limit = 50;
            let offset = 0;
            let pass_limit = req.query.limit;
            let pass_offset = req.query.offset;
            const invalid_inputs = [];

            // check if query is valid
            if (pass_limit && !/^\d+$/.test(pass_limit)) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "limit",
                    message: "value must be integer"
                });
            }

            if (pass_offset && !/^\d+$/.test(pass_offset)) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "offset",
                    message: "value must be integer"
                });
            }

            // check if any query is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs,
                    message: "Query(s) value is invalid"
                });

                return;
            }

            if (pass_limit && pass_limit < limit) {
                limit = pass_limit;
            }

            if (pass_offset) {
                offset = pass_offset;
            }

            // count the replies to a comment
            gDB.query(
                'SELECT COUNT(*) AS total FROM article_comments WHERE articleID = ? AND replyToCommentID = ?',
                [req.params.article_id, req.params.cmt_id]
            ).then(cmt_results => {
                // get all comment
                gDB.query(
                    'SELECT A.commentID, A.comment, A.replyCount, A.time, B.firstName, B.userID, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                    'B.profilePictureBigURL FROM article_comments AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ? ' +
                    `AND A.replyToCommentID = ? ORDER BY A.time DESC LIMIT ${limit} OFFSET ${offset}`,
                    [
                        req.params.article_id,
                        req.params.cmt_id
                    ]
                ).then(results => {
                    let comments = [];
                    for (let i = 0; i < results.length; i++) {
                        // check if user has a profile picture
                        if (results[i].profilePictureSmallURL) {
                            comments.push({
                                comment: results[i].comment,
                                id: results[i].commentID,
                                reply_count: results[i].replyCount,
                                time: results[i].time,
                                user: {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: {
                                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                    }
                                }
                            });

                        } else {
                            comments.push({
                                comment: results[i].comment,
                                id: results[i].commentID,
                                reply_count: results[i].replyCount,
                                time: results[i].time,
                                user: {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: null
                                }
                            });
                        }
                    }

                    // send results to client
                    res.status(201);
                    res.json({
                        comments: comments,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: cmt_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// Edit news comment
router.put('/news/:news_id/comments/:cmt_id', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.news_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT userID FROM news_comments WHERE newsID = ? AND commentID = ? LIMIT 1',
            [req.params.news_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                // news doesn't exist
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // check if user is the one that post the comment
            if (!req.user.access_token.user_id == results[0].userID) {
                res.status(401);
                res.json({
                    error_code: "unauthorized_user",
                    message: "Unauthorized"
                });

                return;
            }

            // check if some field contain valid data
            const invalid_inputs = [];

            if (!req.body.comment) {
                invalid_inputs.push({
                    error_code: "undefined_data",
                    field: "comment",
                    message: "comment has to be defined"
                });

            } else if (!(typeof req.body.comment == 'string' && req.body.comment.trim().length > 0)) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment is not acceptable"
                });

            } else if (req.body.comment.trim().length > 1500) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment exceed maximum allowed text"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // update user's comment
            gDB.query(
                'UPDATE news_comments SET comment = ? WHERE newsID = ? AND commentID = ? LIMIT 1',
                [req.body.comment.trim(), req.params.news_id, req.params.cmt_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// Edit article comment
router.put('/articles/:article_id/comments/:cmt_id', custom_utils.allowedScopes(['write:articles', 'write:articles:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.article_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT userID FROM article_comments WHERE articleID = ? AND commentID = ? LIMIT 1',
            [req.params.article_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                // article doesn't exist
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // check if user is the one that post the comment
            if (!req.user.access_token.user_id == results[0].userID) {
                res.status(401);
                res.json({
                    error_code: "unauthorized_user",
                    message: "Unauthorized"
                });

                return;
            }

            // check if some field contain valid data
            const invalid_inputs = [];

            if (!req.body.comment) {
                invalid_inputs.push({
                    error_code: "undefined_data",
                    field: "comment",
                    message: "comment has to be defined"
                });

            } else if (!(typeof req.body.comment == 'string' && req.body.comment.trim().length > 0)) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment is not acceptable"
                });

            } else if (req.body.comment.trim().length > 1500) {
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "comment",
                    message: "comment exceed maximum allowed text"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs,
                    message: "Field(s) value not acceptable"
                });

                return;
            }

            // update user's comment
            gDB.query(
                'UPDATE article_comments SET comment = ? WHERE articleID = ? AND commentID = ? LIMIT 1',
                [req.body.comment.trim(), req.params.article_id, req.params.cmt_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// Delete comment for news
router.delete('/news/:news_id/comments/:cmt_id', custom_utils.allowedScopes(['write:news', 'write:news:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.news_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if news exist
    gDB.query('SELECT 1 FROM news WHERE newsID = ? LIMIT 1', [req.params.news_id]).then(results => {
        if (results.length < 1) {
            // news doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "News doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT userID FROM news_comments WHERE newsID = ? AND commentID = ? LIMIT 1',
            [req.params.news_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // check if user is the one that post the comment
            if (!req.user.access_token.user_id == results[0].userID) {
                res.status(401);
                res.json({
                    error_code: "unauthorized_user",
                    message: "Unauthorized"
                });

                return;
            }

            // delete user's comment
            gDB.query(
                'DELETE FROM news_comments WHERE newsID = ? AND (commentID = ? OR replyToCommentID = ?)',
                [req.params.news_id, req.params.cmt_id, req.params.cmt_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// Delete comment for article
router.delete('/articles/:article_id/comments/:cmt_id', custom_utils.allowedScopes(['write:articles', 'write:articles:all']), (req, res) => {
    // check if user id is integer and comment id is valid
    if (!(/^\d+$/.test(req.params.article_id) && /^[a-zA-Z0-9]{16}$/.test(req.params.cmt_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if article exist
    gDB.query('SELECT 1 FROM articles WHERE articleID = ? LIMIT 1', [req.params.article_id]).then(results => {
        if (results.length < 1) {
            // article doesn't exist
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Article doesn't exist"
            });

            return;
        }

        // check if comment exist
        gDB.query(
            'SELECT userID FROM article_comments WHERE articleID = ? AND commentID = ? LIMIT 1',
            [req.params.article_id, req.params.cmt_id]
        ).then(results => {
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Comment doesn't exist"
                });

                return;
            }

            // check if user is the one that post the comment
            if (!req.user.access_token.user_id == results[0].userID) {
                res.status(401);
                res.json({
                    error_code: "unauthorized_user",
                    message: "Unauthorized"
                });

                return;
            }

            // delete user's comment
            gDB.query(
                'DELETE FROM article_comments WHERE articleID = ? AND (commentID = ? OR replyToCommentID = ?)',
                [req.params.article_id, req.params.cmt_id, req.params.cmt_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the product categories
router.get('/product/categories', custom_utils.allowedScopes(['read:product']), (req, res) => {
    // retrieve from database
    gDB.query('SELECT categoryID AS id, categoryName AS name FROM product_categories').then(results => {
        res.status(200);
        res.json({
            categories: results
        });

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get all the product categories
router.get('/service/categories', custom_utils.allowedScopes(['read:service']), (req, res) => {
    // retrieve from database
    gDB.query('SELECT categoryID AS id, categoryName AS name FROM service_categories').then(results => {
        res.status(200);
        res.json({
            categories: results
        });

        return;

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// create a store for product and work
router.post('/stores', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let store_type = req.query.type;
    let store_category_id = req.query.categoryID;
    let location_id = req.query.locationID;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });

    }

    if (!store_category_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "categoryID",
            message: "categoryID has to be defined"
        });

    } else if (!/^\d+$/.test(store_category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    if (!location_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "locationID",
            message: "locationID has to be defined"
        });

    } else if (!/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    let table_name_1;
    let table_name_2;
    let table_name_3;
    let table_name_4;

    // check store type
    if (store_type == 'product') { // product
        table_name_1 = 'product_categories';
        table_name_2 = 'stores';
        table_name_3 = 'services';
        table_name_4 = 'store_settings';

    } else { // service
        table_name_1 = 'service_categories';
        table_name_2 = 'services';
        table_name_3 = 'stores';
        table_name_4 = 'service_settings';
    }

    // check if category exist
    gDB.query(
        'SELECT 1 FROM ?? WHERE categoryID = ? LIMIT 1',
        [table_name_1, store_category_id]
    ).then(results => {
        if (results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "categoryID",
                message: "categoryID value is invalid"
            });
        }

        // check if location ID exist
        gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id]).then(results => {
            if (results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "locationID",
                    message: "locationID value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs
                });

                return;
            }

            // validate submitted data
            if (!req.body.name) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "name",
                    message: " has to be defined"
                });

            } else if (!/^[a-zA-Z0-9]+$/.test(req.body.name)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "phoneNumber",
                    message: "phoneNumber is not acceptable"
                });
            }

            if (!req.body.description) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "description",
                    message: "description has to be defined"
                });

            } else if (typeof req.body.description != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "description",
                    message: "description is not acceptable"
                });

            } else if (req.body.description.length > 500) { // check if description exceed 500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "description",
                    message: "description exceed maximum allowed text"
                });
            }

            if (!req.body.address) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "address",
                    message: "address has to be defined"
                });

            } else if (typeof req.body.address != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "address",
                    message: "address is not acceptable"
                });
            }

            if (!req.body.email) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "email",
                    message: "email has to be defined"
                });

            } else if (!validator.isEmail(req.body.email)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "email",
                    message: "email is not acceptable"
                });
            }

            if (!req.body.phoneNumber) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "phoneNumber",
                    message: "phoneNumber has to be defined"
                });

            } else if (!/^\d+$/.test(req.body.phoneNumber)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "phoneNumber",
                    message: "phoneNumber is not acceptable"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            // generate hash of 40 characters length from user's store name
            const search_name_hash = crypto.createHash("sha1").update(req.body.name, "binary").digest("hex");

            // check if store name has been used
            gDB.query('SELECT 1 FROM ?? WHERE searchStoreHash = ? LIMIT 1', [table_name_2, searchStoreHash]).then(results => {
                if (results.length > 0) {
                    invalid_inputs.push({
                        error_code: "input_exist",
                        field: "name",
                        message: "Store name has been used"
                    });

                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "invalid_field",
                        errors: invalid_inputs
                    });

                    return;
                }

                // check if store name has been used
                gDB.query('SELECT 1 FROM ?? WHERE searchStoreHash = ? LIMIT 1', [table_name_3, searchStoreHash]).then(results => {
                    if (results.length > 0) {
                        invalid_inputs.push({
                            error_code: "input_exist",
                            field: "name",
                            message: "Store name has been used"
                        });

                        // send json error message to client
                        res.status(406);
                        res.json({
                            error_code: "invalid_field",
                            errors: invalid_inputs
                        });

                        return;
                    }

                    // create store for products
                    gDB.transaction(
                        {
                            query: 'SELECT @start_slot:=slotCount FROM ?? WHERE id = ?',
                            post: [table_name_4, 1]
                        },
                        {
                            query: 'INSERT INTO ?? (userID, categoryID, storeName, searchStoreHash, storeDescription, locationID, ' +
                                'contactAddress, contactEmail, contactPhoneNumber, slotCount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, @start_slot)',
                            post: [
                                table_name_2,
                                user_id,
                                store_category_id,
                                req.body.name,
                                search_name_hash,
                                req.body.description,
                                location_id,
                                req.body.address,
                                req.body.email,
                                req.body.phoneNumber
                            ]
                        }
                    ).then(results => {
                        gDB.query('SELECT storeID FROM ?? WHERE searchStoreHash = ? LIMIT 1', [table_name_2, search_name_hash]).then(results => {
                            res.status(201);
                            res.json({
                                store_id: results[0].storeID
                            });

                            return;
                        });

                    }).catch(err => {
                        // check if is a duplicate error
                        if (err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                            res.status(409);
                            res.json({
                                error_code: "data_already_exist",
                                message: "User has created a store"
                            });

                            return;
                        }

                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get stores base on search and set preference or get user's store by user ID
router.get('/stores', custom_utils.allowedScopes(['read:stores']), (req, res) => {
    // initialise variables
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const store_type = req.query.type;
    const pass_user_id = req.query.userID;
    const store_name = req.query.name;
    const location_id = req.query.locationID;
    const category_id = req.query.categoryID;
    const invalid_inputs = [];

    // check whether to get only user's store
    if (pass_user_id) {
        // query type must be provided
        if (!store_type) {
            invalid_inputs.push({
                error_code: "undefined_value",
                field: "type",
                message: "type is not provided"
            });

        } else if (!/^(product|service)$/.test(store_type)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "type",
                message: "type value is invalid"
            });
        }

        // check if userID is valid
        if (!/^\d+$/.test(pass_user_id)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "userID",
                message: "value must be integer"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_query",
                errors: invalid_inputs
            });

            return;
        }

        let store_table_name;

        // check store type
        if (store_type == 'product') {
            store_table_name = 'stores';

        } else {
            store_table_name = 'services';
        }

        const mappped_field_name = new Map([
            ['location', 'locationID AS location_id'],
            ['category', 'categoryID AS category_id'],
            ['name', 'storeName AS name'],
            ['featuredImage', 'featuredImageRelativeURL'],
            ['description', 'description'],
            ['time', 'time']
        ]);
        let select_query = 'SELECT storeID AS id, ';
        let select_post = [];

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                select_query =
                    'SELECT storeID AS id, categoryID AS category_id, storeName As name, featuredImageRelativeURL, ' +
                    `storeDescription AS description, locationID AS location_id, time, FROM ${store_table_name} `;

            } else {
                select_query +=
                    ` FROM ${store_table_name} `;
            }

        } else { // no fields selection
            select_query +=
                'categoryID AS category_id, storeName As name, featuredImageRelativeURL, ' +
                `storeDescription AS description, locationID AS location_id, time, FROM ${store_table_name} `;
        }

        // query search condition
        select_query += 'WHERE userID = ? LIMIT 1';
        select_post.push(pass_user_id);

        // get user's store
        gDB.query(select_query, select_post).then(results => {
            if (results.length < 1) {
                // send result to client
                res.status(200);
                res.json({ stores: [] });

                return;
            }

            // check if this store has featured image
            if (results[0].featuredImageRelativeURL) {
                // add featured image to results
                results[0].featured_img = {
                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL,
                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'medium'),
                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'small'),
                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'tiny')
                };

            } else if (typeof results[0].featuredImageRelativeURL != 'undefined') {
                // add featured image to results
                results[0].featured_img = null;
            }

            // remove keys
            delete results[0].featuredImageRelativeURL;

            // send result to client
            res.status(200);
            res.json({ stores: results });

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    } else {
        // query type must be provided
        if (!store_type) {
            invalid_inputs.push({
                error_code: "undefined_value",
                field: "type",
                message: "type is not provided"
            });

        } else if (!/^(product|service)$/.test(store_type)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "type",
                message: "type value is invalid"
            });
        }

        // check if query location ID is provided
        if (location_id && !/^\d+$/.test(location_id)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if query category ID is provided
        if (category_id && !/^\d+$/.test(category_id)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "categoryID",
                message: "categoryID value is invalid"
            });
        }

        // check if query name is provided
        if (store_name && !/^[a-zA-Z0-9]+$/.test(store_name)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "name",
                message: "name value is invalid"
            });
        }

        // check if limit is defined and valid
        if (pass_limit && !/^\d+$/.test(pass_limit)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "limit",
                message: "value must be integer"
            });
        }

        // check if offset is defined and valid
        if (pass_offset && !/^\d+$/.test(pass_offset)) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "offset",
                message: "value must be integer"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_query",
                errors: invalid_inputs
            });

            return;
        }

        let store_table_name;
        let category_table_name;

        // check store type
        if (store_type == 'product') {
            store_table_name = 'stores';
            category_table_name = 'product_categories';

        } else {
            store_table_name = 'services';
            category_table_name = 'service_categories';
        }

        // check if region with location ID exist
        gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id ? location_id : 0]).then(results => {
            if (location_id && results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "locationID",
                    message: "locationID value is invalid"
                });
            }

            // check if category ID exist
            gDB.query(
                'SELECT 1 FROM ?? WHERE categoryID = ? LIMIT 1',
                [category_table_name, category_id ? category_id : 0]
            ).then(results => {
                if (category_id && results.length < 1) {
                    invalid_inputs.push({
                        error_code: "invalid_value",
                        field: "categoryID",
                        message: "categoryID value is invalid"
                    });
                }

                // check if any input is invalid
                if (invalid_inputs.length > 0) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "invalid_query",
                        errors: invalid_inputs
                    });

                    return;
                }

                if (pass_limit && pass_limit < limit) {
                    limit = pass_limit;
                }

                if (pass_offset) {
                    offset = pass_offset;
                }

                let req_fields = null;

                if (req.query.fields) {
                    req_fields = custom_utils.filterInArray(
                        req.query.fields.split(','),
                        ['user', 'location', 'category', 'name', 'featuredImage', 'description', 'time']
                    );
                }

                const mappped_field_name = new Map([
                    ['location', 'locationID AS location_id'],
                    ['category', 'categoryID AS category_id'],
                    ['name', 'storeName AS name'],
                    ['featuredImage', 'featuredImageRelativeURL'],
                    ['description', 'description'],
                    ['time', 'time']
                ]);

                let permitted_field_count = 0;
                let field_already_exist = [];

                // check to retrieve information about the user that add the product
                if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
                    let select_query = 'SELECT A.storeID AS id, A.userID';
                    let select_post = [];
                    let count_query = `SELECT COUNT(*) AS total FROM ${store_table_name} `;
                    let count_post = [];

                    // check if valid and required fields is given
                    if (req_fields && req_fields.length > 0) {
                        req_fields.forEach(elem => {
                            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                                if (permitted_field_count == 0) {
                                    select_query += `, A.${mappped_field_name.get(elem)}`;

                                } else {
                                    select_query += `, A.${mappped_field_name.get(elem)}`;
                                }

                                field_already_exist.push(elem);
                                permitted_field_count++; // increment by one
                            }
                        });

                        select_query +=
                            ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                            `B.profilePictureBigURL FROM ${store_table_name} AS A LEFT JOIN user AS B ON A.userID = B.userID `;

                    } else {
                        select_query +=
                            ', A.categoryID AS category_id, A.storeName As name, A.featuredImageRelativeURL, ' +
                            'A.storeDescription AS description, A.locationID AS location_id, A.time, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                            `B.profilePictureMediumURL, B.profilePictureBigURL FROM ${store_table_name} AS A LEFT JOIN user AS B ON A.userID = B.userID `;
                    }

                    let counter = 0; // count numbers of search keyword

                    if (category_id) {
                        select_query += 'WHERE A.categoryID = ? ';
                        select_post.push(category_id);

                        // count query
                        count_query += 'WHERE categoryID = ? ';
                        count_post.push(category_id);

                        counter++;
                    }

                    // search table by user's store name
                    if (store_name) {
                        const search_name_hash = crypto.createHash("sha1").update(store_name, "binary").digest("hex");

                        if (counter > 0) {
                            select_query += 'AND A.searchStoreHash = ? ';
                            select_post.push(search_name_hash);

                            // count query
                            count_query += 'AND searchStoreHash = ? ';
                            count_post.push(search_name_hash);

                        } else {
                            select_query += 'WHERE A.searchStoreHash = ? ';
                            select_post.push(search_name_hash);

                            // count query
                            count_query += 'WHERE searchStoreHash = ? ';
                            count_post.push(search_name_hash);
                        }

                        counter++;
                    }

                    if (location_id) {
                        if (counter > 0) {
                            select_query += 'AND A.locationID = ? ';
                            select_post.push(location_id);

                            // count query
                            count_query += 'AND locationID = ? ';
                            count_post.push(location_id);

                        } else {
                            select_query += 'WHERE A.locationID = ? ';
                            select_post.push(location_id);

                            // count query
                            count_query += 'WHERE locationID = ? ';
                            count_post.push(location_id);
                        }

                        counter++;
                    }

                    // last should come first
                    select_query += 'ORDER BY A.time DESC ';

                    // set limit and offset
                    select_query += `LIMIT ${limit} OFFSET ${offset}`;

                    // get metadata for user's publication
                    gDB.query(count_query, count_post).then(count_results => {
                        // get publication
                        gDB.query(select_query, select_post).then(results => {
                            for (let i = 0; i < results.length; i++) {
                                // check if this store has featured image
                                if (results[i].featuredImageRelativeURL) {
                                    // add featured image to results
                                    results[i].featured_img = {
                                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL,
                                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL).replace('big', 'medium'),
                                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL).replace('big', 'small'),
                                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL).replace('big', 'tiny')
                                    };

                                } else if (typeof results[i].featuredImageRelativeURL != 'undefined') {
                                    // add featured image to results
                                    results[i].featured_img = null;
                                }

                                // check if user has a profile picture
                                if (results[i].profilePictureSmallURL) {
                                    // add user to results
                                    results[i].user = {
                                        id: results[i].userID,
                                        name: results[i].lastName + ' ' + results[i].firstName,
                                        image: {
                                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                        }
                                    };

                                } else {
                                    // add user to results
                                    results[i].user = {
                                        id: results[i].userID,
                                        name: results[i].lastName + ' ' + results[i].firstName,
                                        image: null
                                    };
                                }

                                // remove keys
                                delete results[i].featuredImageRelativeURL;
                                delete results[i].userID;
                                delete results[i].firstName;
                                delete results[i].lastName;
                                delete results[i].profilePictureSmallURL;
                                delete results[i].profilePictureMediumURL;
                                delete results[i].profilePictureBigURL;
                            }

                            // send result to client
                            res.status(200);
                            res.json({
                                stores: results,
                                metadata: {
                                    result_set: {
                                        count: results.length,
                                        offset: offset,
                                        limit: limit,
                                        total: count_results[0].total
                                    }
                                }
                            });

                            return;

                        }).catch(err => {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;
                        });

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                } else { // no user's information
                    let select_query = 'SELECT storeID AS id, ';
                    let select_post = [];
                    let count_query = `SELECT COUNT(*) AS total FROM ${store_table_name} `;
                    let count_post = [];

                    req_fields.forEach(elem => {
                        if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                            if (permitted_field_count == 0) {
                                select_query += `${mappped_field_name.get(elem)}`;

                            } else {
                                select_query += `, ${mappped_field_name.get(elem)}`;
                            }

                            field_already_exist.push(elem);
                            permitted_field_count++; // increment by one
                        }
                    });

                    select_query += ` FROM ${store_table_name} `;

                    let counter = 0; // count numbers of search keyword

                    if (category_id) {
                        select_query += 'WHERE categoryID = ? ';
                        select_post.push(category_id);

                        // count query
                        count_query += 'WHERE categoryID = ? ';
                        count_post.push(category_id);

                        counter++;
                    }

                    // search table by user's store name
                    if (store_name) {
                        const search_name_hash = crypto.createHash("sha1").update(store_name, "binary").digest("hex");

                        if (counter > 0) {
                            select_query += 'AND searchStoreHash = ? ';
                            select_post.push(search_name_hash);

                            // count query
                            count_query += 'AND searchStoreHash = ? ';
                            count_post.push(search_name_hash);

                        } else {
                            select_query += 'WHERE searchStoreHash = ? ';
                            select_post.push(search_name_hash);

                            // count query
                            count_query += 'WHERE searchStoreHash = ? ';
                            count_post.push(search_name_hash);
                        }

                        counter++;
                    }

                    if (location_id) {
                        if (counter > 0) {
                            select_query += 'AND locationID = ? ';
                            select_post.push(location_id);

                            // count query
                            count_query += 'AND locationID = ? ';
                            count_post.push(location_id);

                        } else {
                            select_query += 'WHERE locationID = ? ';
                            select_post.push(location_id);

                            // count query
                            count_query += 'WHERE locationID = ? ';
                            count_post.push(location_id);
                        }

                        counter++;
                    }

                    // last should come first
                    select_query += 'ORDER BY time DESC ';

                    // set limit and offset
                    select_query += `LIMIT ${limit} OFFSET ${offset}`;

                    // get metadata for user's publication
                    gDB.query(count_query, count_post).then(count_results => {
                        // get publication
                        gDB.query(select_query, select_post).then(results => {
                            for (let i = 0; i < results.length; i++) {
                                // check if this store has featured image
                                if (results[i].featuredImageRelativeURL) {
                                    // add featured image to results
                                    results[i].featured_img = {
                                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL,
                                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL).replace('big', 'medium'),
                                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL).replace('big', 'small'),
                                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featuredImageRelativeURL).replace('big', 'tiny')
                                    };

                                } else if (typeof results[i].featuredImageRelativeURL != 'undefined') {
                                    // add featured image to results
                                    results[i].featured_img = null;
                                }

                                // remove keys
                                delete results[i].featuredImageRelativeURL;
                            }

                            // send result to client
                            res.status(200);
                            res.json({
                                stores: results,
                                metadata: {
                                    result_set: {
                                        count: results.length,
                                        offset: offset,
                                        limit: limit,
                                        total: count_results[0].total
                                    }
                                }
                            });

                            return;

                        }).catch(err => {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;
                        });

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                }

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }
});

// get a store information
router.get('/stores/:store_id', custom_utils.allowedScopes(['read:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // pass in queries
    let store_type = req.query.type;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    let store_table_name;

    // check store type
    if (store_type == 'product') {
        store_table_name = 'stores';

    } else {
        store_table_name = 'services';
    }

    let req_fields = null;

    if (req.query.fields) {
        req_fields = custom_utils.filterInArray(
            req.query.fields.split(','),
            ['user', 'location', 'category', 'name', 'featuredImage', 'description', 'address', 'email', 'phoneNumber', 'time']
        );
    }

    const mappped_field_name = new Map([
        ['location', 'locationID AS location_id'],
        ['category', 'categoryID AS category_id'],
        ['name', 'storeName AS name'],
        ['featuredImage', 'featuredImageRelativeURL'],
        ['description', 'description'],
        ['address', 'contactAddress AS address'],
        ['email', 'contactEmail AS email'],
        ['phoneNumber', 'contactPhoneNumber AS phone_number'],
        ['time', 'time']
    ]);

    let field_already_exist = [];
    let permitted_field_count = 0;

    // check to retrieve information about the user that add the product
    if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
        let select_query = 'SELECT A.storeID AS id, A.userID';

        if (req_fields || req_fields.length > 0) {
            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `, A.${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, A.${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            select_query +=
                ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                `B.profilePictureBigURL FROM ${store_table_name} AS A LEFT JOIN user AS B ON A.userID = B.userID `;

        } else {
            select_query +=
                ', A.categoryID AS category_id, A.storeName As name, A.featuredImageRelativeURL, A.storeDescription AS description, ' +
                'A.locationID AS location_id, A.contactAddress AS address, A.contactEmail AS email, A.contactPhoneNumber AS phone_number, A.time, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                `B.profilePictureMediumURL, B.profilePictureBigURL FROM ${store_table_name} AS A LEFT JOIN user AS B ON A.userID = B.userID `;
        }

        // where condition
        select_query += 'WHERE A.storeID = ? LIMIT 1';

        // check if store exist and retrieve the data
        gDB.query(select_query, [req.params.store_id]).then(results => {
            // check if store exist
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Store can't be found"
                });

                return;
            }

            // check if this store has featured image
            if (results[0].featuredImageRelativeURL) {
                // add featured image to results
                results[0].featured_img = {
                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL,
                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'medium'),
                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'small'),
                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'tiny')
                };

            } else if (typeof results[0].featuredImageRelativeURL != 'undefined') {
                // add featured image to results
                results[0].featured_img = null;
            }

            // check if user has a profile picture
            if (results[0].profilePictureSmallURL) {
                // add user to results
                results[0].user = {
                    id: results[0].userID,
                    name: results[0].lastName + ' ' + results[0].firstName,
                    image: {
                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureBigURL,
                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureMediumURL,
                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureSmallURL
                    }
                };

            } else {
                // add user to results
                results[0].user = {
                    id: results[0].userID,
                    name: results[0].lastName + ' ' + results[0].firstName,
                    image: null
                };
            }

            // remove keys
            delete results[0].featuredImageRelativeURL;
            delete results[0].userID;
            delete results[0].firstName;
            delete results[0].lastName;
            delete results[0].profilePictureSmallURL;
            delete results[0].profilePictureMediumURL;
            delete results[0].profilePictureBigURL;

            //return result to client
            res.status(200);
            res.json(results[0]);

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    } else { // no user's information
        let select_query = 'SELECT storeID AS id';

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `, ${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, ${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        select_query += ` FROM ${store_table_name} `;

        // where condition
        select_query += 'WHERE storeID = ? LIMIT 1';

        // check if store exist and retrieve the data
        gDB.query(select_query, [req.params.store_id]).then(results => {
            // check if store exist
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Store can't be found"
                });

                return;
            }

            // check if this store has featured image
            if (results[0].featuredImageRelativeURL) {
                // add featured image to results
                results[0].featured_img = {
                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL,
                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'medium'),
                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'small'),
                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featuredImageRelativeURL).replace('big', 'tiny')
                };

            } else if (typeof results[0].featuredImageRelativeURL != 'undefined') {
                // add featured image to results
                results[0].featured_img = null;
            }

            // remove keys
            delete results[0].featuredImageRelativeURL;

            //return result to client
            res.status(200);
            res.json(results[0]);

            return;

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }
});

// update store information
router.put('/stores/:store_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let store_type = req.query.type;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });

    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if user has a store
    gDB.query(
        'SELECT userID FROM ?? WHERE storeID = ? LIMIT 1',
        [
            store_type == 'product' ? 'stores' : 'services',
            req.params.store_id,
        ]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // validate submitted data
        if (req.body.description && typeof req.body.description != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "description",
                message: "description is not acceptable"
            });

        } else if (req.body.description && req.body.description.length > 500) { // check if description exceed 500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "description",
                message: "description exceed maximum allowed text"
            });
        }

        if (req.body.address && typeof req.body.address != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "address",
                message: "address is not acceptable"
            });
        }

        if (req.body.email && !validator.isEmail(req.body.email)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "email",
                message: "email is not acceptable"
            });
        }

        if (req.body.phoneNumber && !/^\d+$/.test(req.body.phoneNumber)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "phoneNumber",
                message: "phoneNumber is not acceptable"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs
            });

            return;
        }

        // prepare the update query
        let query = '';
        let query_post = [];
        let input_count = 0;

        // check the type of store
        if (store_type == 'product') {
            query = 'UPDATE stores SET ';

        } else { // service
            query = 'UPDATE services SET ';
        }

        // check if bio is provided
        if (req.body.description) {
            query += 'description = ?';
            post.push(req.body.description);
            input_count++;
        }

        if (req.body.address) {
            if (input_count < 1) {
                query += 'address = ?';
                query_post.push(req.body.address);

            } else {
                query += ', address = ?';
                query_post.push(req.body.address);
            }

            input_count++;
        }

        if (req.body.email) {
            if (input_count < 1) {
                query += 'email = ?';
                query_post.push(req.body.email);

            } else {
                query += ', email = ?';
                query_post.push(req.body.email);
            }

            input_count++;
        }

        if (req.body.phoneNumber) {
            if (input_count < 1) {
                query += 'phoneNumber = ?';
                query_post.push(req.body.phoneNumber);

            } else {
                query += ', phoneNumber = ?';
                query_post.push(req.body.phoneNumber);
            }

            input_count++;
        }

        // last part of the query
        query += ' WHERE storeID = ? LIMIT 1';
        query_post.push(req.params.store_id);

        // get store type
        gDB.query(query, query_post).then(results => {
            return res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete a store user created
router.delete('/stores/:store_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let store_type = req.query.type;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });

    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    let table_name_1;
    let table_name_2;
    let table_name_3;

    // check the type of store
    if (store_type == 'product') {
        table_name_1 = 'stores';
        table_name_2 = 'product_images';
        table_name_3 = 'products';

    } else { // service
        table_name_1 = 'services';
        table_name_2 = 'work_images';
        table_name_3 = 'works';
    }

    // check if store exist or has been deleted
    gDB.query(
        'SELECT userID, featuredImageRelativeURL FROM ?? WHERE storeID = ? LIMIT 1',
        [table_name_1, req.params.store_id]
    ).then(store_results => {
        if (store_results.length < 1) {
            return res.status(200).send();
        }

        // check if user's store
        if (store_results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // get all the uploaded media content for products or services
        gDB.query(
            'SELECT imageRelativeURL FROM ?? WHERE storeID = ?',
            [table_name_2, req.params.store_id]
        ).then(results => {
            let delete_objs = [];

            // add store featured image to the list
            if (store_results[0].featuredImageRelativeURL) delete_objs.push(store_results[0].featuredImageRelativeURL);

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].imageRelativeURL });
            }

            // check if there is object to delete
            if (delete_objs.length > 0) {
                // set aws s3 access credentials
                aws.config.update({
                    apiVersion: '2006-03-01',
                    accessKeyId: gConfig.AWS_ACCESS_ID,
                    secretAccessKey: gConfig.AWS_SECRET_KEY,
                    region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                });

                const s3 = new aws.S3();

                // initialise objects to delete
                const deleteParam = {
                    Bucket: gConfig.AWS_S3_BUCKET_NAME,
                    Delete: {
                        Objects: delete_objs
                    }
                };

                s3.deleteObjects(deleteParam, (err, data) => {
                    if (err) {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    }

                    // delete store and all the related contents
                    gDB.transaction(
                        {
                            query: 'DELETE FROM ?? WHERE storeID = ? LIMIT 1',
                            post: [
                                table_name_1,
                                req.params.store_id
                            ]
                        },
                        {
                            query: 'DELETE FROM ?? WHERE storeID = ?',
                            post: [
                                table_name_3,
                                req.params.user_id
                            ]
                        },
                        {
                            query: 'DELETE FROM ?? WHERE storeID = ?',
                            post: [
                                table_name_2,
                                req.params.user_id
                            ]
                        }
                    ).then(results => {
                        return res.status(200).send();

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });
                });

            } else {
                // delete store and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM ?? WHERE storeID = ? LIMIT 1',
                        post: [
                            table_name_1,
                            req.params.store_id
                        ]
                    },
                    {
                        query: 'DELETE FROM ?? WHERE storeID = ?',
                        post: [
                            table_name_3,
                            req.params.user_id
                        ]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// upload featured image for store
router.post('/stores/:store_id/upload/featuredImage', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let store_type = req.query.type;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    let table_name = store_type == 'product' ? 'stores' : 'services';

    // check if user has created a store
    gDB.query(
        'SELECT userID FROM ?? WHERE storeID = ? LIMIT 1',
        [table_name, req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        upload(req, res, (err) => {
            // check if enctype is multipart form data
            if (!req.is('multipart/form-data')) {
                res.status(415);
                res.json({
                    error_code: "invalid_request_body",
                    message: "Encode type not supported"
                });

                return;
            }

            // check if file contain data
            if (!req.file) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "Bad request"
                });

                return;
            }

            // A Multer error occurred when uploading
            if (err instanceof multer.MulterError) {
                if (err.code == 'LIMIT_FILE_SIZE') {
                    res.status(400);
                    res.json({
                        error_code: "size_exceeded",
                        message: "Image your uploading exceeded allowed size"
                    });

                    return;
                }

                // other multer errors
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;

            } else if (err) { // An unknown error occurred when uploading
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            let file_path = req.file.path; // uploaded file location
            const save_image_ext = 'png';

            // read uploaded image as buffer
            let image_buffer = fs.readFileSync(file_path);

            // check file type and if is supported
            let supported_images = [
                'jpg',
                'png',
                'gif',
                'jp2'
            ];

            // read minimum byte from buffer required to determine file mime
            let file_mime = file_type(Buffer.from(image_buffer, 0, file_type.minimumBytes));

            if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                // delete the uploaded file
                fs.unlinkSync(file_path);

                res.status(406);
                res.json({
                    error_code: "unsupported_format",
                    message: "Uploaded image is not supported"
                });

                return;
            }

            // resize the image if it exceeded the maximum resolution
            sharp(image_buffer)
                .resize({
                    height: 1080, // resize image using the set height
                    withoutEnlargement: true
                })
                .toFormat(save_image_ext)
                .toBuffer()
                .then(outputBuffer => {
                    // no higher than 1080 pixels
                    // and no larger than the input image

                    // upload buffer to aws s3 bucket
                    // set aws s3 access credentials
                    aws.config.update({
                        apiVersion: '2006-03-01',
                        accessKeyId: gConfig.AWS_ACCESS_ID,
                        secretAccessKey: gConfig.AWS_SECRET_KEY,
                        region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                    });

                    const s3 = new aws.S3();

                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    const uploadImage = () => {
                        const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;
                        let dir_name;

                        // check store type
                        if (store_type == 'production') {
                            dir_name = 'store';

                        } else { // service
                            dir_name = 'service';
                        }

                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: outputBuffer,
                            Key: dir_name + '/images/big/' + object_unique_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, (err, data) => {
                            if (err) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            }

                            if (data) { // file uploaded successfully
                                let img_path = dir_name + '/images/big/' + object_unique_name;

                                // save file location to database
                                gDB.query(
                                    'UPDATE ?? SET featuredImageRelativeURL = ? WHERE storeID = ? LIMIT 1',
                                    [
                                        table_name,
                                        img_path,
                                        req.params.store_id
                                    ]
                                ).then(results => {
                                    // send result to client
                                    res.status(201);
                                    res.json({
                                        image: {
                                            big: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/big/${object_unique_name}`,
                                            medium: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/medium/${object_unique_name}`,
                                            small: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/small/${object_unique_name}`,
                                            tiny: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/tiny/${object_unique_name}`
                                        }
                                    });

                                }).catch(err => {
                                    res.status(500);
                                    res.json({
                                        error_code: "internal_error",
                                        message: "Internal error"
                                    });

                                    // log the error to log file
                                    gLogger.log('error', err.message, {
                                        stack: err.stack
                                    });

                                    return;
                                });
                            }
                        });
                    };

                    // check if featured image has been uploaded before
                    gDB.query(
                        'SELECT featuredImageRelativeURL FROM ?? WHERE storeID = ? LIMIT 1',
                        [table_name, req.params.store_id]
                    ).then(results => {
                        if (results[0].featuredImageRelativeURL) {
                            // delete the previous uploaded image
                            const deleteParam = {
                                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                                Delete: {
                                    Objects: [{ Key: results[0].featuredImageRelativeURL }]
                                }
                            };

                            s3.deleteObjects(deleteParam, (err, data) => {
                                if (err) {
                                    res.status(500);
                                    res.json({
                                        error_code: "internal_error",
                                        message: "Internal error"
                                    });

                                    // log the error to log file
                                    gLogger.log('error', err.message, {
                                        stack: err.stack
                                    });

                                    return;

                                } else {
                                    uploadImage();
                                }
                            });

                        } else { // no upload
                            uploadImage();
                        }

                    }).catch(err => {
                        // delete the uploaded file
                        fs.unlinkSync(file_path);

                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete uploaded featured image for store
router.delete('/stores/:store_id/upload/featuredImage', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let store_type = req.query.type;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    let table_name = store_type == 'product' ? 'stores' : 'services';

    // check if store exist
    gDB.query(
        'SELECT userID, featuredImageRelativeURL FROM ?? WHERE storeID = ? LIMIT 1',
        [table_name, req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if image exist
        if (!results[0].featuredImageRelativeURL) {
            return res.status(200).send();
        }

        // set aws s3 access credentials
        aws.config.update({
            apiVersion: '2006-03-01',
            accessKeyId: gConfig.AWS_ACCESS_ID,
            secretAccessKey: gConfig.AWS_SECRET_KEY,
            region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
        });

        const s3 = new aws.S3();

        // initialise objects to delete
        const deleteParam = {
            Bucket: gConfig.AWS_S3_BUCKET_NAME,
            Delete: {
                Objects: [{ Key: results[0].featuredImageRelativeURL }]
            }
        };

        s3.deleteObjects(deleteParam, (err, data) => {
            if (err) {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // delete store featured image
            gDB.query(
                'UPDATE ?? SET featuredImageRelativeURL = ? WHERE storeID = ? LIMIT 1',
                [table_name, '', req.params.store_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// add product to store
router.post('/stores/:store_id/products', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist
    gDB.query(
        'SELECT userID, locationID, categoryID, slotCount, usedSlotCount FROM stores WHERE storeID = ? LIMIT 1',
        [user_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if user still have slot for new product
        if ((results[0].slotCount - results[0].usedSlotCount) < 1) {
            res.status(402);
            res.json({
                error_code: "slot_exhausted",
                message: "Slot for product has been exhausted"
            });

            return;
        }

        uploads(req, res, (err) => {
            // check if enctype is multipart form data
            if (!req.is('multipart/form-data')) {
                res.status(415);
                res.json({
                    error_code: "invalid_request_body",
                    message: "Encode type not supported"
                });

                return;
            }

            // check if files contain data
            if (!req.files) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "At least, one image must be provided"
                });

                return;
            }

            // A Multer error occurred when uploading
            if (err instanceof multer.MulterError) {
                if (err.code == 'LIMIT_FILE_SIZE') {
                    res.status(400);
                    res.json({
                        error_code: "size_exceeded",
                        message: "Image your uploading exceeded allowed size"
                    });

                    return;
                }

                if (err.code == 'LIMIT_FILE_COUNT') {
                    res.status(400);
                    res.json({
                        error_code: "file_count_exceeded",
                        message: "Allowed number of image exceeded"
                    });

                    return;
                }

                // other multer errors
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;

            } else if (err) { // An unknown error occurred when uploading
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // validate submitted data
            const invalid_inputs = [];

            if (!req.body.name) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "name",
                    message: "name has to be defined"
                });

            } else if (!/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.name)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "name",
                    message: "name is not acceptable"
                });
            }

            if (!req.body.description) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "description",
                    message: "description has to be defined"
                });

            } else if (typeof req.body.description != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "description",
                    message: "description is not acceptable"
                });

            } else if (req.body.description.length > 1500) { // check if description exceed 1500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "description",
                    message: "description exceed maximum allowed text"
                });
            }

            if (!req.body.price) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "price",
                    message: "price has to be defined"
                });

            } else if (!/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "price",
                    message: "price format is not acceptable"
                });
            }

            if (!req.body.negotiable) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "negotiable",
                    message: "negotiable has to be defined"
                });

            } else if (!/^[0-1]$/.test(req.body.negotiable)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "negotiable",
                    message: "negotiable value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            const image_buffers = [];
            const img_paths = [];
            let file_mime;
            let img_format_not_supported = false;
            let supported_images = [
                'jpg',
                'png',
                'gif',
                'jp2'
            ];
            const save_image_ext = 'png';

            // read all the uploaded image and add them to buffer
            for (let i = 0; i < req.files.length; i++) {
                // add to array
                image_buffers.push(fs.readFileSync(req.files[i].path));

                // image path
                img_paths.push(req.files[i].path);

                if (!img_format_not_supported) {
                    // read minimum byte from buffer required to determine file mime
                    file_mime = file_type(Buffer.from(image_buffers[i], 0, file_type.minimumBytes));

                    if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                        img_format_not_supported = true;
                    }
                }
            }

            // delete all the uploaded image
            for (let j = 0; j < img_paths.length; j++) {
                fs.unlinkSync(img_paths[j]); // delete the uploaded file
            }

            // check if any image is not supported
            if (img_format_not_supported) {
                res.status(406);
                res.json({
                    error_code: "unsupported_format",
                    message: "Uploaded image(s) is not supported"
                });

                return;
            }

            // resize uploaded image(s)
            const resize = imgBuffer => {
                return new Promise((resolve, rejected) => {
                    sharp(imgBuffer)
                        .resize({
                            height: 1080, // resize image using the set height
                            withoutEnlargement: true
                        })
                        .toFormat(save_image_ext)
                        .toBuffer()
                        .then(buffer => {
                            // resolve the promise
                            resolve(buffer);
                        })
                        .catch(err => {
                            rejected(err);
                        });
                });
            };

            Promise.all(image_buffers.map(resize)).then(buffers => {
                // save the resized image(s) to aws s3 bucket
                // upload each file
                const uploadImage = pass_buffer => {
                    return new Promise((resolve, rejected) => {
                        const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;

                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: pass_buffer,
                            Key: 'store/images/big/' + object_unique_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, (err, data) => {
                            if (err) {
                                rejected(err);

                            } else {
                                resolve(data); // file uploaded successfully
                            }
                        });
                    });
                };

                Promise.all(buffers.map(uploadImage)).then(datas => {
                    const product_id = rand_token.generate(32); // generate 32 digit unique id
                    const insert_values = [];

                    for (let i = 0; i < datas.length; i++) {
                        insert_values.push([
                            req.params.store_id,
                            product_id,
                            url_parse(datas[i].Location, true).pathname.replace('/', '')
                        ]);
                    }

                    //store product and images to database
                    gDB.transaction(
                        {
                            query: 'UPDATE stores SET usedSlotCount = ? WHERE storeID = ? LIMIT 1',
                            post: [
                                results[0].usedSlotCount + 1,
                                req.params.store_id
                            ]
                        },
                        {
                            query: 'INSERT INTO products (productID, storeID, userID, locationID, categoryID, productName, coverImageRelativeURL, ' +
                                'productDescription, priceNegotiable, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            post: [
                                product_id,
                                req.params.store_id,
                                user_id,
                                results[0].locationID,
                                results[0].categoryID,
                                req.body.name,
                                url_parse(datas[0].Location, true).pathname.replace('/', ''),
                                req.body.description,
                                req.body.negotiable,
                                req.body.price
                            ]
                        },
                        {
                            query: 'INSERT INTO product_images (storeID, productID, imageRelativeURL) VALUES ?',
                            post: [insert_values]
                        }
                    ).then(results => {
                        res.status(201);
                        res.json({
                            product_id: product_id
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get list of product in a store
router.get('/stores/:store_id/products', custom_utils.allowedScopes(['read:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    let search_product = req.query.search;
    const invalid_inputs = [];

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if store exist
    gDB.query('SELECT 1 FROM stores WHERE storeID = ? LIMIT 1', [req.params.store_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        if (pass_limit && pass_limit < limit) {
            limit = pass_limit;
        }

        if (pass_offset) {
            offset = pass_offset;
        }

        const mappped_field_name = new Map([
            ['name', 'productName AS name'],
            ['coverImage', 'coverImageRelativeURL'],
            ['price', 'price'],
            ['time', 'time']
        ]);
        let select_query = 'SELECT productID AS id, ';
        let select_post = [];
        let count_query = 'SELECT COUNT(*) AS total FROM products ';
        let count_post = [];

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                select_query = 'SELECT productID AS id, productName AS name, coverImageRelativeURL, price, time FROM products ';

            } else {
                select_query += ' FROM products ';
            }

        } else { // no fields selection
            select_query += ', productName AS name, coverImageRelativeURL, price, time FROM products ';
        }

        // fetch only from this store
        select_query += 'WHERE storeID = ? ';
        select_post.push(req.params.store_id);

        // count query
        count_query += 'WHERE storeID = ? ';
        count_post.push(req.params.store_id);

        // search database for match
        if (search_product) {
            search_product = decodeURIComponent(search_product);
            select_query += 'AND MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
            select_post.push(search_product);

            // count query
            count_query += 'AND MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
            count_post.push(search_product);

        } else {
            // last should come first
            select_query += 'ORDER BY time DESC ';
        }

        // set limit and offset
        select_query += `LIMIT ${limit} OFFSET ${offset}`;

        // get metadata for user's publication
        gDB.query(count_query, count_post).then(count_results => {
            // get publication
            gDB.query(select_query, select_post).then(results => {
                for (let i = 0; i < results.length; i++) {
                    // check if this store has featured image
                    if (results[i].coverImageRelativeURL) {
                        // add featured image to results
                        results[i].cover_img = {
                            big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL,
                            medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'medium'),
                            small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'small'),
                            tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'tiny')
                        };

                    } else if (typeof results[i].coverImageRelativeURL != 'undefined') {
                        // add featured image to results
                        results[i].cover_img = null;
                    }

                    // remove keys
                    delete results[i].coverImageRelativeURL;
                }

                // send result to client
                res.status(200);
                res.json({
                    products: results,
                    metadata: {
                        result_set: {
                            count: results.length,
                            offset: offset,
                            limit: limit,
                            total: count_results[0].total
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get a product in a store
router.get('/stores/:store_id/products/:product_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if store id is integer and product id is valid
    if (!(/^\d+$/.test(req.params.store_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.product_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if store exist
    gDB.query('SELECT 1 FROM stores WHERE storeID = ? LIMIT 1', [req.params.store_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        const mappped_field_name = new Map([
            ['name', 'productName AS name'],
            ['description', 'productDescription AS description'],
            ['negotiable', 'priceNegotiable AS negotiable'],
            ['price', 'price'],
            ['time', 'time']
        ]);
        let select_query = 'SELECT ';
        let req_fields = null;
        let permitted_field_count = 0;
        let select_only_image = false;

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            req_fields = req.query.fields.split(',');
            let field_already_exist = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1 && req_fields.find(f => f == 'images')) {
                select_query = 'SELECT productID FROM products ';
                select_only_image = true;

            } else if (permitted_field_count < 1) {
                select_query = 'SELECT productName AS name, productDescription AS description, ' +
                    'price, priceNegotiable AS negotiable, time FROM products ';

            } else {
                select_query += ' FROM products ';
            }

        } else { // no fields selection
            select_query += 'productName AS name, productDescription AS description, ' +
                'price, priceNegotiable AS negotiable, time FROM products ';
        }

        // where condition
        select_query += 'WHERE storeID = ? AND productID = ? LIMIT 1';

        // check if product exist and retrieve
        gDB.query(select_query, [req.params.store_id, req.params.product_id]).then(product_results => {
            // check if product exist
            if (product_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Product can't be found"
                });

                return;
            }

            // check to fetch only picture(s) for product
            if (select_only_image) {
                // delete productID
                delete product_results[0].productID;

            } else if (req_fields && !req_fields.find(f => f == 'images')) {
                // fetch only product no picture
                // send result to client
                res.status(200);
                res.json(product_results[0]);

                return;
            }

            // get picture(s) for product
            gDB.query(
                'SELECT imageRelativeURL FROM product_images WHERE productID = ?',
                [req.params.product_id]
            ).then(results => {
                let product_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    product_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                product_results[0].images = product_images;

                // send result to client
                res.status(200);
                res.json(product_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// add service (work) to store
router.post('/stores/:store_id/services', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist
    gDB.query(
        'SELECT userID, locationID, categoryID, slotCount, usedSlotCount FROM services WHERE storeID = ? LIMIT 1',
        [user_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if user still have slot for new product
        if ((results[0].slotCount - results[0].usedSlotCount) < 1) {
            res.status(402);
            res.json({
                error_code: "slot_exhausted",
                message: "Slot for product has been exhausted"
            });

            return;
        }

        uploads(req, res, (err) => {
            // check if enctype is multipart form data
            if (!req.is('multipart/form-data')) {
                res.status(415);
                res.json({
                    error_code: "invalid_request_body",
                    message: "Encode type not supported"
                });

                return;
            }

            // check if files contain data
            if (!req.files) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "At least, one image must be provided"
                });

                return;
            }

            // A Multer error occurred when uploading
            if (err instanceof multer.MulterError) {
                if (err.code == 'LIMIT_FILE_SIZE') {
                    res.status(400);
                    res.json({
                        error_code: "size_exceeded",
                        message: "Image your uploading exceeded allowed size"
                    });

                    return;
                }

                if (err.code == 'LIMIT_FILE_COUNT') {
                    res.status(400);
                    res.json({
                        error_code: "file_count_exceeded",
                        message: "Allowed number of image exceeded"
                    });

                    return;
                }

                // other multer errors
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;

            } else if (err) { // An unknown error occurred when uploading
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // validate submitted data
            const invalid_inputs = [];

            if (!req.body.name) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "name",
                    message: "name has to be defined"
                });

            } else if (!/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.name)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "name",
                    message: "name is not acceptable"
                });
            }

            if (!req.body.description) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "description",
                    message: "description has to be defined"
                });

            } else if (typeof req.body.description != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "description",
                    message: "description is not acceptable"
                });

            } else if (req.body.description.length > 1500) { // check if description exceed 1500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "description",
                    message: "description exceed maximum allowed text"
                });
            }

            if (!req.body.price) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "price",
                    message: "price has to be defined"
                });

            } else if (!/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "price",
                    message: "price format is not acceptable"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            const image_buffers = [];
            const img_paths = [];
            let file_mime;
            let img_format_not_supported = false;
            let supported_images = [
                'jpg',
                'png',
                'gif',
                'jp2'
            ];
            const save_image_ext = 'png';

            // read all the uploaded image and add them to buffer
            for (let i = 0; i < req.files.length; i++) {
                // add to array
                image_buffers.push(fs.readFileSync(req.files[i].path));

                // image path
                img_paths.push(req.files[i].path);

                if (!img_format_not_supported) {
                    // read minimum byte from buffer required to determine file mime
                    file_mime = file_type(Buffer.from(image_buffers[i], 0, file_type.minimumBytes));

                    if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                        img_format_not_supported = true;
                    }
                }
            }

            // delete all the uploaded image
            for (let j = 0; j < img_paths.length; j++) {
                fs.unlinkSync(img_paths[j]); // delete the uploaded file
            }

            // check if any image is not supported
            if (img_format_not_supported) {
                res.status(406);
                res.json({
                    error_code: "unsupported_format",
                    message: "Uploaded image(s) is not supported"
                });

                return;
            }

            // resize uploaded image(s)
            const resize = imgBuffer => {
                return new Promise((resolve, rejected) => {
                    sharp(imgBuffer)
                        .resize({
                            height: 1080, // resize image using the set height
                            withoutEnlargement: true
                        })
                        .toFormat(save_image_ext)
                        .toBuffer()
                        .then(buffer => {
                            // resolve the promise
                            resolve(buffer);
                        })
                        .catch(err => {
                            rejected(err);
                        });
                });
            };

            Promise.all(image_buffers.map(resize)).then(buffers => {
                // save the resized image(s) to aws s3 bucket
                // upload each file
                const uploadImage = pass_buffer => {
                    return new Promise((resolve, rejected) => {
                        const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;

                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: pass_buffer,
                            Key: 'service/images/big/' + object_unique_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, (err, data) => {
                            if (err) {
                                rejected(err);

                            } else {
                                resolve(data); // file uploaded successfully
                            }
                        });
                    });
                };

                Promise.all(buffers.map(uploadImage)).then(datas => {
                    const work_id = rand_token.generate(32); // generate 32 digit unique id
                    const insert_values = [];

                    for (let i = 0; i < datas.length; i++) {
                        insert_values.push([
                            req.params.store_id,
                            work_id,
                            url_parse(datas[i].Location, true).pathname.replace('/', '')
                        ]);
                    }

                    //store product and images to database
                    gDB.transaction(
                        {
                            query: 'UPDATE services SET usedSlotCount = ? WHERE storeID = ? LIMIT 1',
                            post: [
                                results[0].usedSlotCount + 1,
                                req.params.store_id
                            ]
                        },
                        {
                            query: 'INSERT INTO works (workID, storeID, userID, locationID, categoryID, workName, coverImageRelativeURL, ' +
                                'workDescription, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            post: [
                                work_id,
                                req.params.store_id,
                                user_id,
                                results[0].locationID,
                                results[0].categoryID,
                                req.body.name,
                                url_parse(datas[0].Location, true).pathname.replace('/', ''),
                                req.body.description,
                                req.body.price
                            ]
                        },
                        {
                            query: 'INSERT INTO work_images (storeID, workID, imageRelativeURL) VALUES ?',
                            post: [insert_values]
                        }
                    ).then(results => {
                        res.status(201);
                        res.json({
                            service_id: work_id
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get list of service in a store
router.get('/stores/:store_id/services', custom_utils.allowedScopes(['read:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    let search_service = req.query.search;
    const invalid_inputs = [];

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if store exist
    gDB.query('SELECT 1 FROM services WHERE storeID = ? LIMIT 1', [req.params.store_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        if (pass_limit && pass_limit < limit) {
            limit = pass_limit;
        }

        if (pass_offset) {
            offset = pass_offset;
        }

        const mappped_field_name = new Map([
            ['name', 'workName AS name'],
            ['coverImage', 'coverImageRelativeURL'],
            ['price', 'price'],
            ['time', 'time']
        ]);
        let select_query = 'SELECT workID AS id, ';
        let select_post = [];
        let count_query = 'SELECT COUNT(*) AS total FROM works ';
        let count_post = [];

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                select_query = 'SELECT workID AS id, workName AS name, coverImageRelativeURL, price, time FROM works ';

            } else {
                select_query += ' FROM works ';
            }

        } else { // no fields selection
            select_query += ', workName AS name, coverImageRelativeURL, price, time FROM works ';
        }

        // fetch only from this store
        select_query += 'WHERE storeID = ? ';
        select_post.push(req.params.store_id);

        // count query
        count_query += 'WHERE storeID = ? ';
        count_post.push(req.params.store_id);

        // search database for match
        if (search_service) {
            search_service = decodeURIComponent(search_service);
            select_query += 'AND MATCH(workName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
            select_post.push(search_service);

            // count query
            count_query += 'AND MATCH(workName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
            count_post.push(search_service);

        } else {
            // last should come first
            select_query += 'ORDER BY time DESC ';
        }

        // set limit and offset
        select_query += `LIMIT ${limit} OFFSET ${offset}`;

        // get metadata for user's publication
        gDB.query(count_query, count_post).then(count_results => {
            // get publication
            gDB.query(select_query, select_post).then(results => {
                for (let i = 0; i < results.length; i++) {
                    // check if this store has featured image
                    if (results[i].coverImageRelativeURL) {
                        // add featured image to results
                        results[i].cover_img = {
                            big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL,
                            medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'medium'),
                            small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'small'),
                            tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'tiny')
                        };

                    } else if (typeof results[i].coverImageRelativeURL != 'undefined') {
                        // add featured image to results
                        results[i].cover_img = null;
                    }

                    // remove keys
                    delete results[i].coverImageRelativeURL;
                }

                // send result to client
                res.status(200);
                res.json({
                    services: results,
                    metadata: {
                        result_set: {
                            count: results.length,
                            offset: offset,
                            limit: limit,
                            total: count_results[0].total
                        }
                    }
                });

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get a service in a store
router.get('/stores/:store_id/services/:service_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if store id is integer and product id is valid
    if (!(/^\d+$/.test(req.params.store_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.service_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if store exist
    gDB.query('SELECT 1 FROM services WHERE storeID = ? LIMIT 1', [req.params.service_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        const mappped_field_name = new Map([
            ['name', 'workName AS name'],
            ['description', 'workDescription AS description'],
            ['price', 'price'],
            ['time', 'time']
        ]);
        let select_query = 'SELECT ';
        let req_fields = null;
        let permitted_field_count = 0;
        let select_only_image = false;

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            req_fields = req.query.fields.split(',');
            let field_already_exist = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1 && req_fields.find(f => f == 'images')) {
                select_query = 'SELECT workID FROM works ';
                select_only_image = true;

            } else if (permitted_field_count < 1) {
                select_query = 'SELECT workName AS name, workDescription AS description, price, time FROM works ';

            } else {
                select_query += ' FROM works ';
            }

        } else { // no fields selection
            select_query += 'workName AS name, workDescription AS description, price, time FROM works ';
        }

        // where condition
        select_query += 'WHERE storeID = ? AND workID = ? LIMIT 1';

        // check if product exist and retrieve
        gDB.query(select_query, [req.params.store_id, req.params.service_id]).then(service_results => {
            // check if product exist
            if (service_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Service can't be found"
                });

                return;
            }

            // check to fetch only picture(s) for service
            if (select_only_image) {
                // delete workID
                delete service_results[0].workID;

            } else if (req_fields && !req_fields.find(f => f == 'images')) {
                // fetch only service no picture
                // send result to client
                res.status(200);
                res.json(service_results[0]);

                return;
            }

            // get picture(s) for service
            gDB.query(
                'SELECT imageRelativeURL FROM work_images WHERE workID = ?',
                [req.params.service_id]
            ).then(results => {
                let service_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    service_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                service_results[0].images = service_images;

                // send result to client
                res.status(200);
                res.json(service_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// update product data except image
router.put('/stores/:store_id/products/:product_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!(/^\d+$/.test(req.params.store_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.product_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist
    gDB.query(
        'SELECT userID FROM stores WHERE storeID = ? LIMIT 1',
        [req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if product exist
        gDB.query(
            'SELECT 1 FROM products WHERE productID = ? LIMIT 1',
            [req.params.product_id]
        ).then(results => {
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Product can't be found"
                });

                return;
            }

            // validate submitted data
            const invalid_inputs = [];

            if (req.body.name && !/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.name)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "name",
                    message: "name is not acceptable"
                });
            }

            if (req.body.description && typeof req.body.description != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "description",
                    message: "description is not acceptable"
                });

            } else if (req.body.description && req.body.description.length > 1500) { // check if description exceed 1500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "description",
                    message: "description exceed maximum allowed text"
                });
            }

            if (req.body.price && !/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "price",
                    message: "price format is not acceptable"
                });
            }

            if (req.body.negotiable && !/^[0-1]$/.test(req.body.negotiable)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "negotiable",
                    message: "negotiable value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            // prepare the update query
            let query = 'UPDATE products SET ';
            let query_post = [];
            let input_count = 0;

            // check if bio is provided
            if (req.body.name) {
                query += 'name = ?';
                query_post.push(req.body.name);
                input_count++;
            }

            if (req.body.description) {
                if (input_count < 1) {
                    query += 'description = ?';
                    query_post.push(req.body.description);

                } else {
                    query += ', description = ?';
                    query_post.push(req.body.description);
                }

                input_count++;
            }

            if (req.body.price) {
                if (input_count < 1) {
                    query += 'price = ?';
                    query_post.push(req.body.price);

                } else {
                    query += ', price = ?';
                    query_post.push(req.body.price);
                }

                input_count++;
            }

            if (req.body.negotiable) {
                if (input_count < 1) {
                    query += 'negotiable = ?';
                    query_post.push(req.body.negotiable);

                } else {
                    query += ', negotiable = ?';
                    query_post.push(req.body.negotiable);
                }

                input_count++;
            }

            // last part of the query
            query += ' WHERE productID = ? LIMIT 1';
            query_post.push(req.params.product_id);

            // get store type
            gDB.query(query, query_post).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// update service (or work) data except image
router.put('/stores/:store_id/services/:service_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!(/^\d+$/.test(req.params.store_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.service_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist
    gDB.query(
        'SELECT userID FROM services WHERE storeID = ? LIMIT 1',
        [req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if service exist
        gDB.query(
            'SELECT 1 FROM works WHERE workID = ? LIMIT 1',
            [req.params.service_id]
        ).then(results => {
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Service can't be found"
                });

                return;
            }

            // validate submitted data
            const invalid_inputs = [];

            if (req.body.name && !/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.name)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "name",
                    message: "name is not acceptable"
                });
            }

            if (req.body.description && typeof req.body.description != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "description",
                    message: "description is not acceptable"
                });

            } else if (req.body.description && req.body.description.length > 1500) { // check if description exceed 1500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "description",
                    message: "description exceed maximum allowed text"
                });
            }

            if (req.body.price && !/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "price",
                    message: "price format is not acceptable"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            // prepare the update query
            let query = 'UPDATE works SET ';
            let query_post = [];
            let input_count = 0;

            // check if bio is provided
            if (req.body.name) {
                query += 'name = ?';
                query_post.push(req.body.name);
                input_count++;
            }

            if (req.body.description) {
                if (input_count < 1) {
                    query += 'description = ?';
                    query_post.push(req.body.description);

                } else {
                    query += ', description = ?';
                    query_post.push(req.body.description);
                }

                input_count++;
            }

            if (req.body.price) {
                if (input_count < 1) {
                    query += 'price = ?';
                    query_post.push(req.body.price);

                } else {
                    query += ', price = ?';
                    query_post.push(req.body.price);
                }

                input_count++;
            }

            // last part of the query
            query += ' WHERE workID = ? LIMIT 1';
            query_post.push(req.params.service_id);

            // get store type
            gDB.query(query, query_post).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete a product in a store
router.delete('/stores/:store_id/products/:product_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if store id is integer and product id is valid
    if (!(/^\d+$/.test(req.params.store_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.product_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist
    gDB.query(
        'SELECT userID FROM stores WHERE storeID = ? LIMIT 1',
        [req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if product exist
        gDB.query(
            'SELECT imageRelativeURL FROM product_images WHERE productID = ?',
            [req.params.product_id]
        ).then(results => {
            if (results.length < 1) {
                return res.status(200).send(); // product has been deleted
            }

            let delete_objs = [];

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].imageRelativeURL });
            }

            // set aws s3 access credentials
            aws.config.update({
                apiVersion: '2006-03-01',
                accessKeyId: gConfig.AWS_ACCESS_ID,
                secretAccessKey: gConfig.AWS_SECRET_KEY,
                region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
            });

            const s3 = new aws.S3();

            // initialise objects to delete
            const deleteParam = {
                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                Delete: {
                    Objects: delete_objs
                }
            };

            s3.deleteObjects(deleteParam, (err, data) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // delete product and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM products WHERE productID = ? LIMIT 1',
                        post: [req.params.product_id]
                    },
                    {
                        query: 'DELETE FROM product_images WHERE productID = ?',
                        post: [req.params.product_id]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete a service (or work sample) in a store
router.delete('/stores/:store_id/services/:service_id', custom_utils.allowedScopes(['write:stores']), (req, res) => {
    // check if id is integer
    if (!(/^\d+$/.test(req.params.store_id) && /^[a-zA-Z0-9]{32}$/.test(req.params.service_id))) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist
    gDB.query(
        'SELECT userID FROM services WHERE storeID = ? LIMIT 1',
        [req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // check if product exist
        gDB.query(
            'SELECT imageRelativeURL FROM work_images WHERE workID = ?',
            [req.params.service_id]
        ).then(results => {
            if (results.length < 1) {
                return res.status(200).send(); // product has been deleted
            }

            let delete_objs = [];

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].imageRelativeURL });
            }

            // set aws s3 access credentials
            aws.config.update({
                apiVersion: '2006-03-01',
                accessKeyId: gConfig.AWS_ACCESS_ID,
                secretAccessKey: gConfig.AWS_SECRET_KEY,
                region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
            });

            const s3 = new aws.S3();

            // initialise objects to delete
            const deleteParam = {
                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                Delete: {
                    Objects: delete_objs
                }
            };

            s3.deleteObjects(deleteParam, (err, data) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // delete work and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM works WHERE workID = ? LIMIT 1',
                        post: [req.params.service_id]
                    },
                    {
                        query: 'DELETE FROM work_images WHERE workID = ?',
                        post: [req.params.service_id]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get used and available slot for product or service
router.get('/stores/:store_id/slot', custom_utils.allowedScopes(['read:stores']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.store_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // pass in queries
    let store_type = req.query.type;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!store_type) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "type",
            message: "type has to be defined"
        });

    } else if (!/^(product|service)$/.test(store_type)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "type",
            message: "type value is invalid"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    let table_name = store_type == 'product' ? 'stores' : 'services';

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if store exist and retrieve necessary information
    gDB.query(
        'SELECT userID, slotCount AS count, usedSlotCount AS used FROM ?? WHERE storeID = ? LIMIT 1',
        [table_name, req.params.store_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Store can't be found"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // delete user ID
        delete results[0].userID;

        // send result to client
        res.status(200);
        res.json(results[0]);

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// post product without actually having a store
router.post('/products', custom_utils.allowedScopes(['write:products']), (req, res) => {
    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let category_id = req.query.categoryID;
    let location_id = req.query.locationID;

    if (!category_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "categoryID",
            message: "categoryID has to be defined"
        });

    } else if (!/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });

    }

    if (!location_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "locationID",
            message: "locationID has to be defined"
        });

    } else if (!/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });

    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if category exist
    gDB.query(
        'SELECT 1 FROM product_categories WHERE categoryID = ? LIMIT 1',
        [store_category_id]
    ).then(results => {
        if (results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "categoryID",
                message: "categoryID value is invalid"
            });
        }

        // check if location ID exist
        gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id]).then(results => {
            if (results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "locationID",
                    message: "locationID value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs
                });

                return;
            }

            uploads(req, res, (err) => {
                // check if enctype is multipart form data
                if (!req.is('multipart/form-data')) {
                    res.status(415);
                    res.json({
                        error_code: "invalid_request_body",
                        message: "Encode type not supported"
                    });

                    return;
                }

                // check if files contain data
                if (!req.files) {
                    res.status(400);
                    res.json({
                        error_code: "invalid_request",
                        message: "At least, one image must be provided"
                    });

                    return;
                }

                // A Multer error occurred when uploading
                if (err instanceof multer.MulterError) {
                    if (err.code == 'LIMIT_FILE_SIZE') {
                        res.status(400);
                        res.json({
                            error_code: "size_exceeded",
                            message: "Image your uploading exceeded allowed size"
                        });

                        return;
                    }

                    if (err.code == 'LIMIT_FILE_COUNT') {
                        res.status(400);
                        res.json({
                            error_code: "file_count_exceeded",
                            message: "Allowed number of image exceeded"
                        });

                        return;
                    }

                    // other multer errors
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;

                } else if (err) { // An unknown error occurred when uploading
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // validate submitted data
                const invalid_inputs = [];

                if (!req.body.name) {
                    invalid_inputs.push({
                        error_code: "undefined_input",
                        field: "name",
                        message: "name has to be defined"
                    });

                } else if (!/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.name)) {
                    invalid_inputs.push({
                        error_code: "invalid_input",
                        field: "name",
                        message: "name is not acceptable"
                    });
                }

                if (!req.body.description) {
                    invalid_inputs.push({
                        error_code: "undefined_input",
                        field: "description",
                        message: "description has to be defined"
                    });

                } else if (typeof req.body.description != 'string') {
                    invalid_inputs.push({
                        error_code: "invalid_input",
                        field: "description",
                        message: "description is not acceptable"
                    });

                } else if (req.body.description.length > 1500) { // check if description exceed 1500 characters
                    invalid_inputs.push({
                        error_code: "invalid_data",
                        field: "description",
                        message: "description exceed maximum allowed text"
                    });
                }

                if (!req.body.price) {
                    invalid_inputs.push({
                        error_code: "undefined_input",
                        field: "price",
                        message: "price has to be defined"
                    });

                } else if (!/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
                    invalid_inputs.push({
                        error_code: "invalid_input",
                        field: "price",
                        message: "price format is not acceptable"
                    });
                }

                if (!req.body.negotiable) {
                    invalid_inputs.push({
                        error_code: "undefined_input",
                        field: "negotiable",
                        message: "negotiable has to be defined"
                    });

                } else if (!/^[0-1]$/.test(req.body.negotiable)) {
                    invalid_inputs.push({
                        error_code: "invalid_input",
                        field: "negotiable",
                        message: "negotiable value is invalid"
                    });
                }

                // contact information
                if (req.body.email && !validator.isEmail(req.body.email)) {
                    invalid_inputs.push({
                        error_code: "invalid_input",
                        field: "email",
                        message: "email is not acceptable"
                    });
                }

                if (!req.body.phoneNumber) {
                    invalid_inputs.push({
                        error_code: "undefined_input",
                        field: "phoneNumber",
                        message: "phoneNumber has to be defined"
                    });

                } else if (!/^\d+$/.test(req.body.phoneNumber)) {
                    invalid_inputs.push({
                        error_code: "invalid_input",
                        field: "phoneNumber",
                        message: "phoneNumber value is invalid"
                    });
                }

                // check if any input is invalid
                if (invalid_inputs.length > 0) {
                    // send json error message to client
                    res.status(406);
                    res.json({
                        error_code: "invalid_field",
                        errors: invalid_inputs
                    });

                    return;
                }

                const image_buffers = [];
                const img_paths = [];
                let file_mime;
                let img_format_not_supported = false;
                let supported_images = [
                    'jpg',
                    'png',
                    'gif',
                    'jp2'
                ];
                const save_image_ext = 'png';

                // read all the uploaded image and add them to buffer
                for (let i = 0; i < req.files.length; i++) {
                    // add to array
                    image_buffers.push(fs.readFileSync(req.files[i].path));

                    // image path
                    img_paths.push(req.files[i].path);

                    if (!img_format_not_supported) {
                        // read minimum byte from buffer required to determine file mime
                        file_mime = file_type(Buffer.from(image_buffers[i], 0, file_type.minimumBytes));

                        if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                            img_format_not_supported = true;
                        }
                    }
                }

                // delete all the uploaded image
                for (let j = 0; j < img_paths.length; j++) {
                    fs.unlinkSync(img_paths[j]); // delete the uploaded file
                }

                // check if any image is not supported
                if (img_format_not_supported) {
                    res.status(406);
                    res.json({
                        error_code: "unsupported_format",
                        message: "Uploaded image(s) is not supported"
                    });

                    return;
                }

                // resize uploaded image(s)
                const resize = imgBuffer => {
                    return new Promise((resolve, rejected) => {
                        sharp(imgBuffer)
                            .resize({
                                height: 1080, // resize image using the set height
                                withoutEnlargement: true
                            })
                            .toFormat(save_image_ext)
                            .toBuffer()
                            .then(buffer => {
                                // resolve the promise
                                resolve(buffer);
                            })
                            .catch(err => {
                                rejected(err);
                            });
                    });
                };

                Promise.all(image_buffers.map(resize)).then(buffers => {
                    // save the resized image(s) to aws s3 bucket
                    // upload each file
                    const uploadImage = pass_buffer => {
                        return new Promise((resolve, rejected) => {
                            const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;

                            const upload_params = {
                                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                                Body: pass_buffer,
                                Key: 'store/images/big/' + object_unique_name,
                                ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                            };

                            s3.upload(upload_params, (err, data) => {
                                if (err) {
                                    rejected(err);

                                } else {
                                    resolve(data); // file uploaded successfully
                                }
                            });
                        });
                    };

                    Promise.all(buffers.map(uploadImage)).then(datas => {
                        const product_id = rand_token.generate(32); // generate 32 digit unique id
                        const insert_values = [];

                        for (let i = 0; i < datas.length; i++) {
                            insert_values.push([
                                -1,
                                product_id,
                                url_parse(datas[i].Location, true).pathname.replace('/', '')
                            ]);
                        }

                        //add product and images to database
                        gDB.transaction(
                            {
                                query: 'INSERT INTO product_contact_info (productID, userID, email, phoneNumber) VALUES (?, ?, ?, ?)',
                                post: [
                                    product_id,
                                    user_id,
                                    req.body.email ? req.body.email : '',
                                    req.body.phoneNumber
                                ]
                            },
                            {
                                query: 'INSERT INTO products (productID, storeID, userID, locationID, categoryID, productName, coverImageRelativeURL, ' +
                                    'productDescription, priceNegotiable, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                                post: [
                                    product_id,
                                    -1,
                                    user_id,
                                    location_id,
                                    category_id,
                                    req.body.name,
                                    url_parse(datas[0].Location, true).pathname.replace('/', ''),
                                    req.body.description,
                                    req.body.negotiable,
                                    req.body.price
                                ]
                            },
                            {
                                query: 'INSERT INTO product_images (storeID, productID, imageRelativeURL) VALUES ?',
                                post: [insert_values]
                            }
                        ).then(results => {
                            res.status(201);
                            res.json({
                                product_id: product_id
                            });

                            return;

                        }).catch(err => {
                            res.status(500);
                            res.json({
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log('error', err.message, {
                                stack: err.stack
                            });

                            return;
                        });

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// update product information
router.put('/products/:product_id', custom_utils.allowedScopes(['write:products']), (req, res) => {
    // check if product id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.product_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if product exist and not a product in store
    gDB.query('SELECT storeID, userID FROM products WHERE productID = ? LIMIT 1', [req.params.product_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Product can't be found"
            });

            return;
        }

        // product in a store
        if (results[0].storeID < 0) {
            res.status(403);
            res.json({
                error_code: "request_forbidden",
                message: "This product can't be updated using this endpoint"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // validate submitted data
        const invalid_inputs = [];

        if (req.body.name && !/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.name)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "name",
                message: "name is not acceptable"
            });
        }

        if (req.body.description && typeof req.body.description != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "description",
                message: "description is not acceptable"
            });

        } else if (req.body.description && req.body.description.length > 1500) { // check if description exceed 1500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "description",
                message: "description exceed maximum allowed text"
            });
        }

        if (req.body.price && !/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "price",
                message: "price format is not acceptable"
            });
        }

        if (req.body.negotiable && !/^[0-1]$/.test(req.body.negotiable)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "negotiable",
                message: "negotiable value is invalid"
            });
        }

        // contact information
        if (req.body.email && !validator.isEmail(req.body.email)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "email",
                message: "email is not acceptable"
            });
        }

        if (!req.body.phoneNumber) {
            invalid_inputs.push({
                error_code: "undefined_input",
                field: "phoneNumber",
                message: "phoneNumber has to be defined"
            });

        } else if (!/^\d+$/.test(req.body.phoneNumber)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "phoneNumber",
                message: "phoneNumber value is invalid"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs
            });

            return;
        }

        // prepare the update query
        let transaction = [];
        let query = 'UPDATE products SET ';
        let query_2 = 'UPDATE product_contact_info SET ';
        let query_post = [];
        let query_post_2 = [];
        let input_count = 0;
        let input_count_2 = 0;

        // check if name is provided
        if (req.body.name) {
            query += 'name = ?';
            query_post.push(req.body.name);
            input_count++;
        }

        if (req.body.description) {
            if (input_count < 1) {
                query += 'description = ?';
                query_post.push(req.body.description);

            } else {
                query += ', description = ?';
                query_post.push(req.body.description);
            }

            input_count++;
        }

        if (req.body.price) {
            if (input_count < 1) {
                query += 'price = ?';
                query_post.push(req.body.price);

            } else {
                query += ', price = ?';
                query_post.push(req.body.price);
            }

            input_count++;
        }

        if (req.body.negotiable) {
            if (input_count < 1) {
                query += 'negotiable = ?';
                query_post.push(req.body.negotiable);

            } else {
                query += ', negotiable = ?';
                query_post.push(req.body.negotiable);
            }

            input_count++;
        }

        if (req.body.email) {
            query_2 += 'email = ?';
            query_post_2.push(req.body.email);
            input_count_2++;
        }

        if (req.body.phoneNumber) {
            if (input_count_2 < 1) {
                query_2 += 'phoneNumber = ?';
                query_post_2.push(req.body.phoneNumber);

            } else {
                query_2 += ', phoneNumber = ?';
                query_post.push(req.body.phoneNumber);
            }

            input_count_2++;
        }

        // check if first table should be updated
        if (query_post.length > 0) {
            // last part of the query
            query += ' WHERE productID = ? LIMIT 1';
            query_post.push(req.params.product_id);

            // add to transaction
            transaction.push({ query: query, post: query_post });
        }

        // check if second table should be updated
        if (query_post_2.length > 0) {
            // last part of the query
            query_2 += ' WHERE productID = ? LIMIT 1';
            query_post_2.push(req.params.product_id);

            // add to transaction
            transaction.push({ query: query_2, post: query_post_2 });
        }

        // update product in store and it contact information
        gDB.transaction(...transaction).then(results => {
            return res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete a product
router.delete('/products/:product_id', custom_utils.allowedScopes(['write:products']), (req, res) => {
    // check if product id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.product_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if product exist and not a product in store
    gDB.query('SELECT storeID, userID FROM products WHERE productID = ? LIMIT 1', [req.params.product_id]).then(results => {
        if (results.length < 1) {
            return res.status(200).send();
        }

        // product in a store
        if (results[0].storeID < 0) {
            res.status(403);
            res.json({
                error_code: "request_forbidden",
                message: "This product can't be deleted using this endpoint"
            });

            return;
        }

        // check if is user's store
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // get image(s) for product
        gDB.query(
            'SELECT imageRelativeURL FROM product_images WHERE productID = ?',
            [req.params.product_id]
        ).then(results => {
            let delete_objs = [];

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].imageRelativeURL });
            }

            // set aws s3 access credentials
            aws.config.update({
                apiVersion: '2006-03-01',
                accessKeyId: gConfig.AWS_ACCESS_ID,
                secretAccessKey: gConfig.AWS_SECRET_KEY,
                region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
            });

            const s3 = new aws.S3();

            // initialise objects to delete
            const deleteParam = {
                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                Delete: {
                    Objects: delete_objs
                }
            };

            s3.deleteObjects(deleteParam, (err, data) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // delete a product and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM product_contact_info WHERE productID = ? LIMIT 1',
                        post: [req.params.product_id]
                    },
                    {
                        query: 'DELETE FROM products WHERE productID = ? LIMIT 1',
                        post: [req.params.product_id]
                    },
                    {
                        query: 'DELETE FROM product_images WHERE productID = ?',
                        post: [req.params.product_id]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get list of product from store and individual
router.get('/products', custom_utils.allowedScopes(['read:products', 'read:stores']), (req, res) => {
    // initialise variables
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    let in_store = req.query.store;
    const location_id = req.query.locationID;
    const category_id = req.query.categoryID;
    const pass_user_id = req.query.userID;
    let search_product = req.query.search;
    const invalid_inputs = [];

    // check if query store is valid
    if (!pass_user_id && in_store && !/^(1|0)$/.test(in_store)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "store",
            message: "store value is invalid"
        });
    }

    // check if query location ID is valid
    if (location_id && !/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if query category ID is valid
    if (category_id && !/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if pass user ID is valid
    if (pass_user_id && !/^\d+$/.test(pass_user_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "userID",
            message: "userID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if region with location ID exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id ? location_id : 0]).then(results => {
        if (location_id && results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if category ID exist
        gDB.query(
            'SELECT 1 FROM product_categories WHERE categoryID = ? LIMIT 1',
            [category_id ? category_id : 0]
        ).then(results => {
            if (category_id && results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "categoryID",
                    message: "categoryID value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs
                });

                return;
            }

            if (pass_limit && pass_limit < limit) {
                limit = pass_limit;
            }

            if (pass_offset) {
                offset = pass_offset;
            }

            let req_fields = null;

            if (req.query.fields) {
                req_fields = custom_utils.filterInArray(
                    req.query.fields.split(','),
                    ['user', 'location', 'category', 'name', 'coverImage', 'price', 'time']
                );
            }

            const mappped_field_name = new Map([
                ['location', 'locationID AS location_id'],
                ['category', 'categoryID AS category_id'],
                ['name', 'storeName AS name'],
                ['coverImage', 'coverImageRelativeURL'],
                ['price', 'price'],
                ['time', 'time']
            ]);

            let permitted_field_count = 0;
            let field_already_exist = [];

            // check to retrieve information about the user that add the product
            if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
                let select_query = 'SELECT A.productID AS id, A.userID, A.storeID AS store_id';
                let select_post = [];
                let count_query = 'SELECT COUNT(*) AS total FROM products ';
                let count_post = [];

                // check if valid and required fields is given
                if (req_fields && req_fields.length > 0) {
                    req_fields.forEach(elem => {
                        if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                            if (permitted_field_count == 0) {
                                select_query += `, A.${mappped_field_name.get(elem)}`;

                            } else {
                                select_query += `, A.${mappped_field_name.get(elem)}`;
                            }

                            field_already_exist.push(elem);
                            permitted_field_count++; // increment by one
                        }
                    });

                    select_query +=
                        ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                        'B.profilePictureBigURL FROM products AS A LEFT JOIN user AS B ON A.userID = B.userID ';

                } else { // no fields selection
                    select_query +=
                        ', A.locationID AS location_id, A.categoryID AS category_id, A.productName As name, ' +
                        'A.coverImageRelativeURL, A.price, A.time, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                        'B.profilePictureBigURL FROM products AS A LEFT JOIN user AS B ON A.userID = B.userID ';
                }

                let counter = 0; // count numbers of search keyword

                // override store's query value
                if (pass_user_id) in_store = 0;

                if (in_store) {
                    if (in_store > 0) {
                        select_query += 'WHERE A.storeID > ? ';
                        select_post.push(-1);

                        // count query
                        count_query += 'WHERE storeID > ? ';
                        count_post.push(-1);

                        counter++;

                    } else {
                        select_query += 'WHERE A.storeID < ? ';
                        select_post.push(0);

                        // count query
                        count_query += 'WHERE storeID < ? ';
                        count_post.push(0);

                        counter++;
                    }
                }

                if (pass_user_id) {
                    if (counter > 0) {
                        select_query += 'AND A.userID = ? ';
                        select_post.push(pass_user_id);

                        // count query
                        count_query += 'AND userID = ? ';
                        count_post.push(pass_user_id);

                    } else {
                        select_query += 'WHERE A.userID = ? ';
                        select_post.push(pass_user_id);

                        // count query
                        count_query += 'WHERE userID = ? ';
                        count_post.push(pass_user_id);
                    }

                    counter++;
                }

                if (category_id) {
                    if (counter > 0) {
                        select_query += 'AND A.categoryID = ? ';
                        select_post.push(category_id);

                        // count query
                        count_query += 'AND categoryID = ? ';
                        count_post.push(category_id);

                    } else {
                        select_query += 'WHERE A.categoryID = ? ';
                        select_post.push(category_id);

                        // count query
                        count_query += 'WHERE categoryID = ? ';
                        count_post.push(category_id);
                    }

                    counter++;
                }

                if (location_id) {
                    if (counter > 0) {
                        select_query += 'AND A.locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'AND locationID = ? ';
                        count_post.push(location_id);

                    } else {
                        select_query += 'WHERE A.locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'WHERE locationID = ? ';
                        count_post.push(location_id);
                    }

                    counter++;
                }

                // search database for match
                if (search_product) {
                    search_product = decodeURIComponent(search_product);

                    if (counter > 0) {
                        select_query += 'AND MATCH(A.productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        select_post.push(search_product);

                        // count query
                        count_query += 'AND MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        count_post.push(search_product);

                    } else {
                        select_query += 'WHERE MATCH(A.productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        select_post.push(search_product);

                        // count query
                        count_query += 'WHERE MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        count_post.push(search_product);

                        counter++
                    }

                } else {
                    // last should come first
                    select_query += 'ORDER BY A.time DESC ';
                }

                // set limit and offset
                select_query += `LIMIT ${limit} OFFSET ${offset}`;

                // get metadata for user's publication
                gDB.query(count_query, count_post).then(count_results => {
                    // get publication
                    gDB.query(select_query, select_post).then(results => {
                        for (let i = 0; i < results.length; i++) {
                            // check to get cover image for products
                            if (results[i].coverImageRelativeURL) {
                                // add featured image to results
                                results[i].cover_img = {
                                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL,
                                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'medium'),
                                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'small'),
                                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'tiny')
                                };
                            }

                            // check if user has a profile picture
                            if (results[i].profilePictureSmallURL) {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: {
                                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                    }
                                };

                            } else {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: null
                                };
                            }

                            // remove keys
                            delete results[i].coverImageRelativeURL;
                            delete results[i].userID;
                            delete results[i].firstName;
                            delete results[i].lastName;
                            delete results[i].profilePictureSmallURL;
                            delete results[i].profilePictureMediumURL;
                            delete results[i].profilePictureBigURL;
                        }

                        // send result to client
                        res.status(200);
                        res.json({
                            products: results,
                            metadata: {
                                result_set: {
                                    count: results.length,
                                    offset: offset,
                                    limit: limit,
                                    total: count_results[0].total
                                }
                            }
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            } else { // no user's information
                let select_query = 'SELECT productID AS id, storeID AS store_id';
                let select_post = [];
                let count_query = 'SELECT COUNT(*) AS total FROM products ';
                let count_post = [];

                req_fields.forEach(elem => {
                    if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                        if (permitted_field_count == 0) {
                            select_query += `, ${mappped_field_name.get(elem)}`;

                        } else {
                            select_query += `, ${mappped_field_name.get(elem)}`;
                        }

                        field_already_exist.push(elem);
                        permitted_field_count++; // increment by one
                    }
                });

                select_query += ' FROM products ';

                let counter = 0; // count numbers of search keyword

                // override store query value
                if (pass_user_id) in_store = 0;

                if (in_store) {
                    if (in_store > 0) {
                        select_query += 'WHERE storeID > ? ';
                        select_post.push(-1);

                        // count query
                        count_query += 'WHERE storeID > ? ';
                        count_post.push(-1);

                        counter++;

                    } else {
                        select_query += 'WHERE storeID < ? ';
                        select_post.push(0);

                        // count query
                        count_query += 'WHERE storeID < ? ';
                        count_post.push(0);

                        counter++;
                    }
                }

                if (pass_user_id) {
                    if (counter > 0) {
                        select_query += 'AND userID = ? ';
                        select_post.push(pass_user_id);

                        // count query
                        count_query += 'AND userID = ? ';
                        count_post.push(pass_user_id);

                    } else {
                        select_query += 'WHERE userID = ? ';
                        select_post.push(pass_user_id);

                        // count query
                        count_query += 'WHERE userID = ? ';
                        count_post.push(pass_user_id);
                    }

                    counter++;
                }

                if (category_id) {
                    if (counter > 0) {
                        select_query += 'AND categoryID = ? ';
                        select_post.push(category_id);

                        // count query
                        count_query += 'AND categoryID = ? ';
                        count_post.push(category_id);

                    } else {
                        select_query += 'WHERE categoryID = ? ';
                        select_post.push(category_id);

                        // count query
                        count_query += 'WHERE categoryID = ? ';
                        count_post.push(category_id);
                    }

                    counter++;
                }

                if (location_id) {
                    if (counter > 0) {
                        select_query += 'AND locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'AND locationID = ? ';
                        count_post.push(location_id);

                    } else {
                        select_query += 'WHERE locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'WHERE locationID = ? ';
                        count_post.push(location_id);
                    }

                    counter++;
                }

                // search database for match
                if (search_product) {
                    search_product = decodeURIComponent(search_product);

                    if (counter > 0) {
                        select_query += 'AND MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        select_post.push(search_product);

                        // count query
                        count_query += 'AND MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        count_post.push(search_product);

                    } else {
                        select_query += 'WHERE MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        select_post.push(search_product);

                        // count query
                        count_query += 'WHERE MATCH(productName) AGAINST(? IN NATURAL LANGUAGE MODE) ';
                        count_post.push(search_product);

                        counter++
                    }

                } else {
                    // last should come first
                    select_query += 'ORDER BY time DESC ';
                }

                // set limit and offset
                select_query += `LIMIT ${limit} OFFSET ${offset}`;

                // get metadata for user's publication
                gDB.query(count_query, count_post).then(count_results => {
                    // get publication
                    gDB.query(select_query, select_post).then(results => {
                        for (let i = 0; i < results.length; i++) {
                            // check to get cover image for products
                            if (results[i].coverImageRelativeURL) {
                                // add featured image to results
                                results[i].cover_img = {
                                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL,
                                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'medium'),
                                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'small'),
                                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'tiny')
                                };
                            }

                            // remove keys
                            delete results[i].coverImageRelativeURL;
                        }

                        // send result to client
                        res.status(200);
                        res.json({
                            products: results,
                            metadata: {
                                result_set: {
                                    count: results.length,
                                    offset: offset,
                                    limit: limit,
                                    total: count_results[0].total
                                }
                            }
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get list of service from all store
router.get('/services', custom_utils.allowedScopes(['read:services', 'read:stores']), (req, res) => {
    // initialise variables
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const location_id = req.query.locationID;
    const category_id = req.query.categoryID;
    const invalid_inputs = [];

    // check if query location ID is valid
    if (location_id && !/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if query category ID is valid
    if (category_id && !/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if region with location ID exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id ? location_id : 0]).then(results => {
        if (location_id && results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if category ID exist
        gDB.query(
            'SELECT 1 FROM service_categories WHERE categoryID = ? LIMIT 1',
            [category_id ? category_id : 0]
        ).then(results => {
            if (category_id && results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "categoryID",
                    message: "categoryID value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs
                });

                return;
            }

            if (pass_limit && pass_limit < limit) {
                limit = pass_limit;
            }

            if (pass_offset) {
                offset = pass_offset;
            }

            let req_fields = null;

            if (req.query.fields) {
                req_fields = custom_utils.filterInArray(
                    req.query.fields.split(','),
                    ['user', 'location', 'category', 'name', 'coverImage', 'price', 'time']
                );
            }

            const mappped_field_name = new Map([
                ['location', 'locationID AS location_id'],
                ['category', 'categoryID AS category_id'],
                ['name', 'workName AS name'],
                ['coverImage', 'coverImageRelativeURL'],
                ['price', 'price'],
                ['time', 'time']
            ]);

            let permitted_field_count = 0;
            let field_already_exist = [];

            // check to retrieve information about the user that add the product
            if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
                let select_query = 'SELECT A.workID AS id, A.userID, A.storeID AS store_id';
                let select_post = [];
                let count_query = 'SELECT COUNT(*) AS total FROM works ';
                let count_post = [];

                // check if valid and required fields is given
                if (req_fields && req_fields.length > 0) {
                    req_fields.forEach(elem => {
                        if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                            if (permitted_field_count == 0) {
                                select_query += `, A.${mappped_field_name.get(elem)}`;

                            } else {
                                select_query += `, A.${mappped_field_name.get(elem)}`;
                            }

                            field_already_exist.push(elem);
                            permitted_field_count++; // increment by one
                        }
                    });

                    select_query +=
                        ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                        'B.profilePictureBigURL FROM works AS A LEFT JOIN user AS B ON A.userID = B.userID ';

                } else { // no fields selection
                    select_query +=
                        ', A.locationID AS location_id, A.categoryID AS category_id, A.workName As name, ' +
                        'A.coverImageRelativeURL, A.price, A.time, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                        'B.profilePictureBigURL FROM works AS A LEFT JOIN user AS B ON A.userID = B.userID ';
                }

                let counter = 0; // count numbers of search keyword

                if (category_id) {
                    select_query += 'WHERE A.categoryID = ? ';
                    select_post.push(category_id);

                    // count query
                    count_query += 'WHERE categoryID = ? ';
                    count_post.push(category_id);

                    counter++;
                }

                if (location_id) {
                    if (counter > 0) {
                        select_query += 'AND A.locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'AND locationID = ? ';
                        count_post.push(location_id);

                    } else {
                        select_query += 'WHERE A.locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'WHERE locationID = ? ';
                        count_post.push(location_id);
                    }

                    counter++;
                }

                // last should come first
                select_query += 'ORDER BY A.time DESC ';

                // set limit and offset
                select_query += `LIMIT ${limit} OFFSET ${offset}`;

                // get metadata for user's publication
                gDB.query(count_query, count_post).then(count_results => {
                    // get publication
                    gDB.query(select_query, select_post).then(results => {
                        for (let i = 0; i < results.length; i++) {
                            // check to get cover image for products
                            if (results[i].coverImageRelativeURL) {
                                // add featured image to results
                                results[i].cover_img = {
                                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL,
                                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'medium'),
                                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'small'),
                                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'tiny')
                                };
                            }

                            // check if user has a profile picture
                            if (results[i].profilePictureSmallURL) {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: {
                                        big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                        medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                        small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                    }
                                };

                            } else {
                                // add user to results
                                results[i].user = {
                                    id: results[i].userID,
                                    name: results[i].lastName + ' ' + results[i].firstName,
                                    image: null
                                };
                            }

                            // remove keys
                            delete results[i].coverImageRelativeURL;
                            delete results[i].userID;
                            delete results[i].firstName;
                            delete results[i].lastName;
                            delete results[i].profilePictureSmallURL;
                            delete results[i].profilePictureMediumURL;
                            delete results[i].profilePictureBigURL;
                        }

                        // send result to client
                        res.status(200);
                        res.json({
                            products: results,
                            metadata: {
                                result_set: {
                                    count: results.length,
                                    offset: offset,
                                    limit: limit,
                                    total: count_results[0].total
                                }
                            }
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            } else { // no user's information
                let select_query = 'SELECT workID AS id, storeID AS store_id';
                let select_post = [];
                let count_query = 'SELECT COUNT(*) AS total FROM works ';
                let count_post = [];

                req_fields.forEach(elem => {
                    if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                        if (permitted_field_count == 0) {
                            select_query += `, ${mappped_field_name.get(elem)}`;

                        } else {
                            select_query += `, ${mappped_field_name.get(elem)}`;
                        }

                        field_already_exist.push(elem);
                        permitted_field_count++; // increment by one
                    }
                });

                select_query += ' FROM works ';

                let counter = 0; // count numbers of search keyword

                if (category_id) {
                    select_query += 'WHERE categoryID = ? ';
                    select_post.push(category_id);

                    // count query
                    count_query += 'WHERE categoryID = ? ';
                    count_post.push(category_id);

                    counter++;
                }

                if (location_id) {
                    if (counter > 0) {
                        select_query += 'AND locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'AND locationID = ? ';
                        count_post.push(location_id);

                    } else {
                        select_query += 'WHERE locationID = ? ';
                        select_post.push(location_id);

                        // count query
                        count_query += 'WHERE locationID = ? ';
                        count_post.push(location_id);
                    }

                    counter++;
                }

                // last should come first
                select_query += 'ORDER BY time DESC ';

                // set limit and offset
                select_query += `LIMIT ${limit} OFFSET ${offset}`;

                // get metadata for user's publication
                gDB.query(count_query, count_post).then(count_results => {
                    // get publication
                    gDB.query(select_query, select_post).then(results => {
                        for (let i = 0; i < results.length; i++) {
                            // check to get cover image for products
                            if (results[i].coverImageRelativeURL) {
                                // add featured image to results
                                results[i].cover_img = {
                                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL,
                                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'medium'),
                                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'small'),
                                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].coverImageRelativeURL).replace('big', 'tiny')
                                };
                            }

                            // remove keys
                            delete results[i].coverImageRelativeURL;
                        }

                        // send result to client
                        res.status(200);
                        res.json({
                            products: results,
                            metadata: {
                                result_set: {
                                    count: results.length,
                                    offset: offset,
                                    limit: limit,
                                    total: count_results[0].total
                                }
                            }
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            }

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get a product
router.get('/products/:product_id', custom_utils.allowedScopes(['read:products', 'read:stores']), (req, res) => {
    // check if product id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.product_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    let req_fields = null;

    if (req.query.fields) {
        req_fields = custom_utils.filterInArray(
            req.query.fields.split(','),
            ['user', 'images', 'location', 'category', 'name', 'description', 'negotiable', 'email', 'phoneNumber', 'price', 'time']
        );
    }

    const mappped_field_name = new Map([
        ['location', 'A.locationID AS location_id'],
        ['category', 'A.categoryID AS category_id'],
        ['name', 'A.productName AS name'],
        ['description', 'A.productDescription AS description'],
        ['negotiable', 'A.priceNegotiable AS negotiable'],
        ['price', 'A.price'],
        ['email', 'C.contactEmail, D.email'],
        ['phoneNumber', 'C.contactPhoneNumber, D.phoneNumber AS phone_number'],
        ['time', 'A.time']
    ]);

    let field_already_exist = [];
    let permitted_field_count = 0;
    let get_contact_info = true;

    // check to retrieve information about the user that add the product
    if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
        let select_query = 'SELECT A.userID, A.storeID AS store_id';
        let get_product_images = false;

        if (req_fields || req_fields.length > 0) {
            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `, ${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            // get seller contact information
            if (req_fields.find(f => (f == 'email' || f == 'phoneNumber'))) {
                select_query += ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL, ' +
                    'FROM products AS A LEFT JOIN user AS B ON A.userID = B.userID LEFT JOIN stores AS C ON A.storeID = C.storeID ' +
                    'LEFT JOIN product_contact_info AS D ON A.productID = D.productID ';

            } else {
                select_query += ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                    'FROM products AS A LEFT JOIN user AS B ON A.userID = B.userID ';

                get_contact_info = false;
            }

            if (req_fields.find(f => f == 'images')) {
                get_product_images = true;
            }

        } else {
            select_query += ', A.locationID AS location_id, A.categoryID AS category_id, ' +
                'A.productName AS name, A.productDescription AS description, A.price, A.priceNegotiable AS negotiable, B.firstName, B.lastName, ' +
                'B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL, C.contactEmail, C.contactPhoneNumber, ' +
                'D.email, D.phoneNumber AS phone_number, A.time FROM products AS A LEFT JOIN user AS B ON A.userID = B.userID LEFT JOIN stores AS C ON A.storeID = C.storeID ' +
                'LEFT JOIN product_contact_info AS D ON A.productID = D.productID ';

            get_product_images = true;
        }

        // where condition
        select_query += 'WHERE productID = ? LIMIT 1';

        // check if product exist and retrieve
        gDB.query(select_query, [req.params.product_id]).then(product_results => {
            // check if product exist
            if (product_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Product can't be found"
                });

                return;
            }

            if (req_fields && !get_product_images) { // fetch only product no picture
                // check to get contact information
                if (get_contact_info) {
                    if (req_fields.find(f => f == 'email')) { // for email
                        if (product_results[0].contactEmail) {
                            product_results[0].email = product_results[0].contactEmail;
                            delete product_results[0].contactEmail; // remove key

                        } else {
                            delete product_results[0].contactEmail; // remove key
                        }
                    }

                    if (req_fields.find(f => f == 'phoneNumber')) { // for phone number
                        if (product_results[0].contactPhoneNumber) {
                            product_results[0].phone_number = product_results[0].contactPhoneNumber;
                            delete product_results[0].contactPhoneNumber; // remove key

                        } else {
                            delete product_results[0].contactPhoneNumber; // remove key
                        }
                    }
                }

                // check if user has a profile picture
                if (product_results[0].profilePictureSmallURL) {
                    // add user to results
                    product_results[0].user = {
                        id: product_results[0].userID,
                        name: product_results[0].lastName + ' ' + product_results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + product_results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + product_results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + product_results[0].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    product_results[0].user = {
                        id: product_results[0].userID,
                        name: product_results[0].lastName + ' ' + product_results[0].firstName,
                        image: null
                    };
                }

                // remove keys
                delete product_results[0].userID;
                delete product_results[0].firstName;
                delete product_results[0].lastName;
                delete product_results[0].profilePictureSmallURL;
                delete product_results[0].profilePictureMediumURL;
                delete product_results[0].profilePictureBigURL;

                // send result to client
                res.status(200);
                res.json(product_results[0]);

                return;
            }

            // get picture(s) for product
            gDB.query(
                'SELECT imageRelativeURL FROM product_images WHERE productID = ?',
                [req.params.product_id]
            ).then(results => {
                let product_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    product_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                product_results[0].images = product_images;

                // check to get contact information
                if (get_contact_info) {
                    if (!req_fields || req_fields.find(f => f == 'email')) { // for email
                        if (product_results[0].contactEmail) {
                            product_results[0].email = product_results[0].contactEmail;
                            delete product_results[0].contactEmail; // remove key

                        } else {
                            delete product_results[0].contactEmail; // remove key
                        }
                    }

                    if (!req_fields || req_fields.find(f => f == 'phoneNumber')) { // for phone number
                        if (product_results[0].contactPhoneNumber) {
                            product_results[0].phone_number = product_results[0].contactPhoneNumber;
                            delete product_results[0].contactPhoneNumber; // remove key

                        } else {
                            delete product_results[0].contactPhoneNumber; // remove key
                        }
                    }
                }

                // check if user has a profile picture
                if (product_results[0].profilePictureSmallURL) {
                    // add user to results
                    product_results[0].user = {
                        id: product_results[0].userID,
                        name: product_results[0].lastName + ' ' + product_results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + product_results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + product_results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + product_results[0].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    product_results[0].user = {
                        id: product_results[0].userID,
                        name: product_results[0].lastName + ' ' + product_results[0].firstName,
                        image: null
                    };
                }

                // remove keys
                delete product_results[0].userID;
                delete product_results[0].firstName;
                delete product_results[0].lastName;
                delete product_results[0].profilePictureSmallURL;
                delete product_results[0].profilePictureMediumURL;
                delete product_results[0].profilePictureBigURL;

                // send result to client
                res.status(200);
                res.json(product_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    } else { // no user's information
        let select_query = 'SELECT A.storeID AS store_id';

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `, ${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, ${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        // get seller contact information
        if (req_fields.find(f => (f == 'email' || f == 'phoneNumber'))) {
            select_query += ' FROM products AS A LEFT JOIN stores AS C ON A.storeID = C.storeID ' +
                'LEFT JOIN product_contact_info AS D ON A.productID = D.productID ';

            get_contact_info = true;

        } else { // don't get seller contact information
            select_query += ' FROM products AS A ';
            get_contact_info = false;
        }

        // where condition
        select_query += 'WHERE A.productID = ? LIMIT 1';

        // check if product exist and retrieve
        gDB.query(select_query, [req.params.product_id]).then(product_results => {
            // check if product exist
            if (product_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Product can't be found"
                });

                return;
            }

            if (!req_fields.find(f => f == 'images')) { // fetch only product no picture
                // check to get contact information
                if (get_contact_info) {
                    if (req_fields.find(f => f == 'email')) { // for email
                        if (product_results[0].contactEmail) {
                            product_results[0].email = product_results[0].contactEmail;
                            delete product_results[0].contactEmail; // remove key

                        } else {
                            delete product_results[0].contactEmail; // remove key
                        }
                    }

                    if (req_fields.find(f => f == 'phoneNumber')) { // for phone number
                        if (product_results[0].contactPhoneNumber) {
                            product_results[0].phone_number = product_results[0].contactPhoneNumber;
                            delete product_results[0].contactPhoneNumber; // remove key

                        } else {
                            delete product_results[0].contactPhoneNumber; // remove key
                        }
                    }
                }

                // send result to client
                res.status(200);
                res.json(product_results[0]);

                return;
            }

            // get picture(s) for product
            gDB.query(
                'SELECT imageRelativeURL FROM product_images WHERE productID = ?',
                [req.params.product_id]
            ).then(results => {
                let product_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    product_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                product_results[0].images = product_images;

                // check to get contact information
                if (get_contact_info) {
                    if (req_fields.find(f => f == 'email')) { // for email
                        if (product_results[0].contactEmail) {
                            product_results[0].email = product_results[0].contactEmail;
                            delete product_results[0].contactEmail; // remove key

                        } else {
                            delete product_results[0].contactEmail; // remove key
                        }
                    }

                    if (req_fields.find(f => f == 'phoneNumber')) { // for phone number
                        if (product_results[0].contactPhoneNumber) {
                            product_results[0].phone_number = product_results[0].contactPhoneNumber;
                            delete product_results[0].contactPhoneNumber; // remove key

                        } else {
                            delete product_results[0].contactPhoneNumber; // remove key
                        }
                    }
                }

                // send result to client
                res.status(200);
                res.json(product_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }
});

// get a service
router.get('/services/:service_id', custom_utils.allowedScopes(['read:services', 'read:stores']), (req, res) => {
    // check if service id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.service_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    let req_fields = null;

    if (req.query.fields) {
        req_fields = custom_utils.filterInArray(
            req.query.fields.split(','),
            ['user', 'images', 'location', 'category', 'name', 'description', 'email', 'phoneNumber', 'price', 'time']
        );
    }

    const mappped_field_name = new Map([
        ['location', 'A.locationID AS location_id'],
        ['category', 'A.categoryID AS category_id'],
        ['name', 'A.workName AS name'],
        ['description', 'A.workDescription AS description'],
        ['price', 'A.price'],
        ['email', 'C.contactEmail AS email'],
        ['phoneNumber', 'C.contactPhoneNumber AS phone_number'],
        ['time', 'A.time']
    ]);

    let field_already_exist = [];
    let permitted_field_count = 0;

    // check to retrieve information about the user that add the product
    if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
        let select_query = 'SELECT A.userID, A.storeID AS store_id';
        let get_service_images = false;

        if (req_fields || req_fields.length > 0) {
            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `, ${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            // get seller contact information
            if (req_fields.find(f => (f == 'email' || f == 'phoneNumber'))) {
                select_query += ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL, ' +
                    'FROM works AS A LEFT JOIN user AS B ON A.userID = B.userID LEFT JOIN services AS C ON A.storeID = C.storeID ';

            } else {
                select_query += ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                    'FROM works AS A LEFT JOIN user AS B ON A.userID = B.userID ';
            }

            if (req_fields.find(f => f == 'images')) {
                get_service_images = true;
            }

        } else {
            select_query += ', A.locationID AS location_id, A.categoryID AS category_id, ' +
                'A.workName AS name, A.workDescription AS description, A.price, B.firstName, B.lastName, ' +
                'B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL, C.contactEmail AS email, C.contactPhoneNumber AS phone_number, ' +
                ' A.time FROM works AS A LEFT JOIN user AS B ON A.userID = B.userID LEFT JOIN services AS C ON A.storeID = C.storeID ';

            get_service_images = true;
        }

        // where condition
        select_query += 'WHERE workID = ? LIMIT 1';

        // check if work exist and retrieve
        gDB.query(select_query, [req.params.service_id]).then(work_results => {
            // check if work exist
            if (work_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Service can't be found"
                });

                return;
            }

            if (req_fields && !get_service_images) { // fetch only work no picture
                // check if user has a profile picture
                if (work_results[0].profilePictureSmallURL) {
                    // add user to results
                    work_results[0].user = {
                        id: work_results[0].userID,
                        name: work_results[0].lastName + ' ' + work_results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + work_results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + work_results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + work_results[0].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    work_results[0].user = {
                        id: work_results[0].userID,
                        name: work_results[0].lastName + ' ' + work_results[0].firstName,
                        image: null
                    };
                }

                // remove keys
                delete work_results[0].userID;
                delete work_results[0].firstName;
                delete work_results[0].lastName;
                delete work_results[0].profilePictureSmallURL;
                delete work_results[0].profilePictureMediumURL;
                delete work_results[0].profilePictureBigURL;

                // send result to client
                res.status(200);
                res.json(work_results[0]);

                return;
            }

            // get picture(s) for work
            gDB.query(
                'SELECT imageRelativeURL FROM work_images WHERE workID = ?',
                [req.params.service_id]
            ).then(results => {
                let work_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    work_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                work_results[0].images = work_images;

                // check if user has a profile picture
                if (work_results[0].profilePictureSmallURL) {
                    // add user to results
                    work_results[0].user = {
                        id: work_results[0].userID,
                        name: work_results[0].lastName + ' ' + work_results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + work_results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + work_results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + work_results[0].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    work_results[0].user = {
                        id: work_results[0].userID,
                        name: work_results[0].lastName + ' ' + work_results[0].firstName,
                        image: null
                    };
                }

                // remove keys
                delete work_results[0].userID;
                delete work_results[0].firstName;
                delete work_results[0].lastName;
                delete work_results[0].profilePictureSmallURL;
                delete work_results[0].profilePictureMediumURL;
                delete work_results[0].profilePictureBigURL;

                // send result to client
                res.status(200);
                res.json(work_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    } else { // no user's information
        let select_query = 'SELECT A.storeID AS store_id';

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `, ${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, ${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        // get seller contact information
        if (req_fields.find(f => (f == 'email' || f == 'phoneNumber'))) {
            select_query += ' FROM works AS A LEFT JOIN services AS C ON A.storeID = C.storeID ';

        } else { // don't get seller contact information
            select_query += ' FROM works AS A ';
        }

        // where condition
        select_query += 'WHERE A.workID = ? LIMIT 1';

        // check if work exist and retrieve
        gDB.query(select_query, [req.params.service_id]).then(work_results => {
            // check if work exist
            if (work_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Service can't be found"
                });

                return;
            }

            if (!req_fields.find(f => f == 'images')) { // fetch only work no picture
                // send result to client
                res.status(200);
                res.json(work_results[0]);

                return;
            }

            // get picture(s) for work
            gDB.query(
                'SELECT imageRelativeURL FROM work_images WHERE workID = ?',
                [req.params.service_id]
            ).then(results => {
                let work_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    work_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                work_results[0].images = work_images;

                // send result to client
                res.status(200);
                res.json(work_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }
});

// add house to realestate for rent or purchase
router.post('/realEstate/houses', custom_utils.allowedScopes(['write:houses']), (req, res) => {
    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // pass in queries
    let purpose = req.query.for;
    let location_id = req.query.locationID;

    if (!purpose) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "for",
            message: "for has to be defined"
        });

    } else if (!/^(rent|buy)$/.test(purpose)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "for",
            message: "for value is invalid"
        });

    }

    if (!location_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "locationID",
            message: "locationID has to be defined"
        });

    } else if (!/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });

    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if location ID exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id]).then(results => {
        if (results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_query",
                errors: invalid_inputs
            });

            return;
        }

        uploads(req, res, (err) => {
            // check if enctype is multipart form data
            if (!req.is('multipart/form-data')) {
                res.status(415);
                res.json({
                    error_code: "invalid_request_body",
                    message: "Encode type not supported"
                });

                return;
            }

            // check if files contain data
            if (!req.files) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "At least, one image must be provided"
                });

                return;
            }

            // A Multer error occurred when uploading
            if (err instanceof multer.MulterError) {
                if (err.code == 'LIMIT_FILE_SIZE') {
                    res.status(400);
                    res.json({
                        error_code: "size_exceeded",
                        message: "Image your uploading exceeded allowed size"
                    });

                    return;
                }

                if (err.code == 'LIMIT_FILE_COUNT') {
                    res.status(400);
                    res.json({
                        error_code: "file_count_exceeded",
                        message: "Allowed number of image exceeded"
                    });

                    return;
                }

                // other multer errors
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;

            } else if (err) { // An unknown error occurred when uploading
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // validate submitted data
            const invalid_inputs = [];

            if (!req.body.description) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "description",
                    message: "description has to be defined"
                });

            } else if (typeof req.body.description != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "description",
                    message: "description is not acceptable"
                });

            } else if (req.body.description.length > 1500) { // check if description exceed 1500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "description",
                    message: "description exceed maximum allowed text"
                });
            }

            if (!req.body.price) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "price",
                    message: "price has to be defined"
                });

            } else if (!/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "price",
                    message: "price format is not acceptable"
                });
            }

            if (!req.body.negotiable) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "negotiable",
                    message: "negotiable has to be defined"
                });

            } else if (!/^[0-1]$/.test(req.body.negotiable)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "negotiable",
                    message: "negotiable value is invalid"
                });
            }

            if (!req.body.address) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "address",
                    message: "address has to be defined"
                });

            } else if (typeof req.body.address != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "address",
                    message: "address is not acceptable"
                });
            }

            // contact information
            if (req.body.email && !validator.isEmail(req.body.email)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "email",
                    message: "email is not acceptable"
                });
            }

            if (!req.body.phoneNumber) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "phoneNumber",
                    message: "phoneNumber has to be defined"
                });

            } else if (!/^\d+$/.test(req.body.phoneNumber)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "phoneNumber",
                    message: "phoneNumber value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            const image_buffers = [];
            const img_paths = [];
            let file_mime;
            let img_format_not_supported = false;
            let supported_images = [
                'jpg',
                'png',
                'gif',
                'jp2'
            ];
            const save_image_ext = 'png';

            // read all the uploaded image and add them to buffer
            for (let i = 0; i < req.files.length; i++) {
                // add to array
                image_buffers.push(fs.readFileSync(req.files[i].path));

                // image path
                img_paths.push(req.files[i].path);

                if (!img_format_not_supported) {
                    // read minimum byte from buffer required to determine file mime
                    file_mime = file_type(Buffer.from(image_buffers[i], 0, file_type.minimumBytes));

                    if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                        img_format_not_supported = true;
                    }
                }
            }

            // delete all the uploaded image
            for (let j = 0; j < img_paths.length; j++) {
                fs.unlinkSync(img_paths[j]); // delete the uploaded file
            }

            // check if any image is not supported
            if (img_format_not_supported) {
                res.status(406);
                res.json({
                    error_code: "unsupported_format",
                    message: "Uploaded image(s) is not supported"
                });

                return;
            }

            // resize uploaded image(s)
            const resize = imgBuffer => {
                return new Promise((resolve, rejected) => {
                    sharp(imgBuffer)
                        .resize({
                            height: 1080, // resize image using the set height
                            withoutEnlargement: true
                        })
                        .toFormat(save_image_ext)
                        .toBuffer()
                        .then(buffer => {
                            // resolve the promise
                            resolve(buffer);
                        })
                        .catch(err => {
                            rejected(err);
                        });
                });
            };

            Promise.all(image_buffers.map(resize)).then(buffers => {
                // save the resized image(s) to aws s3 bucket
                // upload each file
                const uploadImage = pass_buffer => {
                    return new Promise((resolve, rejected) => {
                        const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;

                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: pass_buffer,
                            Key: 'house/images/big/' + object_unique_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, (err, data) => {
                            if (err) {
                                rejected(err);

                            } else {
                                resolve(data); // file uploaded successfully
                            }
                        });
                    });
                };

                Promise.all(buffers.map(uploadImage)).then(datas => {
                    const house_id = rand_token.generate(32); // generate 32 digit unique id
                    const insert_values = [];

                    for (let i = 0; i < datas.length; i++) {
                        insert_values.push([
                            house_id,
                            url_parse(datas[i].Location, true).pathname.replace('/', '')
                        ]);
                    }

                    //add product and images to database
                    gDB.transaction(
                        {
                            query: 'INSERT INTO realestate_houses (houseID, userID, locationID, for, featuredImageRelativeURL, description, price, ' +
                                'negotiable, address, contactEmail, contactPhoneNumber) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            post: [
                                house_id,
                                user_id,
                                location_id,
                                purpose == 'rent' ? 1 : 2,
                                url_parse(datas[0].Location, true).pathname.replace('/', ''),
                                req.body.description,
                                req.body.price,
                                req.body.negotiable,
                                req.body.address,
                                req.body.email,
                                req.body.phoneNumber
                            ]
                        },
                        {
                            query: 'INSERT INTO realestate_house_images (houseID, imageRelativeURL) VALUES ?',
                            post: [insert_values]
                        }
                    ).then(results => {
                        res.status(201);
                        res.json({
                            house_id: house_id
                        });

                        return;

                    }).catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// update the information of the house
router.put('/realEstate/houses/:house_id', custom_utils.allowedScopes(['write:houses']), (req, res) => {
    // check if house id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.house_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if house exist
    gDB.query('SELECT userID FROM realestate_houses WHERE houseID = ? LIMIT 1', [req.params.house_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "House can't be found"
            });

            return;
        }

        // check if is the user
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // validate submitted data
        const invalid_inputs = [];

        if (req.body.description && typeof req.body.description != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "description",
                message: "description is not acceptable"
            });

        } else if (req.body.description && req.body.description.length > 1500) { // check if description exceed 1500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "description",
                message: "description exceed maximum allowed text"
            });
        }

        if (req.body.price && !/^([1-9][0-9]*([.]{1}[0-9]+)?|[0]([.]{1}[0-9]+)?)$/.test(req.body.price)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "price",
                message: "price format is not acceptable"
            });
        }

        if (req.body.negotiable && !/^[0-1]$/.test(req.body.negotiable)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "negotiable",
                message: "negotiable value is invalid"
            });
        }

        if (req.body.address && typeof req.body.address != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "address",
                message: "address is not acceptable"
            });
        }

        // contact information
        if (req.body.email && !validator.isEmail(req.body.email)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "email",
                message: "email is not acceptable"
            });
        }

        if (req.body.phoneNumber && !/^\d+$/.test(req.body.phoneNumber)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "phoneNumber",
                message: "phoneNumber value is invalid"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs
            });

            return;
        }

        // prepare the update query
        let query = 'UPDATE realestate_houses SET ';
        let query_post = [];
        let input_count = 0;

        // check if description is provided
        if (req.body.description) {
            query += 'description = ?';
            post.push(req.body.description);
            input_count++;
        }

        if (req.body.price) {
            if (input_count < 1) {
                query += 'price = ?';
                query_post.push(req.body.price);

            } else {
                query += ', price = ?';
                query_post.push(req.body.price);
            }

            input_count++;
        }

        if (req.body.negotiable) {
            if (input_count < 1) {
                query += 'negotiable = ?';
                query_post.push(req.body.negotiable);

            } else {
                query += ', negotiable = ?';
                query_post.push(req.body.negotiable);
            }

            input_count++;
        }

        if (req.body.address) {
            if (input_count < 1) {
                query += 'address = ?';
                query_post.push(req.body.address);

            } else {
                query += ', address = ?';
                query_post.push(req.body.address);
            }

            input_count++;
        }

        if (req.body.email) {
            if (input_count < 1) {
                query += 'contactEmail = ?';
                query_post.push(req.body.email);

            } else {
                query += ', contactEmail = ?';
                query_post.push(req.body.email);
            }

            input_count++;
        }

        if (req.body.phoneNumber) {
            if (input_count < 1) {
                query += 'contactPhoneNumber = ?';
                query_post.push(req.body.phoneNumber);

            } else {
                query += ', contactPhoneNumber = ?';
                query_post.push(req.body.phoneNumber);
            }

            input_count++;
        }

        // last part of the query
        query += ' WHERE houseID = ? LIMIT 1';
        query_post.push(req.params.house_id);

        // update product in store
        gDB.query(query, query_post).then(results => {
            return res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete added house from the list
router.delete('/realEstate/houses/:house_id', custom_utils.allowedScopes(['write:houses']), (req, res) => {
    // check if house id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.house_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if account is verified
    if (!req.user.account_verified) {
        res.status(401);
        res.json({
            error_code: "account_not_verified",
            message: "User should verify their email"
        });

        return;
    }

    // get user's ID from access token
    const user_id = req.user.access_token.user_id;

    // check if house exist
    gDB.query('SELECT userID FROM realestate_houses WHERE houseID = ? LIMIT 1', [req.params.house_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "House can't be found"
            });

            return;
        }

        // check if is the user
        if (results[0].userID != user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // get image(s) for house
        gDB.query(
            'SELECT imageRelativeURL FROM realestate_house_images WHERE houseID = ?',
            [req.params.house_id]
        ).then(results => {
            let delete_objs = [];

            // add object(s) to delete
            for (let i = 0; i < results.length; i++) {
                delete_objs.push({ Key: results[i].imageRelativeURL });
            }

            // set aws s3 access credentials
            aws.config.update({
                apiVersion: '2006-03-01',
                accessKeyId: gConfig.AWS_ACCESS_ID,
                secretAccessKey: gConfig.AWS_SECRET_KEY,
                region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
            });

            const s3 = new aws.S3();

            // initialise objects to delete
            const deleteParam = {
                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                Delete: {
                    Objects: delete_objs
                }
            };

            s3.deleteObjects(deleteParam, (err, data) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // delete a house and all the related contents
                gDB.transaction(
                    {
                        query: 'DELETE FROM realestate_houses WHERE houseID = ? LIMIT 1',
                        post: [req.params.house_id]
                    },
                    {
                        query: 'DELETE FROM realestate_house_images WHERE houseID = ?',
                        post: [req.params.house_id]
                    }
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get list of house for rent or purchase
router.get('/realEstate/houses', custom_utils.allowedScopes(['read:houses']), (req, res) => {
    // initialise variables
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    let purpose = req.query.for;
    const location_id = req.query.locationID;
    const pass_user_id = req.query.userID;
    const invalid_inputs = [];

    // check if pass user ID is valid
    if (pass_user_id && !/^\d+$/.test(pass_user_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "userID",
            message: "userID value is invalid"
        });
    }

    // check if for is valid
    if (purpose && !/^(rent|buy)$/.test(purpose)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "for",
            message: "for value is invalid"
        });
    }

    // check if query location ID is valid
    if (location_id && !/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if region with location ID exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id ? location_id : 0]).then(results => {
        if (location_id && results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_query",
                errors: invalid_inputs
            });

            return;
        }

        if (pass_limit && pass_limit < limit) {
            limit = pass_limit;
        }

        if (pass_offset) {
            offset = pass_offset;
        }

        let req_fields = null;

        if (req.query.fields) {
            req_fields = custom_utils.filterInArray(
                req.query.fields.split(','),
                ['user', 'location', 'featuredImage', 'description', 'price', 'time']
            );
        }

        const mappped_field_name = new Map([
            ['location', 'locationID AS location_id'],
            ['featuredImage', 'featuredImageRelativeURL AS featured_img'],
            ['description', 'description'],
            ['price', 'price'],
            ['time', 'time']
        ]);

        let permitted_field_count = 0;
        let field_already_exist = [];

        // check to retrieve information about the user that add the house
        if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
            let select_query = 'SELECT A.houseID AS id, A.userID';
            let select_post = [];
            let count_query = 'SELECT COUNT(*) AS total FROM realestate_houses ';
            let count_post = [];

            // check if valid and required fields is given
            if (req_fields && req_fields.length > 0) {
                req_fields.forEach(elem => {
                    if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                        if (permitted_field_count == 0) {
                            select_query += `, A.${mappped_field_name.get(elem)}`;

                        } else {
                            select_query += `, A.${mappped_field_name.get(elem)}`;
                        }

                        field_already_exist.push(elem);
                        permitted_field_count++; // increment by one
                    }
                });

                select_query +=
                    ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                    'B.profilePictureBigURL FROM realestate_houses AS A LEFT JOIN user AS B ON A.userID = B.userID ';

            } else { // no fields selection
                select_query +=
                    ', A.locationID AS location_id, A.featuredImageRelativeURL AS featured_img, A.description, ' +
                    'A.price, A.time, B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, ' +
                    'B.profilePictureBigURL FROM realestate_houses AS A LEFT JOIN user AS B ON A.userID = B.userID ';
            }

            let counter = 0; // count numbers of search keyword

            if (pass_user_id) {
                select_query += 'WHERE A.userID = ? ';
                select_post.push(pass_user_id);

                // count query
                count_query += 'WHERE userID = ? ';
                count_post.push(pass_user_id);

                counter++;
            }

            if (location_id) {
                if (counter > 0) {
                    select_query += 'AND A.locationID = ? ';
                    select_post.push(location_id);

                    // count query
                    count_query += 'AND locationID = ? ';
                    count_post.push(location_id);

                } else {
                    select_query += 'WHERE A.locationID = ? ';
                    select_post.push(location_id);

                    // count query
                    count_query += 'WHERE locationID = ? ';
                    count_post.push(location_id);
                }

                counter++;
            }

            if (purpose) {
                if (counter > 0) {
                    select_query += 'AND A.for = ? ';
                    select_post.push(purpose == 'rent' ? 1 : 2);

                    // count query
                    count_query += 'AND for = ? ';
                    count_post.push(purpose == 'rent' ? 1 : 2);

                } else {
                    select_query += 'WHERE A.for = ? ';
                    select_post.push(purpose == 'rent' ? 1 : 2);

                    // count query
                    count_query += 'WHERE for = ? ';
                    count_post.push(purpose == 'rent' ? 1 : 2);
                }

                counter++;
            }

            // last should come first
            select_query += 'ORDER BY A.time DESC ';

            // set limit and offset
            select_query += `LIMIT ${limit} OFFSET ${offset}`;

            // get metadata for houses
            gDB.query(count_query, count_post).then(count_results => {
                // get houses
                gDB.query(select_query, select_post).then(results => {
                    for (let i = 0; i < results.length; i++) {
                        // check to get featured image for houses
                        if (results[i].featured_img) {
                            // add featured image to results
                            results[i].featured_img = {
                                big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img,
                                medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'medium'),
                                small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'small'),
                                tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'tiny')
                            };
                        }

                        // check if user has a profile picture
                        if (results[i].profilePictureSmallURL) {
                            // add user to results
                            results[i].user = {
                                id: results[i].userID,
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: {
                                    big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureBigURL,
                                    medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureMediumURL,
                                    small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL
                                }
                            };

                        } else {
                            // add user to results
                            results[i].user = {
                                id: results[i].userID,
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: null
                            };
                        }

                        // remove keys
                        delete results[i].userID;
                        delete results[i].firstName;
                        delete results[i].lastName;
                        delete results[i].profilePictureSmallURL;
                        delete results[i].profilePictureMediumURL;
                        delete results[i].profilePictureBigURL;
                    }

                    // send result to client
                    res.status(200);
                    res.json({
                        houses: results,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: count_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        } else { // no user's information
            let select_query = 'SELECT houseID AS id';
            let select_post = [];
            let count_query = 'SELECT COUNT(*) AS total FROM realestate_houses ';
            let count_post = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `, ${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            select_query += ' FROM realestate_houses ';

            let counter = 0; // count numbers of search keyword

            if (pass_user_id) {
                select_query += 'WHERE userID = ? ';
                select_post.push(pass_user_id);

                // count query
                count_query += 'WHERE userID = ? ';
                count_post.push(pass_user_id);

                counter++;
            }

            if (location_id) {
                if (counter > 0) {
                    select_query += 'AND locationID = ? ';
                    select_post.push(location_id);

                    // count query
                    count_query += 'AND locationID = ? ';
                    count_post.push(location_id);

                } else {
                    select_query += 'WHERE locationID = ? ';
                    select_post.push(location_id);

                    // count query
                    count_query += 'WHERE locationID = ? ';
                    count_post.push(location_id);
                }

                counter++;
            }

            if (purpose) {
                if (counter > 0) {
                    select_query += 'AND for = ? ';
                    select_post.push(purpose == 'rent' ? 1 : 2);

                    // count query
                    count_query += 'AND for = ? ';
                    count_post.push(purpose == 'rent' ? 1 : 2);

                } else {
                    select_query += 'WHERE for = ? ';
                    select_post.push(purpose == 'rent' ? 1 : 2);

                    // count query
                    count_query += 'WHERE for = ? ';
                    count_post.push(purpose == 'rent' ? 1 : 2);
                }

                counter++;
            }

            // last should come first
            select_query += 'ORDER BY time DESC ';

            // set limit and offset
            select_query += `LIMIT ${limit} OFFSET ${offset}`;

            // get metadata for houses
            gDB.query(count_query, count_post).then(count_results => {
                // get houses
                gDB.query(select_query, select_post).then(results => {
                    for (let i = 0; i < results.length; i++) {
                        // check to get featured image for houses
                        if (results[i].featured_img) {
                            // add featured image to results
                            results[i].featured_img = {
                                big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img,
                                medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'medium'),
                                small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'small'),
                                tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'tiny')
                            };
                        }
                    }

                    // send result to client
                    res.status(200);
                    res.json({
                        houses: results,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: count_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        }

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get a house for rent or purchase
router.get('/realEstate/houses/:house_id', custom_utils.allowedScopes(['read:houses']), (req, res) => {
    // check if house id is valid
    if (!/^[a-zA-Z0-9]{32}$/.test(req.params.house_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    let req_fields = null;

    if (req.query.fields) {
        req_fields = custom_utils.filterInArray(
            req.query.fields.split(','),
            ['user', 'images', 'location', 'description', 'negotiable', 'address', 'email', 'phoneNumber', 'price', 'time']
        );
    }

    const mappped_field_name = new Map([
        ['location', 'locationID AS location_id'],
        ['description', 'description'],
        ['negotiable', 'negotiable'],
        ['address', 'address'],
        ['email', 'contactEmail AS email'],
        ['phoneNumber', 'contactPhoneNumber AS phone_number'],
        ['price', 'price'],
        ['time', 'time']
    ]);

    let field_already_exist = [];
    let permitted_field_count = 0;

    // check to retrieve information about the user that add the product
    if (!req_fields || req_fields.length < 1 || req_fields.find(f => f == 'user')) {
        let select_query = 'SELECT A.userID';
        let get_house_images = false;

        if (req_fields || req_fields.length > 0) {
            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `, A.${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, A.${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            select_query +=
                ', B.firstName, B.lastName, B.profilePictureSmallURL, B.profilePictureMediumURL, B.profilePictureBigURL ' +
                'FROM realestate_houses AS A LEFT JOIN user AS B ON A.userID = B.userID ';

            if (req_fields.find(f => f == 'images')) {
                get_house_images = true;
            }

        } else { // no fields selection
            select_query += ', A.locationID AS location_id, A.negotiable, A.description, A.address, A.contactEmail AS email, ' +
                'A.contactPhoneNumber AS phone_number, A.price, A.time, B.firstName, B.lastName, B.profilePictureSmallURL, ' +
                'B.profilePictureMediumURL, B.profilePictureBigURL FROM realestate_houses AS A LEFT JOIN user AS B ON A.userID = B.userID ';

            get_house_images = true;
        }

        // where condition
        select_query += 'WHERE houseID = ? LIMIT 1';

        // check if house exist and retrieve
        gDB.query(select_query, [req.params.house_id]).then(house_results => {
            // check if house exist
            if (house_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "House can't be found"
                });

                return;
            }

            if (req_fields && !get_house_images) { // fetch only house no picture
                // check if user has a profile picture
                if (house_results[0].profilePictureSmallURL) {
                    // add user to results
                    house_results[0].user = {
                        id: house_results[0].userID,
                        name: house_results[0].lastName + ' ' + house_results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + house_results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + house_results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + house_results[0].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    house_results[0].user = {
                        id: house_results[0].userID,
                        name: house_results[0].lastName + ' ' + house_results[0].firstName,
                        image: null
                    };
                }

                // remove keys
                delete house_results[0].userID;
                delete house_results[0].firstName;
                delete house_results[0].lastName;
                delete house_results[0].profilePictureSmallURL;
                delete house_results[0].profilePictureMediumURL;
                delete house_results[0].profilePictureBigURL;

                // send result to client
                res.status(200);
                res.json(house_results[0]);

                return;
            }

            // get picture(s) for house
            gDB.query(
                'SELECT imageRelativeURL FROM realestate_house_images WHERE houseID = ?',
                [req.params.house_id]
            ).then(results => {
                let house_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    house_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                house_results[0].images = house_images;

                // check if user has a profile picture
                if (house_results[0].profilePictureSmallURL) {
                    // add user to results
                    house_results[0].user = {
                        id: house_results[0].userID,
                        name: house_results[0].lastName + ' ' + house_results[0].firstName,
                        image: {
                            big: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + house_results[0].profilePictureBigURL,
                            medium: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + house_results[0].profilePictureMediumURL,
                            small: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + house_results[0].profilePictureSmallURL
                        }
                    };

                } else {
                    // add user to results
                    house_results[0].user = {
                        id: house_results[0].userID,
                        name: house_results[0].lastName + ' ' + house_results[0].firstName,
                        image: null
                    };
                }

                // remove keys
                delete house_results[0].userID;
                delete house_results[0].firstName;
                delete house_results[0].lastName;
                delete house_results[0].profilePictureSmallURL;
                delete house_results[0].profilePictureMediumURL;
                delete house_results[0].profilePictureBigURL;

                // send result to client
                res.status(200);
                res.json(house_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    } else { // no user's information
        let select_query = 'SELECT ';

        req_fields.forEach(elem => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (permitted_field_count == 0) {
                    select_query += `${mappped_field_name.get(elem)}`;

                } else {
                    select_query += `, ${mappped_field_name.get(elem)}`;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        // check if thier is no field select from this table
        if (permitted_field_count < 1) {
            select_query += '1 FROM realestate_houses ';

        } else {
            select_query += ' FROM realestate_houses ';
        }

        // where condition
        select_query += 'WHERE houseID = ? LIMIT 1';

        // check if house exist and retrieve
        gDB.query(select_query, [req.params.house_id]).then(house_results => {
            // check if house exist
            if (house_results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "House can't be found"
                });

                return;
            }

            if (!req_fields.find(f => f == 'images')) { // fetch only house no picture
                // send result to client
                res.status(200);
                res.json(house_results[0]);

                return;
            }

            // get picture(s) for house
            gDB.query(
                'SELECT imageRelativeURL FROM realestate_house_images WHERE houseID = ?',
                [req.params.house_id]
            ).then(results => {
                let house_images = [];

                // prepare image
                for (let i = 0; i < results.length; i++) {
                    house_images.push({
                        big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL,
                        medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'medium'),
                        small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'small'),
                        tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].imageRelativeURL).replace('big', 'tiny')
                    });
                }

                // add to result
                house_results[0].images = house_images;

                // send result to client
                res.status(200);
                res.json(house_results[0]);

                return;

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });
    }
});

// get all the categories for contact emergency
router.get('/emergency/contact/categories', custom_utils.allowedScopes(['read:emergency']), (req, res) => {
    // fetch categories from database
    gDB.query('SELECT categoryID AS id, categoryName AS name FROM emergency_contact_categories').then(results => {
        // return result to client
        res.status(200);
        res.json({
            categories: results
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// add emergency contact to database
router.post('/emergency/contacts', custom_utils.allowedScopes(['write:emergency:admin']), (req, res) => {
    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // pass in queries
    let category_id = req.query.categoryID;
    let location_id = req.query.locationID;

    // check if URL query is defined and valid
    const invalid_inputs = [];

    if (!category_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "categoryID",
            message: "categoryID has to be defined"
        });

    } else if (!/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    if (!location_id) {
        invalid_inputs.push({
            error_code: "undefined_query",
            field: "locationID",
            message: "locationID has to be defined"
        });

    } else if (!/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if category exist
    gDB.query('SELECT 1 FROM emergency_contact_categories WHERE categoryID = ? LIMIT 1', category_id).then(results => {
        if (results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "categoryID",
                message: "categoryID value is invalid"
            });
        }

        // check if location ID exist
        gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id]).then(results => {
            if (results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "locationID",
                    message: "locationID value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs
                });

                return;
            }

            // validate submitted data
            if (!req.body.title) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "title",
                    message: "title has to be defined"
                });

            } else if (!/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.title)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "title",
                    message: "title is not acceptable"
                });
            }

            if (!req.body.address) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "address",
                    message: "address has to be defined"
                });

            } else if (typeof req.body.address != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "address",
                    message: "address is not acceptable"
                });
            }

            if (req.body.email && !validator.isEmail(req.body.email)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "email",
                    message: "email is not acceptable"
                });
            }

            if (!req.body.phoneNumber) {
                invalid_inputs.push({
                    error_code: "undefined_input",
                    field: "phoneNumber",
                    message: "phoneNumber has to be defined"
                });

            } else if (!/^\d+$/.test(req.body.phoneNumber)) {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "phoneNumber",
                    message: "phoneNumber is not acceptable"
                });
            }

            if (req.body.about && typeof req.body.about != 'string') {
                invalid_inputs.push({
                    error_code: "invalid_input",
                    field: "about",
                    message: "about is not acceptable"
                });

            } else if (req.body.about && req.body.about.length > 1500) { // check if about exceed 1500 characters
                invalid_inputs.push({
                    error_code: "invalid_data",
                    field: "about",
                    message: "about exceed maximum allowed text"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_field",
                    errors: invalid_inputs
                });

                return;
            }

            // create emergency contact for users
            gDB.query(
                'INSERT INTO emergency_contacts (categoryID, locationID, title, address, email, phoneNumber, about) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [
                    category_id,
                    location_id,
                    req.body.title,
                    req.body.address,
                    req.body.email ? req.body.email : '',
                    req.body.phoneNumber,
                    req.body.about ? req.body.about : ''
                ]
            ).then(results => {
                // send id to client
                res.status(201);
                res.json({
                    contact_id: results.insertId
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// edit or update emergency contact information
router.put('/emergency/contacts/:contact_id', custom_utils.allowedScopes(['write:emergency:admin']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.contact_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }

    // check if contact exist
    gDB.query('SELECT 1 FROM emergency_contacts WHERE contactID = ? LIMIT 1', [req.params.contact_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Contact can't be found"
            });

            return;
        }

        // validate submitted data
        const invalid_inputs = [];

        if (req.body.title && !/^([a-zA-Z0-9]+([ ]?[a-zA-Z0-9]+)*)$/.test(req.body.title)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "title",
                message: "title is not acceptable"
            });
        }

        if (req.body.address && typeof req.body.address != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "address",
                message: "address is not acceptable"
            });
        }

        if (req.body.email && !validator.isEmail(req.body.email)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "email",
                message: "email is not acceptable"
            });
        }

        if (req.body.phoneNumber && !/^\d+$/.test(req.body.phoneNumber)) {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "phoneNumber",
                message: "phoneNumber is not acceptable"
            });
        }

        if (req.body.about && typeof req.body.about != 'string') {
            invalid_inputs.push({
                error_code: "invalid_input",
                field: "about",
                message: "about is not acceptable"
            });

        } else if (req.body.about && req.body.about.length > 1500) { // check if about exceed 1500 characters
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "about",
                message: "about exceed maximum allowed text"
            });
        }

        // check if any input is invalid
        if (invalid_inputs.length > 0) {
            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs
            });

            return;
        }

        // prepare the update query
        let query = 'UPDATE emergency_contacts SET ';
        let query_post = [];
        let input_count = 0;

        if (req.body.title) {
            query += 'title = ?';
            post.push(req.body.title);
            input_count++;
        }

        if (req.body.address) {
            if (input_count < 1) {
                query += 'address = ?';
                query_post.push(req.body.address);

            } else {
                query += ', address = ?';
                query_post.push(req.body.address);
            }

            input_count++;
        }

        if (req.body.email) {
            if (input_count < 1) {
                query += 'email = ?';
                query_post.push(req.body.email);

            } else {
                query += ', email = ?';
                query_post.push(req.body.email);
            }

            input_count++;
        }

        if (req.body.phoneNumber) {
            if (input_count < 1) {
                query += 'phoneNumber = ?';
                query_post.push(req.body.phoneNumber);

            } else {
                query += ', phoneNumber = ?';
                query_post.push(req.body.phoneNumber);
            }

            input_count++;
        }

        if (req.body.about) {
            if (input_count < 1) {
                query += 'about = ?';
                query_post.push(req.body.about);

            } else {
                query += ', about = ?';
                query_post.push(req.body.about);
            }

            input_count++;
        }

        // last part of the query
        query += ' WHERE contactID = ? LIMIT 1';
        query_post.push(req.params.contact_id);

        // update emergency contact
        gDB.query(query, query_post).then(results => {
            return res.status(200).send();

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });

            return;
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete an emergency contact
router.delete('/emergency/contacts/:contact_id', custom_utils.allowedScopes(['write:emergency:admin']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.contact_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if contact exist and get an featured image if there any
    gDB.query(
        'SELECT featuredImageRelativeURL FROM emergency_contacts WHERE contactID = ? LIMIT 1',
        [req.params.contact_id]
    ).then(results => {
        if (results.length < 1) {
            return res.status(200).send();
        }

        // check if there is featured image to delete
        if (results[0].featuredImageRelativeURL) {
            // set aws s3 access credentials
            aws.config.update({
                apiVersion: '2006-03-01',
                accessKeyId: gConfig.AWS_ACCESS_ID,
                secretAccessKey: gConfig.AWS_SECRET_KEY,
                region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
            });

            const s3 = new aws.S3();

            // initialise objects to delete
            const deleteParam = {
                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                Delete: {
                    Objects: [{ Key: results[0].featuredImageRelativeURL }]
                }
            };

            s3.deleteObjects(deleteParam, (err, data) => {
                if (err) {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                }

                // delete an emergency contact
                gDB.query(
                    'DELETE FROM emergency_contacts WHERE contactID = ? LIMIT 1',
                    [req.params.contact_id]
                ).then(results => {
                    return res.status(200).send();

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
            });

        } else { // no image
            // delete an emergency contact
            gDB.query(
                'DELETE FROM emergency_contacts WHERE contactID = ? LIMIT 1',
                [req.params.contact_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        }

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// upload image for emergency contact
router.post('/emergency/contacts/:contact_id/upload/featuredImage', custom_utils.allowedScopes(['write:emergency:admin']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.contact_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if contact exist
    gDB.query('SELECT 1 FROM emergency_contacts WHERE contactID = ? LIMIT 1', [req.params.contact_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Contact can't be found"
            });

            return;
        }

        upload(req, res, (err) => {
            // check if enctype is multipart form data
            if (!req.is('multipart/form-data')) {
                res.status(415);
                res.json({
                    error_code: "invalid_request_body",
                    message: "Encode type not supported"
                });

                return;
            }

            // check if file contain data
            if (!req.file) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "Bad request"
                });

                return;
            }

            // A Multer error occurred when uploading
            if (err instanceof multer.MulterError) {
                if (err.code == 'LIMIT_FILE_SIZE') {
                    res.status(400);
                    res.json({
                        error_code: "size_exceeded",
                        message: "Image your uploading exceeded allowed size"
                    });

                    return;
                }

                // other multer errors
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;

            } else if (err) { // An unknown error occurred when uploading
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            let file_path = req.file.path; // uploaded file location
            const save_image_ext = 'png';

            // read uploaded image as buffer
            let image_buffer = fs.readFileSync(file_path);

            // check file type and if is supported
            let supported_images = [
                'jpg',
                'png',
                'gif',
                'jp2'
            ];

            // read minimum byte from buffer required to determine file mime
            let file_mime = file_type(Buffer.from(image_buffer, 0, file_type.minimumBytes));

            if (!(file_mime.mime.split('/')[0] == 'image' && supported_images.find(e => e == file_mime.ext))) {
                // delete the uploaded file
                fs.unlinkSync(file_path);

                res.status(406);
                res.json({
                    error_code: "unsupported_format",
                    message: "Uploaded image is not supported"
                });

                return;
            }

            // resize the image if it exceeded the maximum resolution
            sharp(image_buffer)
                .resize({
                    height: 1080, // resize image using the set height
                    withoutEnlargement: true
                })
                .toFormat(save_image_ext)
                .toBuffer()
                .then(outputBuffer => {
                    // no higher than 1080 pixels
                    // and no larger than the input image

                    // upload buffer to aws s3 bucket
                    // set aws s3 access credentials
                    aws.config.update({
                        apiVersion: '2006-03-01',
                        accessKeyId: gConfig.AWS_ACCESS_ID,
                        secretAccessKey: gConfig.AWS_SECRET_KEY,
                        region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
                    });

                    const s3 = new aws.S3();

                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    const uploadImage = () => {
                        const object_unique_name = rand_token.uid(34) + '.' + save_image_ext;
                        let dir_name = 'emergency';

                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: outputBuffer,
                            Key: dir_name + '/images/big/' + object_unique_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, (err, data) => {
                            if (err) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            }

                            if (data) { // file uploaded successfully
                                let img_path = dir_name + '/images/big/' + object_unique_name;

                                // save file location to database
                                gDB.query(
                                    'UPDATE emergency_contacts SET featuredImageRelativeURL = ? WHERE contactID = ? LIMIT 1',
                                    [
                                        img_path,
                                        req.params.contact_id
                                    ]
                                ).then(results => {
                                    // send result to client
                                    res.status(200);
                                    res.json({
                                        image: {
                                            big: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/big/${object_unique_name}`,
                                            medium: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/medium/${object_unique_name}`,
                                            small: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/small/${object_unique_name}`,
                                            tiny: `${gConfig.AWS_S3_WEB_BASE_URL}/${dir_name}/images/tiny/${object_unique_name}`
                                        }
                                    });

                                }).catch(err => {
                                    res.status(500);
                                    res.json({
                                        error_code: "internal_error",
                                        message: "Internal error"
                                    });

                                    // log the error to log file
                                    gLogger.log('error', err.message, {
                                        stack: err.stack
                                    });

                                    return;
                                });
                            }
                        });
                    };

                    // check if featured image has been uploaded before
                    gDB.query(
                        'SELECT featuredImageRelativeURL FROM emergency_contacts WHERE contactID = ? LIMIT 1',
                        [req.params.contact_id]
                    ).then(results => {
                        if (results[0].featuredImageRelativeURL) {
                            // delete the previous uploaded image
                            const deleteParam = {
                                Bucket: gConfig.AWS_S3_BUCKET_NAME,
                                Delete: {
                                    Objects: [{ Key: results[0].featuredImageRelativeURL }]
                                }
                            };

                            s3.deleteObjects(deleteParam, (err, data) => {
                                if (err) {
                                    res.status(500);
                                    res.json({
                                        error_code: "internal_error",
                                        message: "Internal error"
                                    });

                                    // log the error to log file
                                    gLogger.log('error', err.message, {
                                        stack: err.stack
                                    });

                                    return;

                                } else {
                                    uploadImage();
                                }
                            });

                        } else { // no upload
                            uploadImage();
                        }

                    }).catch(err => {
                        // delete the uploaded file
                        fs.unlinkSync(file_path);

                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

                }).catch(err => {
                    // delete the uploaded file
                    fs.unlinkSync(file_path);

                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// delete uploaded image for emergency contact
router.delete('/emergency/contacts/:contact_id/upload/featuredImage', custom_utils.allowedScopes(['write:emergency:admin']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.contact_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if contact exist and get featured image for emergency contact
    gDB.query(
        'SELECT featuredImageRelativeURL FROM emergency_contacts WHERE contactID = ? LIMIT 1',
        [req.params.contact_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Contact can't be found"
            });

            return;
        }

        // check if image exist
        if (!results[0].featuredImageRelativeURL) {
            return res.status(200).send();
        }

        // set aws s3 access credentials
        aws.config.update({
            apiVersion: '2006-03-01',
            accessKeyId: gConfig.AWS_ACCESS_ID,
            secretAccessKey: gConfig.AWS_SECRET_KEY,
            region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
        });

        const s3 = new aws.S3();

        // initialise objects to delete
        const deleteParam = {
            Bucket: gConfig.AWS_S3_BUCKET_NAME,
            Delete: {
                Objects: [{ Key: results[0].featuredImageRelativeURL }]
            }
        };

        s3.deleteObjects(deleteParam, (err, data) => {
            if (err) {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            }

            // delete contact featured image
            gDB.query(
                'UPDATE emergency_contacts SET featuredImageRelativeURL = ? WHERE contactID = ? LIMIT 1',
                ['', req.params.contact_id]
            ).then(results => {
                return res.status(200).send();

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });

        return;
    });
});

// get list of emergency contact
router.get('/emergency/contacts', custom_utils.allowedScopes(['read:emergency']), (req, res) => {
    //define and initialise variables
    let limit = 50;
    let offset = 0;
    let pass_limit = req.query.limit;
    let pass_offset = req.query.offset;
    const location_id = req.query.locationID;
    const category_id = req.query.categoryID;
    const invalid_inputs = [];

    // check if query category ID is provided and valid
    if (!category_id) {
        invalid_inputs.push({
            error_code: "undefined_value",
            field: "categoryID",
            message: "categoryID is not provided"
        });

    } else if (!/^\d+$/.test(category_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "categoryID",
            message: "categoryID value is invalid"
        });
    }

    // check if query location ID is valid
    if (location_id && !/^\d+$/.test(location_id)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "locationID",
            message: "locationID value is invalid"
        });
    }

    // check if limit is defined and valid
    if (pass_limit && !/^\d+$/.test(pass_limit)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "limit",
            message: "value must be integer"
        });
    }

    // check if offset is defined and valid
    if (pass_offset && !/^\d+$/.test(pass_offset)) {
        invalid_inputs.push({
            error_code: "invalid_value",
            field: "offset",
            message: "value must be integer"
        });
    }

    // check if any input is invalid
    if (invalid_inputs.length > 0) {
        // send json error message to client
        res.status(406);
        res.json({
            error_code: "invalid_query",
            errors: invalid_inputs
        });

        return;
    }

    // check if region with location ID exist
    gDB.query('SELECT 1 FROM map_regions WHERE regionID = ? LIMIT 1', [location_id ? location_id : 0]).then(results => {
        if (location_id && results.length < 1) {
            invalid_inputs.push({
                error_code: "invalid_value",
                field: "locationID",
                message: "locationID value is invalid"
            });
        }

        // check if category ID exist
        gDB.query(
            'SELECT 1 FROM emergency_contact_categories WHERE categoryID = ? LIMIT 1',
            [category_id ? category_id : 0]
        ).then(results => {
            if (category_id && results.length < 1) {
                invalid_inputs.push({
                    error_code: "invalid_value",
                    field: "categoryID",
                    message: "categoryID value is invalid"
                });
            }

            // check if any input is invalid
            if (invalid_inputs.length > 0) {
                // send json error message to client
                res.status(406);
                res.json({
                    error_code: "invalid_query",
                    errors: invalid_inputs
                });

                return;
            }

            if (pass_limit && pass_limit < limit) {
                limit = pass_limit;
            }

            if (pass_offset) {
                offset = pass_offset;
            }

            const mappped_field_name = new Map([
                ['location', 'locationID AS location_id'],
                ['featuredImage', 'featuredImageRelativeURL AS featured_img'],
                ['title', 'title'],
                ['address', 'address'],
                ['time', 'time']
            ]);
            let select_query = 'SELECT contactID AS id, ';
            let select_post = [];
            let count_query = 'SELECT COUNT(*) AS total FROM emergency_contacts ';
            let count_post = [];

            // check if is valid and required fields is given
            if (req.query.fields) {
                // split the provided fields
                let req_fields = req.query.fields.split(',');
                let permitted_field_count = 0;
                let field_already_exist = [];

                req_fields.forEach(elem => {
                    if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                        if (permitted_field_count == 0) {
                            select_query += `${mappped_field_name.get(elem)}`;

                        } else {
                            select_query += `, ${mappped_field_name.get(elem)}`;
                        }

                        field_already_exist.push(elem);
                        permitted_field_count++; // increment by one
                    }
                });

                if (permitted_field_count < 1) {
                    select_query =
                        'SELECT contactID AS id, locationID AS location_id, featuredImageRelativeURL AS featured_img, ' +
                        'title, address, time FROM emergency_contacts ';

                } else {
                    select_query += ' FROM emergency_contacts ';
                }

            } else { // no fields selection
                select_query += 'locationID AS location_id, featuredImageRelativeURL AS featured_img, title, address, time FROM emergency_contacts ';
            }

            // add search keywords to SQL query
            // category
            select_query += 'WHERE categoryID = ? ';
            select_post.push(category_id);

            // for count query
            count_query += 'WHERE categoryID = ? ';
            count_post.push(category_id);

            // location
            if (location_id) {
                select_query += 'AND locationID = ? ';
                select_post.push(location_id);

                // for count query
                count_query += 'AND locationID = ? ';
                count_post.push(location_id);
            }

            // set limit and offset
            select_query += `LIMIT ${limit} OFFSET ${offset}`;

            // get metadata for contacts
            gDB.query(count_query, count_post).then(count_results => {
                // get contacts
                gDB.query(select_query, select_post).then(results => {
                    for (let i = 0; i < results.length; i++) {
                        // check if contact has featured image
                        if (results[i].featured_img) {
                            // add featured image to the results
                            results[i].featured_img = {
                                big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img,
                                medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'medium'),
                                small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'small'),
                                tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[i].featured_img).replace('big', 'tiny')
                            };

                        } else if (typeof results[i].featured_img != 'undefined') {
                            // add featured image to the results
                            results[i].featured_img = null;
                        }
                    }

                    // send result to client
                    res.status(200);
                    res.json({
                        contacts: results,
                        metadata: {
                            result_set: {
                                count: results.length,
                                offset: offset,
                                limit: limit,
                                total: count_results[0].total
                            }
                        }
                    });

                    return;

                }).catch(err => {
                    res.status(500);
                    res.json({
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log('error', err.message, {
                        stack: err.stack
                    });

                    return;
                });

            }).catch(err => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });

                return;
            });

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });
    });
});

// get an emergency contact
router.get('/emergency/contacts/:contact_id', custom_utils.allowedScopes(['read:emergency']), (req, res) => {
    // check if id is integer
    if (!/^\d+$/.test(req.params.contact_id)) {
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }

    // check if contact exist
    gDB.query('SELECT 1 FROM emergency_contacts WHERE contactID = ? LIMIT 1', [req.params.contact_id]).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Contact can't be found"
            });

            return;
        }

        const mappped_field_name = new Map([
            ['category', 'categoryID AS category_id'],
            ['location', 'locationID AS location_id'],
            ['featuredImage', 'featuredImageRelativeURL AS featured_img'],
            ['title', 'title'],
            ['address', 'address'],
            ['email', 'email'],
            ['phoneNumber', 'phoneNumber AS phone_number'],
            ['about', 'about'],
            ['time', 'time']
        ]);
        let select_query = 'SELECT ';

        // check if is valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];

            req_fields.forEach(elem => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (permitted_field_count == 0) {
                        select_query += `${mappped_field_name.get(elem)}`;

                    } else {
                        select_query += `, ${mappped_field_name.get(elem)}`;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                select_query =
                    'SELECT categoryID AS category_id, locationID AS location_id, featuredImageRelativeURL AS featured_img, ' +
                    'title, address, email, phoneNumber AS phone_number, about, time FROM emergency_contacts ';

            } else {
                select_query += ' FROM emergency_contacts ';
            }

        } else { // no fields selection
            select_query +=
                'categoryID AS category_id, locationID AS location_id, featuredImageRelativeURL AS featured_img, ' +
                'title, address, email, phoneNumber AS phone_number, about, time FROM emergency_contacts ';
        }

        // SQL WHERE statement
        select_query += 'WHERE contactID = ? LIMIT 1';

        // get a contact
        gDB.query(select_query, [req.params.contact_id]).then(results => {
            // check if contact has featured image
            if (results[0].featured_img) {
                // add featured image to the results
                results[0].featured_img = {
                    big: gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featured_img,
                    medium: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featured_img).replace('big', 'medium'),
                    small: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featured_img).replace('big', 'small'),
                    tiny: (gConfig.AWS_S3_WEB_BASE_URL + '/' + results[0].featured_img).replace('big', 'tiny')
                };

            } else if (typeof results[0].featured_img != 'undefined') {
                // add featured image to the results
                results[0].featured_img = null;
            }

            // send result to client
            res.status(200);
            res.send(results[0]);

        }).catch(err => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log('error', err.message, {
                stack: err.stack
            });
        });

    }).catch(err => {
        res.status(500);
        res.json({
            error_code: "internal_error",
            message: "Internal error"
        });

        // log the error to log file
        gLogger.log('error', err.message, {
            stack: err.stack
        });
    });
});

router.get(/^\/hellos\/(\d+)$/, custom_utils.allowedScopes(['read:hellos', 'read:hellos:all']), (req, res) => {
    const token_user_id = parseInt(req.user.access_token.user_id, 10);
    const user_id = parseInt(req.params[0], 10);

    // check if is accessing the right user or as a logged in user
    if (!user_id == token_user_id) {
        res.status(401);
        res.json({
            status: 401,
            error_code: "unauthorized_user",
            message: "Unauthorized"
        });

        return;

    } else {
        res.status(200);
        res.json({
            status: 200,
            message: 'Welcome to REST API version 1'
        });
    }
});

module.exports = router;

