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
        cb(null, gConfig.TEMP_FILE_STORAGE_PATH);
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
});
const multer_s3 = require('multer-s3');
const aws = require('aws-sdk');
const sharp = require('sharp');
const file_type = require('file-type');

const router = express.Router();

// check and validate access token (JWT)
router.use(custom_utils.validateToken);

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

    const dob = typeof req.body.dateOfBirth == 'undefined' ? null : req.body.dateOfBirth.split('-');

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
                    let search_email_hash = crypto.createHash("sha1").update(req.body.email, "binary").digest("hex");

                    // store user's information to database
                    gDB.transaction({
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
                            query: 'SELECT @user_id:=userID FROM user WHERE searchEmailHash = ?',
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

// validate registration fields or inputs
router.post('/users/validateSignUpInputs', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
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
router.post('/users/:id/email/sendVerification', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
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

        }).catch(reason => {
            res.status(500);
            res.json({
                error_code: "internal_error",
                message: "Internal error"
            });

            // log the error to log file
            gLogger.log({
                level: 'error',
                message: reason
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
router.post('/users/:id/email/confirmVerification', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
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

// unknown
router.post('/users/:user_id/profile/picture', custom_utils.allowedScopes(['write:user']), (req, res) => {
    // code here
});

// unknown
router.get('/users/:user_id/profile/picture', custom_utils.allowedScopes(['read:user']), (req, res) => {
    // code here
});

// unknown
router.post('/users/:user_id/profile/about', custom_utils.allowedScopes(['write:user']), (req, res) => {
    // code here
});

// unknown
router.get('/users/:user_id/profile/about', custom_utils.allowedScopes(['read:user']), (req, res) => {
    // code here
});

// get categories for article or news
router.get('/user/:publication_type/categories', custom_utils.allowedScopes(['read:user']), (req, res) => {
    // check if publication_type is article or news
    if (!/^(article|news)$/.test(req.params.publication_type)) {
        res.status(404);
        res.json({
            error_code: "file_not_found",
            message: "File not found"
        });

        return;
    }

    const table_name = publication_type + '_categories';

    // retrieve categories from database
    gDB.query('SELECT categoryID AS id, categoryTitle AS category FROM ??', [table_name]).then(results => {
        res.status(200);
        res.json({
            categories: results
        });

        return;

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

// get areas users can publish content
router.get('/user/publishLocation/:location', custom_utils.allowedScopes(['read:user']), (req, res) => {
    // check the location
    if (!/^(countries|regions)$/.test(req.params.location)) {
        res.status(404);
        res.json({
            error_code: "file_not_found",
            message: "File not found"
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

    if (req.params.location == 'countries') {
        // select countries from database
        gDB.query(
            'SELECT countryID AS id, name FROM countries LIMIT ? OFFSET ?', [limit, offset]
        ).then(results => {
            res.status(200);
            res.json({
                countries: results
            });

            return;

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

    } else { //regions
        let query;
        let post;

        // get country to select regions from
        if (req.params.countryID && /^\d+$/.test(req.params.countryID)) {
            query = 'SELECT regionID AS id, name FROM regions WHERE countryID = ? LIMIT ? OFFSET ?';
            post = [req.params.countryID, limit, offset];

        } else {
            query = 'SELECT regionID AS id, name FROM regions LIMIT ? OFFSET ?';
            post = [limit, offset];
        }

        // select countries from database
        gDB.query(query, post).then(results => {
            res.status(200);
            res.json({
                regions: results
            });

            return;

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
});

/*
 * save newly created article to draft and return a 
 * unique id that identified the article stored in draft
 */
router.post('/users/:user_id/draft/article', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.user_id)) {
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

        // utility function to save article to draft
        const saveToDraft = () => {
            // generate sixten digit unique id
            const draft_id = rand_token.generate(16);

            // save article to user's draft
            gDB.query(
                'INSERT INTO draft (draftID, categoryID, featuredImageURL, title, content, ' +
                'draftContentTypeID) VALUES (?, ?, ?, ?, ?, ?)',
                [
                    draft_id,
                    req.body.categoryID,
                    req.body.featuredImageURL ? req.body.featuredImageURL : '',
                    req.body.title ? req.body.title : '',
                    req.body.content ? req.body.content : '',
                    0
                ]
            ).then(results => {
                res.status(201);
                res.json({
                    draft_id: draft_id,
                    message: "Draft created successfully for article"
                });

                return;

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
        };

        // check body data type if is provided
        if (req.body.title && typeof req.body.title != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "title",
                message: "title is not acceptable"
            });
        }

        // check body data type if is provided
        if (req.body.content && typeof req.body.content != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "body",
                message: "body is not acceptable"
            });
        }

        //category id must be provided
        if (!req.body.categoryID) {
            invalid_inputs.push({
                error_code: "undefined_data",
                field: "categoryID",
                message: "categoryID has to be defined"
            });

        } else if (!/^\d+$/.test(req.body.categoryID)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "categoryID",
                message: "categoryID is not acceptable"
            });

        } else if (req.body.categoryID) {
            // check if category id exist
            gDB.query('SELECT 1 FROM article_categories WHERE categoryID = ? LIMIT 1', [req.body.categoryID]).then(results => {
                if (results.length < 1) { // the SQL query is fast enough
                    // category does not exist
                    invalid_inputs.push({
                        error_code: "invalid_data",
                        field: "categoryID",
                        message: "categoryID doesn't exist"
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

                // save article to draft
                saveToDraft();

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
            }

            // save article to draft
            saveToDraft();
        }

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

/*
 * Add article to draft for edit and return
 * unique id that identified the article stored in draft
 * 
 * For already published articles, you can't change it location
 */
router.post('/users/:user_id/article/:article_id/edit', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.user_id)) {
        // check if is accessing the right user or as a logged in user
        if (!req.params.user_id == req.user.access_token.user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        // generate sixten digit unique id
        const draft_id = rand_token.generate(16);

        gDB.query(
            'SELECT articleID, categoryID, featuredImageURL, title, ' +
            'highlight, content FROM articles WHERE articleID = ? AND userID = ? LIMIT 1',
            [req.params.article_id, req.params.user_id]
        ).then(results => {
            // check if article exist 
            if (results.length < 1) {
                return res.status(204).send(); // article doesn't exist
            }

            // copy data to draft
            gDB.query(
                'INSERT INTO draft (draftID, userID, draftContentTypeID, categoryID, featuredImageURL, ' +
                'title, highlight, content, published, publishedContentID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    draft_id,
                    req.params.user_id,
                    0, // article
                    results[0].category,
                    results[0].featuredImageURL,
                    results[0].title,
                    results[0].highlight,
                    results[0].content,
                    1, // already published
                    results[0].articleID
                ]
            ).then(results => {
                res.status(201);
                res.json({
                    draft_id: draft_id,
                    message: "Article added to draft successfully"
                });

                return;

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

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// update content save to draft
router.put('/users/:user_id/draft/:draft_id', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.user_id)) {
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

        // utility function to save article to draft
        const saveToDraft = () => {
            let query = 'UPDATE draft SET ';
            let post = [];

            // check if category id is provided
            if (req.body.categoryID) {
                query += 'categoryID = ?, ';
                post.push(req.body.categoryID);

            }

            // check if featuredImageURL is provided
            if (req.body.featuredImageURL) {
                query += 'featuredImageURL = ?, ';
                post.push(req.body.featuredImageURL);

            }

            // check if title is provided
            if (req.body.title) {
                query += 'title = ?, ';
                post.push(req.body.title);

            }

            // check if content is provided
            if (req.body.content) {
                query += 'content = ? ';
                post.push(req.body.content);

            }

            //last part of query
            query += 'WHERE draftID = ? LIMIT 1';
            post.push(req.params.draft_id);

            // save article to user's draft
            gDB.query(query, post).then(results => {
                // check if updated is successfully
                if (results.affectedRows < 1) {
                    return res.status(204).send(); // draft doesn't exist

                } else {
                    return res.status(200).send();
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
        };

        // check body data type if is provided
        if (req.body.title && typeof req.body.title != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "title",
                message: "title is not acceptable"
            });
        }

        // check body data type if is provided
        if (req.body.body && typeof req.body.body != 'string') {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "body",
                message: "body is not acceptable"
            });
        }

        // check category data type if is provided
        if (req.body.categoryID && !/^\d+$/.test(req.body.categoryID)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "categoryID",
                message: "categoryID is not acceptable"
            });

        } else if (req.body.category) {
            // check if category id exist
            gDB.query('SELECT 1 FROM article_categories WHERE categoryID = ? LIMIT 1', [req.body.category]).then(results => {
                if (results.length < 1) { // the SQL query is fast enough
                    // category does not exist
                    invalid_inputs.push({
                        error_code: "invalid_data",
                        field: "categoryID",
                        message: "categoryID doesn't exist"
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

                // save article to draft
                saveToDraft();

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
            }

            // save article to draft
            saveToDraft();
        }

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// publish article or news save to draft and return the id
router.put('/users/:user_id/draft/:draft_id/publish', custom_utils.allowedScopes(['write:users']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.user_id)) {
        // check if is accessing the right user or as a logged in user
        if (!req.params.user_id == req.user.access_token.user_id) {
            res.status(401);
            res.json({
                error_code: "unauthorized_user",
                message: "Unauthorized"
            });

            return;
        }

        if (!req.body) { // check if body contains data
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

        // check if field(s) contain valid data
        const invalid_inputs = [];

        if (!req.body.restrict) {
            invalid_inputs.push({
                error_code: "undefined_data",
                field: "restrict",
                message: "restrict has to be defined"
            });

        } else if (!/^(0|1)+$/.test(req.body.restrict)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "restrict",
                message: "restrict is not valid"
            });
        }

        if (!req.body.locationID) {
            invalid_inputs.push({
                error_code: "undefined_data",
                field: "locationID",
                message: "locationID has to be defined"
            });

            // send json error message to client
            res.status(406);
            res.json({
                error_code: "invalid_field",
                errors: invalid_inputs,
                message: "Field(s) value not acceptable"
            });

            return;

        } else if (!/^\d+$/.test(req.body.locationID)) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "locationID",
                message: "locationID is not valid"
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
            // check if location id exist and retrieve countryID and continentID
            gDB.query(
                'SELECT countryID, continentID FROM regions WHERE regionID = ? LIMIT 1', [req.body.locationID]
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
                        error_code: "invalid_field",
                        errors: invalid_inputs,
                        message: "Field(s) value not acceptable"
                    });

                    return;
                }

                // fetch article stored in draft
                gDB.query(
                    'SELECT categoryID, featuredImageURL, title, content, published, ' +
                    'publishedContentID FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
                    [req.params.draft_id, req.params.user_id]
                ).then(draft_results => {
                    // check if draft exist 
                    if (draft_results.length < 1) {
                        return res.status(204).send(); // draft doesn't exist
                    }

                    // check if is article or news
                    if (draft_results[0].draftContentTypeID == 0) { // article

                        // generate highlight or description from article content
                        let article_highlight = 'sample sample sample'; // still debating on how it will be generated

                        // check if this article is published first time
                        if (draft_results[0].published == 0) { // has not been published
                            gDB.transaction({
                                query: 'DELETE FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
                                post: [req.params.draft_id, req.params.user_id]
                            }, {
                                query: 'INSERT INTO articles (userID, categoryID, continentID, countryID, regionID, featuredImageURL, ' +
                                    'title, highlight, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                                post: [
                                    req.params.user_id,
                                    results[0].categoryID,
                                    region_results[0].continentID,
                                    region_results[0].countryID,
                                    req.body.locationID,
                                    draft_results[0].featuredImageURL,
                                    draft_results[0].title,
                                    article_highlight,
                                    draft_results[0].content
                                ]
                            }).then(results => {
                                res.status(201);
                                res.json({
                                    article_id: results.insertId,
                                    message: "Article published successfully"
                                });

                                return;

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

                        } else { // article has been published
                            gDB.transaction({
                                query: 'DELETE FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
                                post: [req.params.draft_id, req.params.user_id]
                            }, {
                                query: 'UPDATE articles SET categoryID = ?, featuredImageURL = ?, ' +
                                    'title = ?, highlight = ?, content = ? WHERE articleID = ?',
                                post: [
                                    results[0].categoryID,
                                    draft_results[0].featuredImageURL,
                                    draft_results[0].title,
                                    article_highlight,
                                    draft_results[0].content,
                                    draft_results[0].publishedContentID
                                ]
                            }).then(results => {
                                res.status(201);
                                res.json({
                                    article_id: draft_results[0].publishedContentID,
                                    message: "Published successfully"
                                });

                                return;

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

                    } else { // news
                        // generate highlight or description from news content
                        let news_highlight = 'sample sample sample'; // still debating on how it will be generated

                        // check if this article is published first time
                        if (draft_results[0].published == 0) { // has not been published
                            gDB.transaction({
                                query: 'DELETE FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
                                post: [req.params.draft_id, req.params.user_id]
                            }, {
                                query: 'INSERT INTO news (userID, categoryID, continentID, countryID, regionID, featuredImageURL, ' +
                                    'title, highlight, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                                post: [
                                    req.params.user_id,
                                    results[0].categoryID,
                                    region_results[0].continentID,
                                    region_results[0].countryID,
                                    req.body.locationID,
                                    draft_results[0].featuredImageURL,
                                    draft_results[0].title,
                                    news_highlight,
                                    draft_results[0].content
                                ]
                            }).then(results => {
                                res.status(201);
                                res.json({
                                    news_id: results.insertId,
                                    message: "Article published successfully"
                                });

                                return;

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

                        } else { // news has been published
                            gDB.transaction({
                                query: 'DELETE FROM draft WHERE draftID = ? AND userID = ? LIMIT 1',
                                post: [req.params.draft_id, req.params.user_id]
                            }, {
                                query: 'UPDATE news SET categoryID = ?, featuredImageURL = ?, ' +
                                    'title = ?, highlight = ?, content = ? WHERE articleID = ?',
                                post: [
                                    results[0].categoryID,
                                    draft_results[0].featuredImageURL,
                                    draft_results[0].title,
                                    article_highlight,
                                    draft_results[0].content,
                                    draft_results[0].publishedContentID
                                ]
                            }).then(results => {
                                res.status(201);
                                res.json({
                                    news_id: draft_results[0].publishedContentID,
                                    message: "Published successfully"
                                });

                                return;

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

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// retrieve a publication saved to user's draft
router.get('/users/:user_id/draft/:draft_id', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.user_id)) {
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
            'categoryID',
            'featuredImageURL',
            'title',
            'highlight',
            'content',
            'time'
        ];
        let query = 'SELECT ';

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];
            const req_field_count = req_fields.length - 1;

            req_fields.forEach((elem, index) => {
                if (!field_already_exist.find(f => f == elem) && permitted_fields.find(q => q == elem)) {
                    if (index == req_field_count) {
                        query += `${elem} `;

                    } else {
                        query += `${elem}, `;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                query = 'SELECT categoryID, featuredImageURL, title, highlight, content, time ' +
                    'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';

            } else {
                query += 'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';
            }

        } else { // no fields selection
            query += 'categoryID, featuredImageURL, title, highlight, content, time ' +
                'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1'
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

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// retrieve all article saved to user's draft
router.get('/users/:user_id/draft/articles', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.user_id)) {
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
            'categoryID',
            'featuredImageURL',
            'title',
            'highlight',
            'content',
            'time'
        ];
        let query = 'SELECT ';

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];
            const req_field_count = req_fields.length - 1;

            req_fields.forEach((elem, index) => {
                if (!field_already_exist.find(f => f == elem) && permitted_fields.find(q => q == elem)) {
                    if (index == req_field_count) {
                        query += `${elem} `;

                    } else {
                        query += `${elem}, `;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                query = 'SELECT categoryID, featuredImageURL, title, highlight, content, time ' +
                    'FROM draft WHERE userID = ? AND draftContentTypeID = 0';

            } else {
                query += 'FROM draft WHERE userID = ? AND draftContentTypeID = 0';
            }

        } else { // no fields selection
            query += 'categoryID, featuredImageURL, title, highlight, content, time ' +
                'FROM draft WHERE userID = ? AND draftContentTypeID = 0'
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
            res.json({
                articles: results
            });

            return;

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

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_user_id",
            message: "Bad request"
        });

        return;
    }
});

// upload media contents for an article
router.post('/users/:user_id/articles/:article_id/medias', function (req, res) {
    // check if user has needed scopes for this operation
    let validate_scopes = custom_utils.allowedScopes(['write:users']);

    // call pass in function if user has needed scope(s)
    validate_scopes(req, res, () => {
        // check if user and article id is integer
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

        // check if article for the user exist
        gDB.query(
            'SELECT 1 FROM articles WHERE articleID = ? AND userID = ? LIMIT 1',
            [req.params.article_id, req.params.user_id]
        ).then(results => {
            if (results.length < 1) {
                res.status(404);
                res.json({
                    error_code: "file_not_found",
                    message: "Article can't be found"
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

                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: outputBuffer,
                            Key: 'article/images/large/' + object_unique_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, function (err, data) {
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
                                // generate sixten digit unique id
                                const image_id = rand_token.generate(16);
                                const parse_url = url_parse(data.Location, true);

                                // save file metadata and location to database
                                gDB.query(
                                    'INSERT INTO article_media_contents (articleID, userID, mediaID, mediaRelativePath, ' +
                                    'mediaOriginalName, mediaType, mediaExt) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                    [
                                        req.params.article_id,
                                        req.params.user_id,
                                        image_id,
                                        'article/images/large/' + object_unique_name,
                                        file_name,
                                        file_mime.mime.split('/')[0],
                                        save_image_ext,
                                    ]
                                ).then(results => {
                                    // send result to client
                                    res.status(200);
                                    res.json({
                                        id: image_id,
                                        images: [{
                                                url: data.Location,
                                                size: 'large'
                                            },
                                            {
                                                url: parse_url.origin + '/' + gConfig.AWS_S3_BUCKET_NAME + '/article/images/medium/' + object_unique_name,
                                                size: 'medium'
                                            },
                                            {
                                                url: parse_url.origin + '/' + gConfig.AWS_S3_BUCKET_NAME + '/article/images/small/' + object_unique_name,
                                                size: 'small'
                                            },
                                            {
                                                url: parse_url.origin + '/' + gConfig.AWS_S3_BUCKET_NAME + '/article/images/tiny/' + object_unique_name,
                                                size: 'tiny'
                                            }
                                        ]
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
});

// create the requested image size and store it to aws s3 bucket and redirect user to the source
router.get('/resizeImage/:base_folder/images/:resize_size/:image_name', (req, res) => {
    // check if parse base folder name is valid
    if (!/^(article|news)$/.test(req.params.base_folder)) {
        res.status(404);
        res.json({
            error_code: "file_not_found",
            message: "Image does not exist"
        });

        return;
    }

    // fetch image from aws s3 bucket
    // set aws s3 access credentials
    aws.config.update({
        apiVersion: '2006-03-01',
        accessKeyId: gConfig.AWS_ACCESS_ID,
        secretAccessKey: gConfig.AWS_SECRET_KEY,
        region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
    });

    const s3 = new AWS.S3();

    const params = {
        Bucket: gConfig.AWS_S3_BUCKET_NAME,
        Key: req.params.base_folder + '/images/large/' + req.params.image_name
    };

    //check if file exist at s3 bucket
    s3.headObject(params, (err, metadata) => {
        if (err && err.code == 'NotFound') {
            // handle object not found on cloud
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Image does not exist"
            });

            return;

        } else { // object exist
            const resize_sizes = new Map([
                ['medium', 720],
                ['small', 360],
                ['tiny', 250]
            ]);

            const img_res_size = resize_sizes.get(req.params.resize_size);

            // check if size to resize to is valid
            if (!img_res_size) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "Bad request"
                });

                return;
            }

            const s3_promise = s3.getObject(params).promise();

            s3_promise.then((data) => {
                // rezise the image to requested size and upload it back
                sharp(data.Body)
                    .resize({
                        height: img_res_size, // resize image using the set height
                        withoutEnlargement: true
                    })
                    .toFormat('png')
                    .toBuffer()
                    .then(outputBuffer => {
                        // upload resize image to s3 bucket
                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: outputBuffer,
                            Key: 'article/images/' + req.params.resize_size + '/' + req.params.image_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, function (err, data) {
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
                                // redirect client to aws s3 bucket
                                res.set('location', data.Location);
                                res.status(301).send();
                                return;
                            }
                        });

                    })
                    .catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

            }).catch((err) => {
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
    });
});

// retrieve an article
router.get('/articles/:id', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.id)) {

        const permitted_fields = [
            'categoryID',
            'continentID',
            'countryID',
            'regionID',
            'featuredImageURL',
            'title',
            'highlight',
            'content',
            'time'
        ];
        let query = 'SELECT ';

        // check if valid and required fields is given
        if (req.query.fields) {
            // split the provided fields
            let req_fields = req.query.fields.split(',');
            let permitted_field_count = 0;
            let field_already_exist = [];
            const req_field_count = req_fields.length - 1;

            req_fields.forEach((elem, index) => {
                if (!field_already_exist.find(f => f == elem) && permitted_fields.find(q => q == elem)) {
                    if (index == req_field_count) {
                        query += `${elem} `;

                    } else {
                        query += `${elem}, `;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                query = 'SELECT categoryID, continentID, countryID, regionID, featuredImageURL, ' +
                    'title, highlight, content, time FROM articles WHERE articleID = ?';

            } else {
                query += 'FROM articles WHERE articleID = ?';
            }

        } else { // no fields selection
            query += 'categoryID, continentID, countryID, regionID, featuredImageURL, ' +
                'title, highlight, content, time FROM articles WHERE articleID = ?';
        }

        // get publication saved to draft
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

            // send result to client
            res.status(200);
            res.json(results[0]);

            return;

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

    } else { // invalid id
        res.status(400);
        res.json({
            error_code: "invalid_id",
            message: "Bad request"
        });

        return;
    }
});

// search article(s)
router.get('/articles', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // start here
});

router.get('/hellos', custom_utils.allowedScopes(['read:hellos:all']), (req, res) => {
    res.status(200);
    res.send('Welcome you all to REST API version 1');
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