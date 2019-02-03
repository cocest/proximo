/*
 * REST API VERSION 1
 */

const express = require('express');
const custom_utils = require('../../../utilities/custom-utils');
const path = require('path');
const body_parser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rand_token = require('rand-token');
const zxcvbn = require('zxcvbn');
const node_mailer = require('nodemailer');
const validator = require('validator');
const ejs = require('ejs');

const router = express.Router();

// check and validate access token (JWT)
router.use(custom_utils.validateToken);

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
            status: 400,
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            status: 415,
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;

    } else {
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
                status: 406,
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
                        status: 406,
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
                                        status: 201,
                                        user_id: results[0].userID,
                                        message: "New user created successfully"
                                    });

                                    return;
                                });
                            })
                            .catch(reason => {
                                res.status(500);
                                res.json({
                                    status: 500,
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', reason.message, {stack: reason.stack});

                                return;
                            });

                    }).catch(reason => {
                        res.status(500);
                        res.json({
                            status: 500,
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log(gLogger.log('error', reason.message, {stack: reason.stack}));

                        return;
                    });
                }

            }).catch(reason => {
                res.status(500);
                res.json({
                    status: 500,
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log(gLogger.log('error', reason.message, {stack: reason.stack}));

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
                status: 406,
                error_code: "invalid_field",
                errors: invalid_inputs,
                message: "Field(s) value not acceptable"
            });

            return;
        }
    }
});

// validate registration fields or inputs
router.post('/users/validateSignUpInputs', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
    if (!req.body) { // check if body contain data
        res.status(400);
        res.json({
            status: 400,
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            status: 415,
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
                        status: 406,
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
                    status: 500,
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log(gLogger.log('error', reason.message, {stack: reason.stack}));

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
                status: 406,
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
                    status: 406,
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
                    status: 404,
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
                            status: 500,
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log(gLogger.log('error', err.message, {stack: err.stack}));

                        return;
                    }

                    // reply is null when the key is missing
                    if (reply) { // key exist
                        res.status(425);
                        res.json({
                            status: 425,
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
                                    status: 500,
                                    error_code: "internal_error",
                                    message: "Message can't be sent"
                                });

                                // log the error to log file
                                gLogger.log(gLogger.log('error', err.message, {stack: err.stack}));

                                return;

                            } else {
                                // check if email is rejected
                                if (info.rejected.length > 0) {
                                    res.status(500);
                                    res.json({
                                        status: 500,
                                        error_code: "internal_error",
                                        message: "Email was rejected by the server"
                                    });

                                    return;

                                } else { // email sent successfully
                                    // expiration set to 10 minutes
                                    let code_expiration = 60 * 10;

                                    // store the verification code to database (redis) with
                                    gRedisClient.set(access_key, verification_code, 'EX', 60 * 10, (err, replay) => {
                                        if (err) {
                                            res.status(500);
                                            res.json({
                                                status: 500,
                                                error_code: "internal_error",
                                                message: "Internal error"
                                            });

                                            // log the error to log file
                                            gLogger.log(gLogger.log('error', err.message, {stack: err.stack}));

                                            return;

                                        } else {
                                            res.status(200);
                                            res.json({
                                                status: 200,
                                                code_expiration: code_expiration
                                            });

                                            return;
                                        }
                                    });
                                }
                            }
                        });
                    }
                });

            } else { // account is already activated
                res.status(409);
                res.json({
                    status: 409,
                    error_code: "already_processed",
                    message: "Action has been performed"
                });

                return;
            }

        }).catch(reason => {
            res.status(500);
            res.json({
                status: 500,
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
            status: 400,
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
            status: 400,
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }

    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            status: 415,
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;

    } else {
        // check if id is interger
        if (/^\d+$/.test(req.params.id)) {
            if (!req.body.code) {
                res.status(400);
                res.json({
                    status: 400,
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
                        status: 500,
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    gLogger.log(gLogger.log('error', err.message, {stack: err.stack}));

                    return;
                }

                // reply is null when the key is missing
                if (!reply) { // key doesn't exist
                    res.status(404);
                    res.json({
                        status: 404,
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
                                status: 500,
                                error_code: "internal_error",
                                message: "Internal error"
                            });

                            // log the error to log file
                            gLogger.log(gLogger.log('error', reason.message, {stack: reason.stack}));

                            return;
                        });

                    } else { // activation code supplied by user is wrong
                        res.status(406);
                        res.json({
                            status: 406,
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
                status: 400,
                error_code: "invalid_user_id",
                message: "Bad request"
            });

            return;
        }
    }
});

router.get('/hellos', custom_utils.allowedScopes(['read:hellos:all']), (req, res) => {
    res.status(200);
    res.send('Welcome you all to REST API version 1');
});

router.get(/^\/hellos\/(\d+)$/, custom_utils.allowedScopes(['read:hellos', 'read:hellos:all']), (req, res) => {
    const token_user_id = parseInt(req.user.access_token.user_id, 10);
    const user_id = parseInt(req.params[0], 10);

    // check if is accessing the right user or logged in user
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