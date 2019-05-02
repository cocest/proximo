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
const aws = require('aws-sdk');
const sharp = require('sharp');
const file_type = require('file-type');
const smart_crop = require('smartcrop-sharp');

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
                                    url_parse(dm.get(50).Location, true).pathname.replace(`/${gConfig.AWS_S3_BUCKET_NAME}/`, ''),
                                    url_parse(dm.get(120).Location, true).pathname.replace(`/${gConfig.AWS_S3_BUCKET_NAME}/`, ''),
                                    url_parse(dm.get(280).Location, true).pathname.replace(`/${gConfig.AWS_S3_BUCKET_NAME}/`, ''),
                                    req.params.user_id
                                ]
                            ).then(results => {
                                res.status(200);
                                res.json({
                                    images: [{
                                        url: dm.get(280).Location,
                                        size: 'big'
                                    },
                                    {
                                        url: dm.get(120).Location,
                                        size: 'medium'
                                    },
                                    {
                                        url: dm.get(50).Location,
                                        size: 'small'
                                    }
                                    ]
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
                            Objects: [{
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
router.get('/users/:user_id/profile/picture', custom_utils.allowedScopes(['read:user']), (req, res) => {
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

    // check if bio is provided
    if (req.body.bio) {
        query += 'bio = ?, ';
        post.push(req.body.bio.trim());
    }

    // check if about is provided
    if (req.body.about) {
        query += 'about = ? ';
        post.push(req.body.about.trim());
    }

    //last part of query
    query += 'WHERE userID = ? LIMIT 1';
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
            query = 'SELECT bio, about FROM user WHERE userID = ? LIMIT 1';

        } else {
            query += 'FROM user WHERE userID = ? LIMIT 1';
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

    const table_name = publication_type + '_categories';

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
                'SELECT countryID AS id, name AS country FROM map_countries LIMIT ? OFFSET ?', [limit, offset]
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

        } else { //regions
            let query;
            let post;

            // get country to select regions from
            if (country_id) {
                query = 'SELECT regionID AS id, name AS region FROM map_regions WHERE countryID = ? LIMIT ? OFFSET ?';
                post = [country_id, limit, offset];

            } else {
                query = 'SELECT regionID AS id, name AS region FROM map_regions LIMIT ? OFFSET ?';
                post = [limit, offset];
            }

            // select regions from database
            gDB.query(query, post).then(results => {
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

    } else if (!/^(\d+.\d+|\d+)$/.test(req.query.lat)) {
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

    // latitude and longitude
    const position = { x: req.query.lat, y: req.query.long };
    let cont_bounds;
    let cont_polys;
    let temp_cont_polys = [];
    let closest_region;
    let shortest_distance1;
    let shortest_distance2;

    // found which continent user's lat and long fall into
    gDB.query('SELECT continentID, polygons, bounds FROM map_continents').then(continent_results => {
        // check which continet user location fall into
        for (let i = 0; i < results.length; i++) {
            //convert string to javascript object
            cont_bounds = JSON.parse(continent_results[i].bounds);
            cont_polys = JSON.parse(continent_results[i].polygons);

            // check for continent user's position fall into
            if (custom_utils.pointInsideRect(position, cont_bounds) &&
                custom_utils.pointInsidePolygon(position, cont_polys)) {
                // found which country user's lat and long fall into
                gDB.query(
                    'SELECT countryID, polygons, bounds FROM map_countries WHERE continentID = ?',
                    [continent_results[i].continentID]
                ).then(country_results => {
                    // check which country user location fall into
                    for (let j = 0; j < country_results.length; j++) {
                        //convert string to javascript object
                        cont_bounds = JSON.parse(country_results[j].bounds);
                        cont_polys = JSON.parse(country_results[j].polygons);

                        // check for continent user's position fall into
                        if (custom_utils.pointInsideRect(position, cont_bounds) &&
                            custom_utils.pointInsidePolygon(position, cont_polys)) {
                            // found which region user's lat and long fall into
                            gDB.query(
                                'SELECT regionID, name, polygons, bounds FROM map_regions WHERE countryID = ?',
                                [country_results[j].countryID]
                            ).then(region_results => {
                                // check which region user location fall into
                                for (let k = 0; k < region_results.length; k++) {
                                    //convert string to javascript object
                                    cont_bounds = JSON.parse(region_results[k].bounds);
                                    cont_polys = JSON.parse(region_results[k].polygons);

                                    // temporary store the parse polygons
                                    temp_cont_polys.push(cont_polys);

                                    // check for region user's position fall into
                                    if (custom_utils.pointInsideRect(position, cont_bounds) &&
                                        custom_utils.pointInsidePolygon(position, cont_polys)) {
                                        //send user's location to client
                                        res.status(200);
                                        res.json({
                                            location_id: region_results[k].regionID,
                                            location_name: region_results[k].name
                                        });

                                        return;
                                    }
                                }

                                // check for which region is closer to user's location
                                shortest_distance1 = custom_utils.pointDistanceFromObj(position, temp_cont_polys[0]);
                                closest_region = region_results[0];

                                for (let n = 1; n < region_results.length; n++) {
                                    // calculate the distance of region from user's current position
                                    shortest_distance2 = custom_utils.pointDistanceFromObj(position, temp_cont_polys[n]);

                                    // replace with smaller distance
                                    if (shortest_distance2 < shortest_distance1) {
                                        shortest_distance1 = shortest_distance2;
                                        closest_region = region_results[n];
                                    }
                                }

                                // return result of closest region to client
                                res.status(200);
                                res.json({
                                    location_id: closest_region.regionID,
                                    location_name: closest_region.name
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

                    //  service not available at user's location
                    res.status(404);
                    res.json({
                        error_code: "unsupported_location",
                        message: "Service not available at the location"
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

        //  service not available at user's location
        res.status(404);
        res.json({
            error_code: "unsupported_location",
            message: "Service not available at the location"
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
            [req.query.publication + '_categories', req.body.categoryID]
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
                'featuredImageURL, title, highlight, content) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
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
});

/*
 * Add news to draft for edit and return
 * unique id that identified the draft
 * 
 * For already published news, you can't change it location
 */
router.post('/users/:user_id/news/:news_id/edit', custom_utils.allowedScopes(['write:users']), (req, res) => {
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
                    req.query.news_id
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
                    req.query.news_id
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

        // check if highlight is provided
        if (req.body.highlight) {
            query += 'highlight = ?, ';
            post.push(req.body.highlight);
        }

        // check if content is provided
        if (req.body.content) {
            query += 'content = ? ';
            post.push(req.body.content);
        }

        // last part of query
        query += 'WHERE draftID = ? LIMIT 1';
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

    const mappped_field_name = new Map([
        ['publication', 'production'],
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
        const req_field_count = req_fields.length - 1;

        req_fields.forEach((elem, index) => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (index == req_field_count) {
                    query += `${mappped_field_name.get(elem)} `;

                } else {
                    query += `${mappped_field_name.get(elem)}, `;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            query = 'SELECT publication, category, featuredImageURL AS featured_image_url, title, highlight, content, time ' +
                'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';

        } else {
            query += 'FROM draft WHERE draftID = ? AND userID = ? LIMIT 1';
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
        ['publication', 'production'],
        ['category', 'category'],
        ['featuredImageURL', 'featuredImageURL AS featured_image_url'],
        ['title', 'title'],
        ['highlight', 'highlight'],
        ['time', 'time']
    ]);
    let select_query = 'SELECT draftID AS draft_id, ';
    let select_post = [];
    let count_query = 'SELECT COUNT(*) AS total WHERE ';
    let count_post = [];

    // check if valid and required fields is given
    if (req.query.fields) {
        // split the provided fields
        let req_fields = req.query.fields.split(',');
        let permitted_field_count = 0;
        let field_already_exist = [];
        const req_field_count = req_fields.length - 1;

        req_fields.forEach((elem, index) => {
            if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                if (index == req_field_count) {
                    select_query += `${mappped_field_name.get(elem)} `;

                } else {
                    select_query += `${mappped_field_name.get(elem)}, `;
                }

                field_already_exist.push(elem);
                permitted_field_count++; // increment by one
            }
        });

        if (permitted_field_count < 1) {
            select_query = 'SELECT draftID AS draft_id, publication, category, featuredImageURL AS featured_image_url, title, highlight, content, time FROM draft ';

        } else {
            select_query += 'FROM draft ';
        }

    } else { // no fields selection
        select_query += 'publication, category, featuredImageURL AS featured_image_url, title, highlight, content, time FROM draft ';
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

    // set limit and offset
    select_query += 'LIMIT ? OFFSET ? ';
    select_post.push(limit);
    select_post.push(offset);

    // last drafting should come first
    select_query += 'ORDER BY time DESC';

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
router.delete('/users/:user_id/drafts/:draft_id', custom_utils.allowedScopes(['read:users']), (req, res) => {
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

    // delete draft in database
    gDB.query(
        'DELETE FROM draft WHERE draftID = ? AND userID = ? LIMIT 1', 
        [req.params.draft_id, req.params.user_id]
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

// deleting all user's draft
router.delete('/users/:user_id/drafts', custom_utils.allowedScopes(['read:users']), (req, res) => {
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

    // delete all user's draft in database
    gDB.query('DELETE FROM draft WHERE userID = ?', [req.params.draft_id, req.params.user_id]).then(results => {
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

// upload media contents for an news
router.post('/users/:user_id/news/:news_id/medias', custom_utils.allowedScopes(['read:users']), (req, res) => {
    // check if user and article id is integer
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

    // check if article for the user exist
    gDB.query(
        'SELECT 1 FROM news WHERE newsID = ? AND userID = ? LIMIT 1',
        [req.params.news_id, req.params.user_id]
    ).then(results => {
        if (results.length < 1) {
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Publication can't be found"
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
                        Key: 'news/images/big/' + object_unique_name,
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
                            // generate sixten digit unique id
                            const image_id = rand_token.generate(16);
                            const parse_url = url_parse(data.Location, true);

                            // save file metadata and location to database
                            gDB.query(
                                'INSERT INTO news_media_contents (newsID, userID, mediaID, mediaRelativePath, ' +
                                'mediaOriginalName, mediaType, mediaExt) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                [
                                    req.params.news_id,
                                    req.params.user_id,
                                    image_id,
                                    'news/images/big/' + object_unique_name,
                                    file_name,
                                    file_mime.mime.split('/')[0],
                                    save_image_ext,
                                ]
                            ).then(results => {
                                // send result to client
                                res.status(200);
                                res.json({
                                    image_id: image_id,
                                    images: [{
                                        url: data.Location,
                                        size: 'big'
                                    },
                                    {
                                        url: parse_url.origin + '/' + gConfig.AWS_S3_BUCKET_NAME + '/news/images/medium/' + object_unique_name,
                                        size: 'medium'
                                    },
                                    {
                                        url: parse_url.origin + '/' + gConfig.AWS_S3_BUCKET_NAME + '/news/images/small/' + object_unique_name,
                                        size: 'small'
                                    },
                                    {
                                        url: parse_url.origin + '/' + gConfig.AWS_S3_BUCKET_NAME + '/news/images/tiny/' + object_unique_name,
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

// upload media contents for an article
router.post('/users/:user_id/articles/:article_id/medias', custom_utils.allowedScopes(['read:users']), (req, res) => {
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
                message: "Publication can't be found"
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
                        Key: 'article/images/big/' + object_unique_name,
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
                                    'article/images/big/' + object_unique_name,
                                    file_name,
                                    file_mime.mime.split('/')[0],
                                    save_image_ext,
                                ]
                            ).then(results => {
                                // send result to client
                                res.status(200);
                                res.json({
                                    image_id: image_id,
                                    images: [{
                                        url: data.Location,
                                        size: 'big'
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

// publish article or news save to draft and return the id
router.put('/users/:user_id/drafts/:draft_id/publish', custom_utils.allowedScopes(['write:users']), (req, res) => {
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

// retrieve an article
router.get('/articles/:id', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    // check if id is integer
    if (/^\d+$/.test(req.params.id)) {

        const mappped_field_name = new Map([
            ['categoryID', 'categoryID AS category_id'],
            ['continentID', 'continentID AS continent_id'],
            ['countryID', 'countryID AS country_id'],
            ['regionID', 'regionID AS region_id'],
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
            const req_field_count = req_fields.length - 1;

            req_fields.forEach((elem, index) => {
                if (!field_already_exist.find(f => f == elem) && mappped_field_name.get(elem)) {
                    if (index == req_field_count) {
                        query += `${mappped_field_name.get(elem)} `;

                    } else {
                        query += `${mappped_field_name.get(elem)}, `;
                    }

                    field_already_exist.push(elem);
                    permitted_field_count++; // increment by one
                }
            });

            if (permitted_field_count < 1) {
                query = 'SELECT categoryID AS category_id, continentID AS continent_id, countryID AS country_id, ' +
                    'regionID AS region_id, featuredImageURL AS featured_image_url, ' +
                    'title, highlight, content, time FROM articles WHERE articleID = ?';

            } else {
                query += 'FROM articles WHERE articleID = ?';
            }

        } else { // no fields selection
            query += 'categoryID AS category_id, continentID AS continent_id, countryID AS country_id, regionID AS region_id, ' +
                'featuredImageURL AS featured_image_url, title, highlight, content, time FROM articles WHERE articleID = ?';
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

        }).catch(err => {
            res.status(500);
            res.json({
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

// post comment for an article
router.post('/articles/:article_id/comments', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
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

        } else if (req.body.comment.trim().length > 5000) {
            invalid_inputs.push({
                error_code: "invalid_data",
                field: "comment",
                message: "comment exceed maximum allowed text"
            });
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
            'SELECT firstName, lastName, profilePictureSmallURL FROM user WHERE userID = ? LIMIT 1',
            [cmt_results[0].userID]
        ).then(results => {
            // prepare the results
            res.status(200);
            res.json({
                comment: cmt_results[0].comment,
                reply_count: cmt_results[0].replyCount,
                time: cmt_results[0].time,
                user: {
                    name: results[0].lastName + ' ' + results[0].firstName,
                    image: {
                        url: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[0].profilePictureSmallURL,
                        size: 'small'
                    }
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
                'SELECT A.commentID, A.comment, A.replyCount, A.time, B.firstName, B.lastName, B.profilePictureSmallURL ' +
                'FROM article_comments AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ? ' +
                'AND A.replyToCommentID = ? LIMIT ? OFFSET ? ORDER BY A.time DESC',
                [
                    req.params.article_id,
                    -1,
                    limit,
                    offset
                ]
            ).then(results => {
                let comments = [];
                for (let i = 0; i < results.length; i++) {
                    comments.push({
                        comment: results[i].comment,
                        id: results[i].commentID,
                        reply_count: results[i].replyCount,
                        time: results[i].time,
                        user: {
                            name: results[i].lastName + ' ' + results[i].firstName,
                            image: {
                                url: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL,
                                size: 'small'
                            }
                        }
                    });
                }

                // send results to client
                res.status(201);
                res.json({
                    comments: comments,
                    summary: {
                        total_count: cmt_results[0].total
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

// post reply for comment for an article
router.post('/articles/:article_id/comments/:cmt_id/replies', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
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

            } else if (req.body.comment.trim().length > 5000) {
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

// get all the replies for a comment
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
                    'SELECT A.commentID, A.comment, A.replyCount, A.time, B.firstName, B.lastName, B.profilePictureSmallURL ' +
                    'FROM article_comments AS A LEFT JOIN user AS B ON A.userID = B.userID WHERE A.articleID = ? ' +
                    'AND A.replyToCommentID = ? LIMIT ? OFFSET ? ORDER BY A.time DESC',
                    [
                        req.params.article_id,
                        req.params.cmt_id,
                        limit,
                        offset
                    ]
                ).then(results => {
                    let comments = [];
                    for (let i = 0; i < results.length; i++) {
                        comments.push({
                            comment: results[i].comment,
                            id: results[i].commentID,
                            reply_count: results[i].replyCount,
                            time: results[i].time,
                            user: {
                                name: results[i].lastName + ' ' + results[i].firstName,
                                image: {
                                    url: gConfig.AWS_S3_BASE_URL + '/' + gConfig.AWS_S3_BUCKET_NAME + '/' + results[i].profilePictureSmallURL,
                                    size: 'small'
                                }
                            }
                        });
                    }

                    // send results to client
                    res.status(201);
                    res.json({
                        comments: comments,
                        summary: {
                            total_count: cmt_results[0].total
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

router.post('/articles/:article_id/likes', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    //
});

router.post('/articles/:article_id/likes', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    //
});

router.post('/articles/:article_id/dislikes', custom_utils.allowedScopes(['read:articles', 'read:articles:all']), (req, res) => {
    //
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
