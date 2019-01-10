/*
 * REST API VERSION 1
 */

const express = require('express');
const custom_utils = require('../../../utilities/custom-utils');
const body_parser = require('body-parser');
const bcrypt = require('bcrypt');
const zxcvbn = require('zxcvbn');
const validator = require('validator');
const router = express.Router();

// check and validate access token (JWT)
router.use(custom_utils.validateToken);

// parse application/json
router.use(body_parser.json());

// create new user
router.post('/users', custom_utils.allowedScopes(['write:users:all']), (req, res) => {
    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            status: 415,
            error_code: "unsupported_format",
            message: "Unsupported media type"
        });

        return;

    } else {
        // check if these fields are provided and valid: 
        // firstName, lastName, email, password and gender.

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
            // check if email doesn't exist
            gDB.query('SELECT 1 FROM user WHERE emailAddress = ? LIMIT 1', [req.body.email], (err, results) => {
                if (err) {
                    res.status(500);
                    res.json({
                        status: 500,
                        error_code: "internal_error",
                        message: "Internal error"
                    });

                    // log the error to log file
                    //code here

                    return;

                } else {
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
                            // store user's information to database
                            gDB.transaction({
                                    query: 'INSERT INTO user (firstName, lastName, emailAddress, gender) VALUES (?, ?, ?, ?)',
                                    post: [
                                        req.body.firstName,
                                        req.body.lastName,
                                        req.body.email,
                                        req.body.gender
                                    ]
                                }, {
                                    query: 'SELECT @user_id:=userID FROM user WHERE emailAddress = ?',
                                    post: [req.body.email]
                                }, {
                                    query: 'INSERT INTO userauthentication (userID, emailAddress, password) VALUES (@user_id, ?, ?)',
                                    post: [
                                        req.body.email,
                                        hash
                                    ]
                                })
                                .then(results => {
                                    res.status(201);
                                    res.json({
                                        status: 201,
                                        message: "New user created successfully"
                                    });

                                    return;
                                })
                                .catch(reason => {
                                    res.status(500);
                                    res.json({
                                        status: 500,
                                        error_code: "internal_error",
                                        message: "Internal error"
                                    });

                                    // log the error to log file
                                    //code here

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
                            //code here

                            return;
                        });
                    }
                }
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