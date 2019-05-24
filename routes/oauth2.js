/*
 * This module implement the OAuth 2.0 specification which is a flexibile
 * authorization framework for a number of grants (“methods”)
 * for a client application to acquire an access token (which represents
 * a user’s permission for the client to access their data) which can be
 * used to authenticate a request to an API endpoint.
 *
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: Date: 12/18/2018
 *
 */

const express = require('express');
const body_parser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rand_token = require('rand-token');
const jwt = require('jsonwebtoken');
const custom_utils = require('../utilities/custom-utils');
const router = express.Router();

// parse application/x-www-form-urlencoded parser
router.use(body_parser.urlencoded({ extended: false }));

// check if body is empty
router.use((req, res, next) => {
    if (req.body) {
        return next();

    } else {
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;
    }
});

// check if contents in http body is url encoded
router.use((req, res, next) => {
    if (req.is('application/x-www-form-urlencoded')) {
        return next();

    } else {
        res.status(415);
        res.json({
            error_code: "invalid_request_body",
            message: "Unsupported body format"
        });

        return;
    }
});

// handle authorization code flow part one
router.post('/authorize', (req, res) => {
    // determine authorization
    if (!req.body.response_type) {
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;

    } else if (req.body.response_type == 'code') {
        // code here

    } else {
        res.status(404);
        res.json({
            error_code: "unsupported_authentication",
            message: "Authorization flow not supported"
        });

        return;
    }
});

// handle request for access token
router.post('/token', (req, res) => {
    // determine authorization flow or type
    if (!req.body.grant_type) {
        res.status(400);
        res.json({
            error_code: "invalid_request",
            message: "Bad request"
        });

        return;

    } else if (req.body.grant_type == 'refresh_token') {
        // issue JWT token to user using refresh token
        custom_utils.checkOAuth2TokenCrendentials(req.body.grant_type, req.body, err => {
            if (err) {
                res.status(401);
                res.json({
                    error_code: "incomplete_credentials",
                    message: "Unauthorized"
                });

                return;

            } else {
                try {
                    // decrypt refresh token
                    let encryptedText = Buffer.from(req.body.refresh_token, 'hex');
                    let decipher = crypto.createDecipheriv(
                        'aes-256-cbc',
                        Buffer.from(Buffer.from(gConfig.REFRESH_TOKEN_ENCRYPT_SECRET, 'hex')),
                        Buffer.from(gConfig.REFRESH_TOKEN_ENCRYPT_IV, 'hex')
                    );
                    let decrypted = decipher.update(encryptedText);
                    decrypted = Buffer.concat([decrypted, decipher.final()]);
                    let decrypted_rf_token = decrypted.toString();

                    // get refresh token from database
                    gDB.query(
                        'SELECT * FROM apirefreshtoken WHERE clientID = ? AND refreshToken = ? LIMIT 1',
                        [req.body.client_id, decrypted_rf_token]
                    ).then(results => {
                        if (results.length < 1) {
                            res.status(401);
                            res.json({
                                error_code: "authentication_required",
                                message: "Unauthorized"
                            });

                            return;

                        } else {
                            // check if refresh token hasn't expired
                            let lasted_days = (Date.now() / 1000 - results[0].time) / 86400;

                            if (lasted_days > gConfig.REFRESH_TOKEN_EXPIRE_IN) {
                                res.status(401);
                                res.json({
                                    error_code: "refresh_token_expired",
                                    message: "Unauthorized"
                                });

                                // Refresh token has expired. Remove from database
                                gDB.query(
                                    'DELETE FROM apirefreshtoken WHERE clientID = ? AND refreshToken = ? LIMIT 1',
                                    [req.body.client_id, decrypted_rf_token]

                                ).catch(reason => {
                                    // log the error to log file
                                    gLogger.log('error', reason.message, { stack: reason.stack });

                                    return;
                                });

                            } else {
                                // generate new access token
                                let expires_in = Math.floor(Date.now() / 1000) + (60 * 10); //valid for 10 minutes

                                jwt.sign({
                                    iss: gConfig.JWT_ISSUER,
                                    exp: expires_in,
                                    role: results[0].role,
                                    user_id: results[0].userID,
                                    scopes: results[0].assignedScopes.trim().split(' ')
                                },

                                    gConfig.JWT_ENCRYPT_SECRET,

                                    {
                                        algorithm: 'HS256'
                                    },

                                    (err, token) => { // call back function
                                        if (err) {
                                            res.status(500);
                                            res.json({
                                                error_code: "internal_error",
                                                message: "Internal error"
                                            });

                                            // log the error to log file
                                            gLogger.log('error', err.message, { stack: err.stack });

                                            return;

                                        } else {
                                            // send the JWT token to requester
                                            res.status(200);
                                            res.json({
                                                token_type: 'Bearer',
                                                expires_in: expires_in,
                                                access_token: token
                                            });

                                            return;
                                        }
                                    }
                                );
                            }
                        }

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

                } catch (er) {
                    if (er.message == 'Bad input string') {
                        res.status(401);
                        res.json({
                            error_code: "unauthorized_client",
                            message: "Unauthorized"
                        });

                        return;

                    } else {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', er.message, { stack: er.stack });

                        return;
                    }
                }
            }
        });

    } else if (req.body.grant_type == 'authorization_code') {
        // code here

    } else if (req.body.grant_type == 'password') {
        // issue JWT token to user using "Resource owner credentials grant"
        custom_utils.checkOAuth2TokenCrendentials(req.body.grant_type, req.body, err => {
            if (err) {
                res.status(401);
                res.json({
                    error_code: "incomplete_credentials",
                    message: "Unauthorized"
                });

                return;

            } else {
                // get client credentials
                gDB.query(
                    'SELECT clientSecret, permittedGrants FROM registeredapplication WHERE clientID = ? LIMIT 1',
                    [req.body.client_id]
                ).then(results => {
                    if (results.length < 1) {
                        res.status(401);
                        res.json({
                            error_code: "unauthorized_client",
                            message: "Unauthorized"
                        });

                        return;

                    } else {
                        // compare client_secret to hash in database
                        bcrypt.compare(req.body.client_secret, results[0].clientSecret).then(hash_res => {
                            if (!hash_res) {
                                res.status(401);
                                res.json({
                                    error_code: "unauthorized_client",
                                    message: "Unauthorized"
                                });

                                return;

                            } else {
                                // check if client is allow to use this authorization process
                                if (!results[0].permittedGrants.trim().split(' ').find(g => g == 'password')) {
                                    res.status(401);
                                    res.json({
                                        error_code: "authorization_not_allowed",
                                        message: "Unauthorized"
                                    });

                                    return;

                                } else {
                                    // generate hash of 40 characters length from user's email address 
                                    let search_email_hash = crypto.createHash("sha1").update(req.body.username, "binary").digest("hex");

                                    // validate user credentials
                                    gDB.query(
                                        'SELECT userID, password FROM userauthentication WHERE searchEmailHash = ? LIMIT 1',
                                        [search_email_hash]

                                    ).then(results => {
                                        if (results.length < 1) {
                                            res.status(401);
                                            res.json({
                                                error_code: "unauthorized_user",
                                                message: "Unauthorized"
                                            });

                                            return;

                                        } else {
                                            // compare password to hash in database
                                            bcrypt.compare(req.body.password, results[0].password).then(hash_res => {
                                                if (!hash_res) {
                                                    res.status(401);
                                                    res.json({
                                                        error_code: "unauthorized_user",
                                                        message: "Unauthorized"
                                                    });

                                                    return;

                                                } else {
                                                    // get access scope(s) or permission
                                                    custom_utils.assignAPIPrivileges(req, ['user'], (err, assign_scopes) => {
                                                        if (err) {
                                                            if (err.errorCode == 'scope_not_allowed') {
                                                                res.status(403);
                                                                res.json({
                                                                    error_code: "scope_not_allowed",
                                                                    message: "Your are not allowed to use this scope"
                                                                });

                                                                return;

                                                            } else if (err.errorCode == 'invalid_scope_definition') {
                                                                res.status(400);
                                                                res.json({
                                                                    error_code: "invalid_scope_definition",
                                                                    message: "Bad request"
                                                                });

                                                                return;

                                                            } else if (err.errorCode == 'internal_error') {
                                                                res.status(500);
                                                                res.json({
                                                                    error_code: "internal_error",
                                                                    message: "Internal error"
                                                                });

                                                                // log the error to log file
                                                                gLogger.log('error', err.message, { stack: err.stack });

                                                                return;
                                                            }

                                                        } else {
                                                            let role = req.body.scope.trim().split(' ')[0].split('.')[0];
                                                            let expires_in = Math.floor(Date.now() / 1000) + (60 * 10); //valid for 10 minutes

                                                            jwt.sign({
                                                                iss: gConfig.JWT_ISSUER,
                                                                exp: expires_in,
                                                                role: role,
                                                                user_id: results[0].userID,
                                                                scopes: assign_scopes
                                                            },

                                                                gConfig.JWT_ENCRYPT_SECRET,

                                                                {
                                                                    algorithm: 'HS256'
                                                                },

                                                                (err, token) => { // call back function
                                                                    if (err) {
                                                                        res.status(500);
                                                                        res.json({
                                                                            error_code: "internal_error",
                                                                            message: "Internal error"
                                                                        });

                                                                        // log the error to log file
                                                                        gLogger.log('error', err.message, { stack: err.stack })

                                                                        return;

                                                                    } else {
                                                                        // user ID
                                                                        let user_id = results[0].userID;

                                                                        // get client refresh token if it exist
                                                                        gDB.query(
                                                                            'SELECT refreshToken, time FROM apirefreshtoken WHERE userID = ? AND clientID = ? LIMIT 1',
                                                                            [user_id, req.body.client_id]
                                                                        ).then(results => {
                                                                            // check if refresh token exist and hasn't expired
                                                                            if (results.length > 0 && ((Date.now() / 1000 - results[0].time) / 86400) < gConfig.REFRESH_TOKEN_EXPIRE_IN) {
                                                                                try {
                                                                                    // encrypt the refresh token again
                                                                                    let cipher = crypto.createCipheriv(
                                                                                        'aes-256-cbc',
                                                                                        Buffer.from(Buffer.from(gConfig.REFRESH_TOKEN_ENCRYPT_SECRET, 'hex')),
                                                                                        Buffer.from(gConfig.REFRESH_TOKEN_ENCRYPT_IV, 'hex')
                                                                                    );
                                                                                    let encrypted = cipher.update(results[0].refreshToken);
                                                                                    encrypted = Buffer.concat([encrypted, cipher.final()]);
                                                                                    let encrypted_token = encrypted.toString('hex');

                                                                                    // send the JWT token to requester
                                                                                    res.status(200);
                                                                                    res.json({
                                                                                        token_type: 'Bearer',
                                                                                        expires_in: expires_in,
                                                                                        access_token: token,
                                                                                        refresh_token: encrypted_token,
                                                                                        user_id: user_id
                                                                                    });

                                                                                    return;

                                                                                } catch (er) { // catch the error just in case the crypto fail
                                                                                    res.status(500);
                                                                                    res.json({
                                                                                        error_code: "internal_error",
                                                                                        message: "Internal error"
                                                                                    });

                                                                                    // log the error to log file
                                                                                    gLogger.log('error', er.message, { stack: er.stack });

                                                                                    return;
                                                                                }
                                                                            }

                                                                            // generate refresh token
                                                                            let refresh_token = rand_token.generate(32);

                                                                            try {
                                                                                // encrypt the refresh token
                                                                                let cipher = crypto.createCipheriv(
                                                                                    'aes-256-cbc',
                                                                                    Buffer.from(Buffer.from(gConfig.REFRESH_TOKEN_ENCRYPT_SECRET, 'hex')),
                                                                                    Buffer.from(gConfig.REFRESH_TOKEN_ENCRYPT_IV, 'hex')
                                                                                );
                                                                                let encrypted = cipher.update(refresh_token);
                                                                                encrypted = Buffer.concat([encrypted, cipher.final()]);
                                                                                let encrypted_token = encrypted.toString('hex');

                                                                                // check if refresh token doesn't exit
                                                                                if (results.length < 1) {
                                                                                    // store refresh token to database
                                                                                    gDB.query(
                                                                                        'INSERT INTO apirefreshtoken (userID, clientID, refreshToken, role, assignedScopes) VALUES (?, ?, ?, ?, ?)',
                                                                                        [user_id, req.body.client_id, refresh_token, role, assign_scopes.join(' ')]
                                                                                    ).then(results => {
                                                                                        // send the JWT token to requester
                                                                                        res.status(200);
                                                                                        res.json({
                                                                                            token_type: 'Bearer',
                                                                                            expires_in: expires_in,
                                                                                            access_token: token,
                                                                                            refresh_token: encrypted_token,
                                                                                            user_id: user_id
                                                                                        });

                                                                                        return;

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

                                                                                } else { // refresh token has expired
                                                                                    // update refresh token in database
                                                                                    gDB.query(
                                                                                        'UPDATE apirefreshtoken SET refreshToken = ?, role = ?, assignedScopes = ? WHERE userID = ? AND clientID = ? LIMIT 1',
                                                                                        [refresh_token, role, assign_scopes.join(' '), user_id, req.body.client_id]
                                                                                    ).then(results => {
                                                                                        // send the JWT token to requester
                                                                                        res.status(200);
                                                                                        res.json({
                                                                                            token_type: 'Bearer',
                                                                                            expires_in: expires_in,
                                                                                            access_token: token,
                                                                                            refresh_token: encrypted_token,
                                                                                            user_id: user_id
                                                                                        });

                                                                                        return;

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
                                                                                }

                                                                            } catch (er) { // catch the error just in case the crypto fail
                                                                                res.status(500);
                                                                                res.json({
                                                                                    error_code: "internal_error",
                                                                                    message: "Internal error"
                                                                                });

                                                                                // log the error to log file
                                                                                gLogger.log('error', er.message, { stack: er.stack });

                                                                                return;
                                                                            }

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
                                                                    }
                                                                }
                                                            );
                                                        }
                                                    });
                                                }

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
                                        }

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
                                }
                            }

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
                    }

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
            }
        });

    } else if (req.body.grant_type == 'client_credentials') {
        // issue JWT token to user using "Client credentials grant"
        custom_utils.checkOAuth2TokenCrendentials(req.body.grant_type, req.body, err => {
            if (err) {
                res.status(401);
                res.json({
                    error_code: "incomplete_credentials",
                    message: "Unauthorized"
                });

                return;

            } else {
                // get client credentials
                gDB.query(
                    'SELECT clientSecret, permittedGrants FROM registeredapplication WHERE clientID = ? LIMIT 1',
                    [req.body.client_id]
                ).then(results => {
                    if (results.length < 1) {
                        res.status(401);
                        res.json({
                            error_code: "unauthorized_client",
                            message: "Unauthorized"
                        });

                        return;

                    } else {
                        // compare client_secret to hash in database
                        bcrypt.compare(req.body.client_secret, results[0].clientSecret).then(hash_res => {
                            if (!hash_res) {
                                res.status(401);
                                res.json({
                                    error_code: "unauthorized_client",
                                    message: "Unauthorized"
                                });

                                return;

                            } else {
                                // check if client is allow to use this authorization process
                                if (!results[0].permittedGrants.trim().split(' ').find(g => g == 'client_credentials')) {
                                    res.status(401);
                                    res.json({
                                        error_code: "authorization_not_allowed",
                                        message: "Unauthorized"
                                    });

                                    return;

                                } else {
                                    // get access scope(s) or permission
                                    custom_utils.assignAPIPrivileges(req, ['client'], (err, assign_scopes) => {
                                        if (err) {
                                            if (err.errorCode == 'scope_not_allowed') {
                                                res.status(403);
                                                res.json({
                                                    error_code: "scope_not_allowed",
                                                    message: "Your are not allowed to use this scope"
                                                });

                                                return;

                                            } else if (err.errorCode == 'invalid_scope_definition') {
                                                res.status(400);
                                                res.json({
                                                    error_code: "invalid_scope_definition",
                                                    message: "Bad request"
                                                });

                                                return;

                                            } else if (err.errorCode == 'internal_error') {
                                                res.status(500);
                                                res.json({
                                                    error_code: "internal_error",
                                                    message: "Internal error"
                                                });

                                                // log the error to log file
                                                gLogger.log('error', err.message, { stack: err.stack });

                                                return;
                                            }

                                        } else {
                                            let role = req.body.scope.trim().split(' ')[0].split('.')[0];
                                            let expires_in = Math.floor(Date.now() / 1000) + (60 * 10); // valid for 10 minutes

                                            jwt.sign({
                                                iss: gConfig.JWT_ISSUER,
                                                exp: expires_in,
                                                role: role,
                                                user_id: req.body.client_id,
                                                scopes: assign_scopes
                                            },

                                                gConfig.JWT_ENCRYPT_SECRET,

                                                {
                                                    algorithm: 'HS256'
                                                },

                                                (err, token) => { // call back function
                                                    if (err) {
                                                        res.status(500);
                                                        res.json({
                                                            error_code: "internal_error",
                                                            message: "Internal error"
                                                        });

                                                        // log the error to log file
                                                        gLogger.log('error', err.message, { stack: err.stack })

                                                        return;

                                                    } else {
                                                        // send the JWT token to requester
                                                        res.status(200);
                                                        res.json({
                                                            token_type: 'Bearer',
                                                            expires_in: expires_in,
                                                            access_token: token
                                                        });

                                                        return;
                                                    }
                                                }
                                            );
                                        }
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
                            gLogger.log('error', reason.message, { stack: reason.stack });

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
                    gLogger.log('error', reason.message, { stack: reason.stack });

                    return;
                });
            }
        });

    } else {
        res.status(404);
        res.json({
            error_code: "unsupported_authentication",
            message: "Authorization flow not supported"
        });

        return;
    }
});

module.exports = router;