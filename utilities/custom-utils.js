/*
 * Utitlies or helper function for Proximo
 *
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: __/__/__
 * 
 */

const jwt = require('jsonwebtoken');
const validator = require('validator');
const model = require('../models/custom-model');

class Utilities {

    static daysInMonth(m, y) { // m is 0 indexed: 0-11
        switch (m) {
            case 1:
                return (y % 4 == 0 && y % 100) || y % 400 == 0 ? 29 : 28;

            case 8: 
            case 3: 
            case 5: 
            case 10:
                return 30;

            default:
                return 31;
        }
    }

    static validateDate(date) {
        if (!(/^[1-9][0-9]{3}$/.test(date.year) &&
                parseInt(date.year) <= (new Date()).getFullYear())) {

            return false;
        }

        if (!/^([1-9]|[1][0-2])$/.test(date.month)) {
            return false;
        }

        if (!/^([1-9]|[1-2][0-9]|[3][0-1])$/.test(date.day)) {
            return false;

        } else if (parseInt(date.day) > Utilities.daysInMonth(parseInt(date.month) - 1, parseInt(date.year))) {
            return false;
        }

        return true;
    }

    static checkOAuth2TokenCrendentials(grantType, body, call) {
        // check required crendential
        switch (grantType) {
            case 'password':
                if (body.client_id && body.client_secret && body.scope && body.username && body.password) {
                    call(null);

                } else {
                    call(new Error('Credentials not complete'));
                }

                break;

            case 'client_credentials':
                if (body.client_id && body.client_secret && body.scope) {
                    call(null);

                } else {
                    call(new Error('Credentials not complete'));
                }

                break;

            case 'refresh_token':
                if (body.client_id && body.refresh_token) {
                    call(null);

                } else {
                    call(new Error('Credentials not complete'));
                }

                break;

            default:
                // you shouldn't be here
                break;
        }
    }

    static validateToken(req, res, next) {
        const auth_header = req.headers.authorization;

        // get access token from header
        if (!auth_header) {
            res.status(403);
            res.json({
                status: 403,
                error_code: "invalid_request",
                message: "Forbidden"
            });

            return;

        } else {
            // extract values
            const [token_type, token] = auth_header.trim().split(' ');

            if (token_type == 'Bearer' && token) {
                // validation access
                jwt.verify(token, gConfig.JWT_ENCRYPT_SECRET, {
                    algorithms: ['HS256'],
                    issuer: gConfig.JWT_ISSUER
                }, (err, decoded) => {
                    if (err) {
                        // check if token has expired error
                        if (err.name == 'TokenExpiredError') {
                            res.status(401);
                            res.json({
                                status: 401,
                                error_code: "token_expired",
                                message: "Unauthorized"
                            });

                            return;

                        } else {
                            res.status(401);
                            res.json({
                                status: 401,
                                error_code: "invalid_token",
                                message: "Unauthorized"
                            });

                            return;
                        }

                    } else { // token validated successfully
                        // attach decoded JWT token to request
                        if (!req.user) {
                            req.user = {
                                access_token: decoded
                            };

                        } else {
                            req.user.access_token = decoded;
                        }

                        next(); // move to next
                    }
                });

            } else {
                res.status(400);
                res.json({
                    status: 400,
                    error_code: "invalid_authorization_header",
                    message: "Bad request"
                });

                return;
            }
        }
    }

    static allowedScopes(scopes) {
        return (req, res, next) => {
            // validate scopes
            const token_scopes = req.user.access_token.scopes;

            // iterate the two array
            for (let i = 0; i < scopes.length; i++) {
                for (let j = 0; j < token_scopes.length; j++) {
                    if (scopes[i] == token_scopes[j]) {
                        return next();
                    }
                }
            }

            // the scopes doesn't have the needed privilege(s)
            res.status(403);
            res.json({
                status: 403,
                error_code: "insufficient_scope",
                message: "Forbidden"
            });

            return;
        }
    }

    static assignAPIPrivileges(req, call) {
        const requested_scopes = req.body.scope.trim().split(' ');
        const role = requested_scopes[0].split('.');

        if (role[0] == 'user' || role[0] == 'client') {
            if (!(role[1] == 'default' || role[1] == 'defined')) {
                return call({
                    errorCode: 'invalid_scope_definition'
                }, []);

            } else {
                gDB.query('SELECT scopes FROM apiprivileges WHERE role = ? LIMIT 1', [role[0]]).then(results => {
                    if (results.length < 1) {
                        return call({
                            errorCode: 'internal_error'
                        }, []);

                    } else {
                        const default_scopes = results[0].scopes.trim().split(' ');
                        const granted_scopes = [];

                        if (role[1] == 'default') {
                            return call(null, default_scopes);

                        } else { //defined
                            requested_scopes.forEach(scope => {
                                for (let i = 0; i < default_scopes.length; i++) {
                                    if (default_scopes[i] == scope) {
                                        granted_scopes.push(scope);
                                    }
                                }
                            });

                            return call(null, granted_scopes);
                        }
                    }

                }).catch(reason => {
                    return call({
                        errorCode: 'internal_error'
                    }, []);
                });
            }

        } else if (role[0] == 'admin') {
            // code here

        } else {
            return call({
                errorCode: 'invalid_scope_definition'
            }, []);
        }
    }
}

//export the object that contains the utility functions
module.exports = Utilities;