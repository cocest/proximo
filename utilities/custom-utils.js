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
                error_code: "access_token_required",
                message: "Authorization header not defined"
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
                                error_code: "token_expired",
                                message: "Unauthorized"
                            });

                            return;

                        } else {
                            res.status(401);
                            res.json({
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

            // the client doesn't have the needed privilege(s)
            res.status(403);
            res.json({
                status: 403,
                error_code: "insufficient_scope",
                message: "Forbidden"
            });

            return;
        };
    }

    static assignAPIPrivileges(req, allowed_roles, call) {
        const requested_scopes = req.body.scope.trim().split(' ');
        const role = requested_scopes[0].split('.');

        // check if privilege(s) should be assign to this client
        if (!allowed_roles.find(elem => elem == role[0])) {
            return call({ errorCode: 'scope_not_allowed' }, []);
        }

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

    static pointInsideRect(point, bounds) {
        // determine if point is inside pass in rectangle
        if (point.x > bounds[0] && point.x < bounds[2] && point.y > bounds[1] && point.y < bounds[3]) {
            return true;
        }

        return false;
    }

    static pointInsidePolygon(point, polys) {
        // This algorithm use the y-axis to calculate intersection
        // Note: intersection at left side of the point is what is considered
        let int_line_count = 0;
        let t;
        let int_x;
        let point_x = point.x;
        let point_y = point.y;
        let p_x0 = polys[0][0];
        let p_y0 = polys[0][1];
        let p_x1;
        let p_y1;
        let NM;
        let DM;
        let polyline_count = polys.length;

        // iterate the polys
        for (let i = 1; i < polyline_count; i++) {
            p_x1 = polys[i][0];
            p_y1 = polys[i][1];

            // check if line should be skiped by determining if it fall completely at right side
            if (point_x >= p_x0 || point_x >= p_x1) {
                // check if the line should intercept the point y-axis
                if ((point_y <= p_y0 && point_y >= p_y1) || (point_y >= p_y0 && point_y <= p_y1)) {
                    // calculate for intercept
                    DM = p_y0 - p_y1; // denominator

                    if (DM == 0) { // line is horizontal
                        if (p_x0 == point_x || p_x1 == point_x) { // check if point is at line define points
                            return true;

                        } else if ((p_x1 < point_x && p_x0 > point_x) || (p_x0 < point_x && p_x1 > point_x)) {
                            return true;
                        }

                    } else {
                        NM = p_y0 - point_y; // nominator
                        t = NM / DM; // time 
                        int_x = (1 - t) * p_x0 + t * p_x1; // berzier line

                        if (int_x <= point_x) {
                            if (int_x == point_x) {
                                return true;

                            } else if (p_y1 == point_y) {
                                int_line_count++;

                            } else if (p_y0 != point_y) {
                                int_line_count++;
                            }
                        }
                    }
                }
            }

            p_x0 = p_x1;
            p_y0 = p_y1;
        }

        return int_line_count % 2 != 0;
    }

    static pointDistanceFromObj(point, obj) {
        /*
         * determine the distance of a point from polyline or polygon using
         * pythagoras without taking the square root
         * 
         */

        let point_x = point.x;
        let point_y = point.y;
        let d_x = point_x - obj[0][0];
        let d_y = point_y - obj[0][1];
        let r1 = d_x * d_x + d_y * d_y; // distance of point A from point B of object
        let r2;

        for (let i = 1; i < obj.length; i++) {
            d_x = point_x - obj[i][0]; // x component distance
            d_y = point_y - obj[i][1]; // y component distance

            r2 = d_x * d_x + d_y * d_y; // distance of point A from point B of object
            if (r2 < r1) r1 = r2; // replace with smaller distance
        }

        return r1;
    }
}

//export the object that contains the utility functions
module.exports = Utilities;