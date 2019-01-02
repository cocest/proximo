/*
 * REST API VERSION 1
 */

const express = require('express');
const custom_utils = require('../../../utilities/custom-utils');
const body_parser = require('body-parser');
const zxcvbn = require('zxcvbn');
const validator = require('validator');
const router = express.Router();

// check and validate access token (JWT)
router.use(custom_utils.validateToken);

// parse application/json
router.use(body_parser.json());

// create new user
router.post('/users', custom_utils.checkScopes(['write:users:all']), (req, res) => {
    if (!req.is('application/json')) { // check if content type is supported
        res.status(415);
        res.json({
            status: 415,
            error_code: "unsupported_format",
            message: "Unsupported Media Type"
        });

        return;

    } else {
        // check if these fields are provided and valid: 
        // firstName, lastName, email and password is needed

        if (req.body.firstName && /^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.firstName)) {
            //
        }

        if (req.body.lastName && /^[a-zA-Z]+[']?[a-zA-Z]+$/.test(req.body.lastName)) {
            //
        }

        if (req.body.password && zxcvbn(req.body.password).score > 1) {
            //
        }

        if (req.body.gender && /^(male|female|other)$/.test(req.body.gender)) {
            //
        }

        if (req.body.email && validator.isEmail(req.body.email)) {
            // check if email has been used by another user
            gDB.query(
                'INSERT IGNORE INTO user (firstName, lastName, emailAddress, gender) VALUES(?, ?, ?, ?)',
                [req.body.firstName, req.body.lastName, req.body.email, req.body.gender],
                (err, results) => {
                    if (err) {
                        //log the error to log file
                        //code here

                        return;

                    } else if (results.affectedRows > 0){  // check if row is effected. If not, email already exist
                        // start here
                    }
                });
        }

        // return success message here
    }
});

router.get('/hellos', custom_utils.checkScopes(['read:hellos:all']), (req, res) => {
    res.status(200);
    res.send('Welcome you all to REST API version 1');
});

router.get(/^\/hellos\/(\d+)$/, custom_utils.checkScopes(['read:hellos', 'read:hellos:all']), (req, res) => {
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
        res.send('Welcome to REST API version 1');
    }
});

module.exports = router;