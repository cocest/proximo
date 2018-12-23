/*
 * Response server that handle almost all request from client.
 * It's the middle man between client and resources at server end.
 * 
 * Server configuration is in a file "server_config.json"
 * 
 * Author: Attamah Celestine .C.
 * Date: 12/18/2018
 * 
 */

const fs = require('fs');
const app_config = require('./config/config');
const http = require('http');
const express = require('express');
const body_parser = require('body-parser');
const path = require('path');
const logger = require('morgan');
const crypto = require('crypto');
const rand_token = require('rand-token');
const jwt = require('jsonwebtoken');
const proximo_utils = require('./utilities/proximo-utils');
const api_route_v1 = require('./routes/api/v1/index.js');
const app = express();

// issue JWT token to user using "Resource owner credentials grant"

// create application/x-www-form-urlencoded parser
let urlencoded_parser = body_parser.urlencoded({ extended: false });

// middleware that log incoming request etc
app.use(logger('short'));

// set up public path
let public_path = path.resolve(__dirname, 'public');
app.use(express.static(public_path));

// handle request for access token
app.post('/oauth2/v1/token', urlencoded_parser, (req, res) => {
    if (req.body) {
        if (req.body.grant_type == "password") {
            // validate client crendentials
            proximo_utils.compareToHashDataInDB(
                'apiclientauthentication', // table name
                [{ column: 'clientID', search: req.body.client_id }], // search array
                req.body.client_secret // client secret

            ).then((value) => { // client validated successfully
                // validate user crendentials
                proximo_utils.compareToHashDataInDB(
                    'usersauth', // table name
                    [{ column: 'id', search: req.body.username }], // search array
                    req.body.password // password

                ).then((value) => { // user validated successfully
                    //generate id for this JWT token
                    let jwt_id = rand_token.generate(32);
                    let expires_in = Math.floor(Date.now() / 1000) + 86400 * 30;  //valid for thirty days

                    jwt.sign(
                        {
                            iss: gConfig.JWT_ISSUER,
                            jti: jwt_id,
                            exp: expires_in,
                        },

                        gConfig.JWT_ENCRYPTION_SECRET,

                        { algorithm: 'HS256' },

                        (err, token) => { //call back function
                            if (!err) {
                                //store jwt_id to database
                                //code here

                                //send the JWT token to requester
                                res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
                                res.end(
                                    JSON.stringify(
                                        {
                                            token_type: 'Bearer',
                                            expires_in: expires_in,
                                            access_token: token
                                        }
                                    )
                                );

                                console.log('JWT issued token: ' + token);
                            } else {
                                //log the error
                                //code here

                                //send the error to requester
                                res.status(500);
                                res.send('internal error has occurred at the service.');
                            }
                        }
                    );

                }).catch((err) => {
                    res.status(403);
                    res.send('Invalid user credentials');
                });

            }).catch((err) => { // error occured
                res.status(403);
                res.send('Invalid client credentials');
            });

        } else {
            res.status(400);
            res.send('Grant type not supported.');
        }

    } else {
        res.sendStatus(400);
    }
});

// route for API version 1
app.use('/api/v1', api_route_v1);

// logs error
app.use((error, req, res, next) => {
    console.error(error.toString() + '\n'); // log error to console

    // write the error to file
    let file = fs.appendFile('./logs/error_log.txt', error.toString() + '\n', err => {
        if (err != null) {
            next(err);
        } else {
            next();
        }
    });
});

// handle server error
app.use((err, req, res, next) => {
    res.status(500);
    res.send("Internal server error.");
});

// handle page not found
app.use((req, res) => {
    res.status(404);
    res.send('File not found');
});

//start listening on provided port
http.createServer(app).listen(gConfig.port, () => {
    console.log(`Proximo RS server started on port ${gConfig.port}`);
});
