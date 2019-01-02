/*
 * Response server that handle almost all request from client.
 * It's the middle man between client and resources at server end.
 * 
 * Server configuration is in a file "config.json"
 * 
 * Author: Attamah Celestine .C.
 * Date: 12/18/2018
 * 
 */

require('./config/config'); // configure the server and load environmental variables
require('./database/DB'); // load DBMS driver
const fs = require('fs');
const http = require('http');
const express = require('express');
const body_parser = require('body-parser');
const path = require('path');
const logger = require('morgan');
const custom_model = require('./models/custom-model');
const custom_utils = require('./utilities/custom-utils');
const api_route_v1 = require('./routes/api/v1/index.js');
const oauth2 = require('./routes/oauth2');
const app = express();

// create application/x-www-form-urlencoded parser
let urlencoded_parser = body_parser.urlencoded({ extended: false });

// middleware that log incoming request etc
app.use(logger('short'));

// set up public path
let public_path = path.resolve(__dirname, 'public');
app.use(express.static(public_path));

// route for OAuth v2
app.use('/oauth2/v2', oauth2);

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
    console.log(`Proximo server started on port ${gConfig.port}`);
});
