/*
 * Response server that handle almost all request from client.
 * It's the middle man between client and resources at server end.
 * 
 * Server configuration is in a folder "config"
 * 
 * Author: Attamah Celestine .C.
 * Date: 12/18/2018
 * 
 */

//require('dotenv').config(); // don't commit this to github repository
require('./config/config'); // configure the server and load environmental variables
require('./config/logger'); // add logger to global
require('./database/rdbms/DB'); // load DBMS driver
require('./database/nosql/REDIS'); // load Redis client
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
let urlencoded_parser = body_parser.urlencoded({extended: false});

// only on development mode
if (process.env.NODE_ENV != 'production') {
    app.use(logger('short')); // middleware that log incoming request etc
}

// set up public path
let public_path = path.resolve(__dirname, 'public');
app.use(express.static(public_path));

// route for OAuth v2
app.use('/oauth2/v1', oauth2);

// route for API version 1
app.use('/api/v1', api_route_v1);

// logs error
app.use((err, req, res, next) => {
    gLogger.log('error', err.message, {stack: err.stack});
    next(err);
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

// validate user credentials
/*gDB.query('SELECT MAX(categoryID) AS maxUserID FROM newscategories', (err, results) => {
    console.log(results);
});*/

//start listening on provided port
http.createServer(app).listen(gConfig.port, () => {
    console.log(`Proximo server started on port ${gConfig.port}`);
});