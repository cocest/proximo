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
 const http = require('http');
 const express = require('express');
 const body_parser = require("body-parser");
 const path = require('path');
 const logger = require('morgan');
 const api_route_v1 = require('./routes/api/v1/index.js');
 const api_route_v2 = require('./routes/api/v2/index.js');
 const app = express();

 //load server settings
 let file = fs.readFileSync('./rs_config.json');
 let rs_config = JSON.parse(file.toString('UTF-8'));

 //middleware that log incoming request etc
 app.use(logger('short'));

 //set up public path
 let public_path = path.resolve(__dirname, 'public');
 app.use(express.static(public_path));

 //route for API version 1
 app.use('/api/v1', api_route_v1);

 //route for API version 2
 app.use('/api/v2', api_route_v2);

 //start listening to incoming call from client
 http.createServer(app).listen(rs_config.port, rs_config.host, () => {
     console.log(`Resource server started on port ${rs_config.port}`);
 });
