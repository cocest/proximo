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
 const path = require('path');
 //const logger = require('morgan');
 const app = express();

 //load server settings
 let file = fs.readFileSync('./rs_config.json');
 let rs_config = JSON.parse(file.toString('UTF-8'));

 //middleware that log incoming request etc
 //app.use(logger('short'));

 //set up public path
 let public_path = path.resolve(__dirname, 'public');
 app.use(express.static(public_path));

 //start listening to incoming call from client
 http.createServer(app).listen(rs_config.port, rs_config.host, () => {
     console.log(`Resource server started on port ${rs_config.port}`);
 });
