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
const http = require('http');
const express = require('express');
const body_parser = require('body-parser');
const path = require('path');
const logger = require('morgan');
const custom_model = require('./models/custom-model');
const custom_utils = require('./utilities/custom-utils');
const api_route_v1 = require('./routes/api/v1/index.js');
const oauth2 = require('./routes/oauth2');
const aws = require('aws-sdk');
const sharp = require('sharp');
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

// create the requested image size and store it to aws s3 bucket and redirect user to the source
app.get('/resizeImage/:base_folder/images/:resize_size/:image_name', (req, res) => {
    // check if parse base folder name is valid
    if (!/^(article|news)$/.test(req.params.base_folder)) {
        res.status(404);
        res.json({
            error_code: "file_not_found",
            message: "Image does not exist"
        });

        return;
    }

    // fetch image from aws s3 bucket
    // set aws s3 access credentials
    aws.config.update({
        apiVersion: '2006-03-01',
        accessKeyId: gConfig.AWS_ACCESS_ID,
        secretAccessKey: gConfig.AWS_SECRET_KEY,
        region: gConfig.AWS_S3_BUCKET_REGION // region where the bucket reside
    });

    const s3 = new aws.S3();

    const params = {
        Bucket: gConfig.AWS_S3_BUCKET_NAME,
        Key: req.params.base_folder + '/images/big/' + req.params.image_name
    };

    //check if file exist at s3 bucket
    s3.headObject(params, (err, metadata) => {
        if (err && err.code == 'NotFound') {
            // handle object not found on cloud
            res.status(404);
            res.json({
                error_code: "file_not_found",
                message: "Image does not exist"
            });

            return;

        } else { // object exist
            const resize_sizes = new Map([
                ['medium', 720],
                ['small', 360],
                ['tiny', 250]
            ]);

            const img_res_size = resize_sizes.get(req.params.resize_size);

            // check if size to resize to is valid
            if (!img_res_size) {
                res.status(400);
                res.json({
                    error_code: "invalid_request",
                    message: "Bad request"
                });

                return;
            }

            const s3_promise = s3.getObject(params).promise();

            s3_promise.then((data) => {
                // rezise the image to requested size and upload it back
                sharp(data.Body)
                    .resize({
                        height: img_res_size, // resize image using the set height
                        withoutEnlargement: true
                    })
                    .toFormat('png')
                    .toBuffer()
                    .then(outputBuffer => {
                        // upload resize image to s3 bucket
                        const upload_params = {
                            Bucket: gConfig.AWS_S3_BUCKET_NAME,
                            Body: outputBuffer,
                            Key: req.params.base_folder + '/images/' + req.params.resize_size + '/' + req.params.image_name,
                            ACL: gConfig.AWS_S3_BUCKET_PERMISSION
                        };

                        s3.upload(upload_params, function (err, data) {
                            if (err) {
                                res.status(500);
                                res.json({
                                    error_code: "internal_error",
                                    message: "Internal error"
                                });

                                // log the error to log file
                                gLogger.log('error', err.message, {
                                    stack: err.stack
                                });

                                return;
                            }

                            if (data) { // file uploaded successfully
                                // redirect client to aws s3 bucket
                                res.set('location', data.Location);
                                res.status(301).send();
                                return;
                            }
                        });

                    })
                    .catch(err => {
                        res.status(500);
                        res.json({
                            error_code: "internal_error",
                            message: "Internal error"
                        });

                        // log the error to log file
                        gLogger.log('error', err.message, {
                            stack: err.stack
                        });

                        return;
                    });

            }).catch((err) => {
                res.status(500);
                res.json({
                    error_code: "internal_error",
                    message: "Internal error"
                });

                // log the error to log file
                gLogger.log('error', err.message, {
                    stack: err.stack
                });
            });
        }
    });
});

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

//start listening on provided port
http.createServer(app).listen(gConfig.port, () => {
    console.log(`Proximo server started on port ${gConfig.port}`);
});