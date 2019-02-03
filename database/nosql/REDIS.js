/*
 * This add Redis client to Node.js global
 * 
 * Note: config.js have to be loaded first, otherwise it will not 
 * find the settings to initialise
 * 
 * Author: Attamah Celestine .C.
 * Email: attamahcelestine@gmail.com
 * Date: 1/31/2019
 * 
 */

const redis = require('redis');

// connect to redis srver
let client = redis.createClient(
    global.gConfig.redis.connection_url, {no_ready_check: true}
);

// connection error
client.on('error', function (err) {
    // log the error to log file
    gLogger.log('error', err.message, {stack: err.stack});
});

// add to global variables
global.gRedisClient = client;