/*
 * config.js loader and initializer
 *
 * Author: Attamah Celestine .C.
 * Date: __/__/__
 * 
 */

const config = require('./config.json');
const load_settings = config.settings;
const environment_variables = config.environment;
const environment = process.env.NODE_ENV || load_settings.default_environment;
const environment_config = config[environment];
const override = environment_config.system_override || false;

//merge environment_variables and environment_config together
Object.assign(environment_config, environment_variables);

//check if system should override some configuration 
//in config.js file only if it exist
if (override) {
    if (environment_config.port) environment_config.port = process.env.PORT ? process.env.PORT : environment_config.port;
}

// as a best practice
// all global variables should be referenced via global. syntax
// and their names should always begin with g
global.gConfig = environment_config;
