/*
 * config.js loader and initializer
 *
 * Author: Attamah Celestine .C.
 * Date: 1/4/2018
 * 
 */

const config = require('./config.json');
const load_settings = config.settings;
const environment_variables = config.environment;
const environment = process.env.NODE_ENV || load_settings.default_environment;
const environment_config = config[environment];

// merge environment_variables and environment_config together
Object.assign(environment_config, environment_variables);

// load server listening port
if (environment_config.port) assignSetting(environment_config, "port");

// check if db setting exist and load settings
if (environment_config.db) {
    if (environment_config.db.host) assignSetting(environment_config.db, "host");
    if (environment_config.db.database) assignSetting(environment_config.db, "database");
    if (environment_config.db.username) assignSetting(environment_config.db, "username");
    if (environment_config.db.password) assignSetting(environment_config.db, "password");
}

// utility function that assign value to configuration variables
function assignSetting(env_config, setting) {
    // check if we need to set the value
    if (/\$env:/.test(env_config[setting])) {
        let value;
        let splits = env_config[setting].split('|');

        for (let i = 0; i < splits.length; i++) {
            if (/\$env:/.test(splits[i])) {
                value = process.env[splits[i].split(':')[1].trim()];
                if (value) {
                    env_config[setting] = value;
                    break;

                } else if (i == (splits.length - 1)) {
                    env_config[setting] = "";
                }

            } else { // most be default or defined value
                value = splits[i].trim();
                if (/^(\d{1,3}.){3}\d{1,3}$/.test(value)) { // check if is IP Address
                    env_config[setting] = value;

                } else {
                    env_config[setting] = parseInt(value) ? parseInt(value) : value;
                    break;
                }
            }
        }
    }
}

// as a best practice
// all global variables should be referenced via global. syntax
// and their names should always begin with g
global.gConfig = environment_config;