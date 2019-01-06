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

// load and set all the settings
objectIterator(environment_config);

// iterate through object
function objectIterator(ob) {
    let keys = Object.keys(ob);
    for (let i = 0; i < keys.length; i++) {
        if (typeof ob[keys[i]] == 'object') {
            objectIterator(ob[keys[i]]);

        } else {
            assignSetting(ob, keys[i]);
        }
    }
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
                if (/^\d+$/.test(value)) { // check if is integer
                    env_config[setting] = parseInt(value);             

                } else {
                    env_config[setting] = value;
                }

                break;
            }
        }
    }
}

// as a best practice
// all global variables should be referenced via global. syntax
// and their names should always begin with g
global.gConfig = environment_config;