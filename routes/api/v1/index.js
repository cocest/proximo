/*
 * REST API VERSION 1
 */

 const express = require('express');
 const router = express.Router();

 //check and validate access token (JWT)
 router.use((req, res, next) => {
     //validation code here
     next();
 });

 router.get('/hello', (req, res) => {
     res.status(200);
     res.send('Welcome to REST API version 1');
 });

 module.exports = router;