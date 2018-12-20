/*
 * REST API VERSION 2
 */

const express = require('express');
const router = express.Router();

//this is for test
router.get('/hello', (req, res) => {
    res.status(200);
    res.send('Welcome to REST API version 2');
});

module.exports = router;