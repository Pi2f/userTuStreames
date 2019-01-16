const http = require('http');
const express = require('express');
const logger = require('morgan');
const bodyParser = require('body-parser');
const config = require('./config.js');
const methodOverride = require('method-override');
const helmet = require('helmet');
const user = require('./user.js');
var nodemailer = require('nodemailer');
var crypto = require('crypto');
var waterfall = require('async-waterfall');

const app = express();

app.use(logger('dev'));
app.use(methodOverride());
app.use(bodyParser.urlencoded({
  'extended': 'true'
}));
app.use(bodyParser.json());
app.use(express.static(__dirname));


app.use(function onError(err, req, res, next) {
  res.status(500).send(err);
});

app.get('/user/:id', function (req, res) {
    user.get(req.params.id, function (err, user) {
      if (err) throw new Error("Broke");
      else res.status(200).send(user);
    });
});

app.get('/user/all/:id', function (req, res) {
  user.isAdmin(req.params.id, function (err, isAdmin) {
    if (isAdmin) {
      user.getAll(function (err, users) {
        if (err) throw new Error("Broke");
        else res.status(200).send(users);
      });
    } else {
      res.status(500).send();
    }
  });
});

app.post('/user/authenticate', function (req, res) {
  if (req.body.mail && req.body.password) {
    user.signin(req.body.mail, req.body.password, function (err, data) {      
      if (err) res.status(200).send({err: err});
      else {
        user.isBlocked(data, function (err, isBlocked) {
          if (!isBlocked) {
            res.status(200).send(JSON.stringify({user: data}));            
          } else {
            res.status(403).end();
          }
        });
      }
    });
  }
});

app.post('/user/register', function (req, res) {
  user.subscribe(req.body, function (err) {
    if (err) {
      res.status(500).send({
        error: err
      });
    } else res.status(200).send({
      success: true
    });
  });
});

app.get('/user/admin/:id', function (req, res) {
  user.isAdmin(req.params.id, function (err, isAdmin) {
    if (err) res.status(500).send();
    else res.status(200).send({
      isAdmin: isAdmin
    });
  })
});

app.post('/user/admin', function (req, res) {
  user.setAdmin(req.body, function (err, user) {
    if (err) res.status(500).send();
    else res.status(200).send(user);
  });
});

app.post('/user/blocked', function (req, res) {
  user.toggleBlocked(req.body, function (err, user) {
    if (err) res.status(500).send();
    else res.status(200).send(user);
  })
});

app.post('/forgot', function (req, res) {
  waterfall([
    function (done) {
      crypto.randomBytes(20, function (err, buf) {
        if (err) console.log("erreur crypto : " + err)
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function (token, done) {
      user.changePassword(req.body, token, done)
    },
    function (token, user, done) {
      var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'tustreamesnoreply@gmail.com',
          pass: 'heihei89'
        }
      });
      var mailOptions = {
        to: user.mail,
        from: 'tustreamesnoreply@gmail.com',
        subject: 'Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          //'https://' + routeurHost + '/api/reset/' + token + '\n\n' +
          'https://localhost:3000/#!/passwordReset?token=' + token + '\n\n' + //A test !
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      transporter.sendMail(mailOptions, function (err) {
        if (err) console.log("erreur transporteur : " + err);
        console.log('An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function (err) {
    if (err) {
      console.log(err);
      return next(err);
    }
    res.status(200).end();
  });
});

app.post('/reset/:token', function (req, res) {
  waterfall([
    function (done) {
      user.resetPassword(req.params.token, req.body.password, done)
    },
    function (user, done) {
      var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'tustreamesnoreply@gmail.com',
          pass: 'heihei89'
        }
      });
      var mailOptions = {
        to: user.mail,
        from: 'tustreamesnoreply@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.mail + ' has just been changed.\n'
      };
      transporter.sendMail(mailOptions, function (err) {
        done(err);
      });
    }
  ], function (err) {
    res.status(200).end();
  });
});




const server = http.createServer(app).listen(config.port, function () {
  console.log(`Example app listening on port ${config.port}!`)
});