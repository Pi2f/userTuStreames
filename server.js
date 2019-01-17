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
      if (err) {
        res.status(200).send({err: err});
      }
      else {
        user.isBlocked(data, function (err, isBlocked) {
          if (!isBlocked) {
            user.isActive(data, function (err, isActive) {
              if (isActive) {
                res.status(200).send(JSON.stringify({user: data}));
              } else {
                res.status(403).end();
              }
            } );           
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
      res.status(200).send({
        err: err
      });
    } else  {
      
      waterfall([ 
        function (done) {
          crypto.randomBytes(20, function (err, buf) {
            if (err) console.log("erreur crypto : " + err)
            var token = buf.toString('hex');
            done(err, token);
          });
        },
        function (token, done) {
          user.setActivationToken(req.body, token, done)
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
            subject: 'Activate your account',
            text: ' Thanks for subscribing to uour service !\n'
            + 'In order to complete this process you still need to activate your account ! To that end please use the following link : \n'
            + "https://tustreames.herokuapp.com/#!/accountActivation?token="+token
          };
          transporter.sendMail(mailOptions, function (err) {
            if (err) console.log("erreur transporteur : " + err);            
            done(err, 'done');
          });
        }
      ], function (err) {
        if (err) console.log("ERREUR : "+err);
        res.status(200).end();
      });
     
      res.status(200).send({success: true});
    }
  });
});

app.post('/user/activateAccount/:token', function (req, res) {
  waterfall([
    function (done) {
      user.activateAccount(req.params.token, done)
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
        subject: 'Account activated',
        text: 'Hello,\n\n' +
          'This is a confirmation that the account ' + user.mail + ' has just been activated.\n'
          + 'Have fun using our services !'
      };
      transporter.sendMail(mailOptions, function (err) {
        done(err);
      });
    }
  ], function (err) {
    if (err) console.log("ERREUR : "+err);
    res.status(200).end();
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
          'https://tustreames.herokuapp.com/#!/passwordReset?token=' + token + '\n\n' + //A test !
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      transporter.sendMail(mailOptions, function (err) {
        if (err) console.log("erreur transporteur : " + err);
        done(err, 'done');
      });
    }
  ], function (err) {
    if (err) console.log("ERREUR : "+err);
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
    if (err) console.log("ERREUR : "+err);
    res.status(200).end();
  });
});




const server = http.createServer(app).listen(process.env.PORT || config.port, function () {
  console.log(`Example app listening on port ${config.port}!`)
});