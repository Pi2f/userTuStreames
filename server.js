const http = require('http');
const express = require('express');
const logger = require('morgan');
const bodyParser = require('body-parser');
const config = require('./config.js');
const methodOverride = require('method-override');
const helmet = require('helmet');
const user = require('./user.js');
const mail = require('./mail.js')
const crypto = require('crypto');
const waterfall = require('async-waterfall');

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
            const token = buf.toString('hex');
            done(err, token);
          });
        },
        function (token, done) {
          user.setActivationToken(req.body, token, done)
        },      
        function (token, user, done) {
          mail.setActivationTokenMail(user,token,done);
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
     mail.activateAccountMail(user,done);
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
      
    },
    function (token, done) {
      user.changePassword(req.body, token, done)
    },
    function (token, user, done) {
      mail.forgotMail(user,token,done);
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
      mail.reste(user,done);
    }
  ], function (err) {
    if (err) console.log("ERREUR : "+err);
    res.status(200).end();
  });
});

const server = http.createServer(app).listen(process.env.PORT || config.port, function () {
  console.log(`Example app listening on port ${config.port}!`)
});