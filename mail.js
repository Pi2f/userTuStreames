const nodemailer = require('nodemailer');
const config = require('./config.js');

const transporter = nodemailer.createTransport({
    service: config.mailService,
    auth: {
      user: config.mail,
      pass: config.pass,
    }
});

module.exports = {
    activateAccountMail: function(user, done){
          const mailOptions = {
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
    },

    setActivationTokenMail: function(user, token, done){        
          const mailOptions = {
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
    },

    forgotMail: function(user, token, done){
        const mailOptions = {
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
    },

    resetMail: function(user, done) {
          const mailOptions = {
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
}