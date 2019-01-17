const uuidv4 = require('uuid/v4');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const config = require('./config.js');

mongoose.connect(config.urlDB,{
    useFindAndModify: false,
    useNewUrlParser: true,
    useCreateIndex: true,
}, function(err) {
    if (err) { throw err; } else {
        console.log('Mongo: Database connected');
    }
});


const userSchema = new mongoose.Schema({
    _userID: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    mail: {
        type: String,
        required: true,
        trim: true,
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: Array,
        required: true,
        default: ['*'],
    },
    isActive: {
        type: Boolean,
        default: false,
    },
    activationToken: {
        type: String
    },
    isBlocked: {
        type: Boolean,
        default: false,
    },
    resetPasswordToken: {
        type: String
    },
    resetPasswordExpires: {
        type: Date
    }
});

userSchema.pre('save', function (next) {
    var user = this;
    bcrypt.hash(user.password, 8, function (err, hash) {
      if (err) {
        throw err;
      }
      user.password = hash;
      next();
    });
});

function isStrongPassword(data) {
    const strongPassword = new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/);
    return strongPassword.test(data);
}

function isValidMail(data) {
    const validMail = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);    
    return validMail.test(data);
}

function checkForExistingUser(mail, cb){
    userModel.findOne({mail: mail}, function(err, result){
        cb(result);
    });
}


const userModel = mongoose.model('Users', userSchema);

module.exports = {
    isAdmin: function(data, cb){
        return userModel.findOne({
            _userID: data,
        }, function (err, user) {
           cb(err, user.role.indexOf('admin') !== -1);
        });
    },

    setAdmin: function(data, cb){
        if(data.role.indexOf('admin') === -1){
            data.role.push('admin');
            return userModel.findOneAndUpdate({
                _userID: data._userID,
            }, { role: data.role },
            function (err, user) {
                cb(err, user);
            });
        } else {
            data.role.splice(1,data.role.indexOf('admin'));
            return userModel.findOneAndUpdate({
                _userID: data._userID,
            }, { role: data.role },
            function (err, user) {
                cb(err, user);
            });
        }

    },

    isBlocked: function(data, cb){
        return userModel.findOne({
            _userID: data._userID,
        }, function (err, user) {
           cb(err, user.isBlocked);
        });
    },

    toggleBlocked: function(data, cb){
        return userModel.findOneAndUpdate({
            _userID: data._userID,
        }, { isBlocked: !data.isBlocked },
        function (err, user) {
            cb(err, user);
        });
    },

    isActive: function(data, cb){
        return userModel.findOne({
            _userID: data._userID,
        }, function (err, user) {
           cb(err, user.isActive);
        });
    },

    toggleActive: function(data, cb){
        return userModel.findOneAndUpdate({
            _userID: data._userID,
        }, { isBlocked: !data.isActive },
        function (err, user) {
            cb(err, user);
        });
    },

    subscribe: function(data, cb){
        if(isStrongPassword(data.password) && isValidMail(data.mail)){
            checkForExistingUser(data.mail, function(result){
                if(result == null){
                    const userData = new userModel({
                        username: data.username,
                        mail: data.mail,
                        password: data.password,
                        _userID: uuidv4()
                    });
                    userData.save(function(err){
                        if(err) cb(err);
                        cb();
                    });
                } else {
                    cb("Mail déjà utilisé par un autre utilisateur");
                }
            });
            
        } else {
            cb("Invalide password or mail");
        }
        //cb();   
    },

    signin: function(mail, password, cb){  
        userModel.findOne({mail: mail}, 
            function(err, user){
                if(err){
                    cb(err);
                } else if (!user){                    
                    cb("L'utilisateur n'existe pas");
                } else {
                    bcrypt.compare(password, user.password, function(err, result) {                        
                        if(result === true){                            
                            cb(null, user);
                        } else {                                            
                            cb("Password false");
                        }                        
                    });
                }
            }
        )
    },

    getAll: function(cb){
        userModel.find({}, function(err, users) {
            if(err) cb(err);
            else cb(null, users);
        })
    },

    get: function(id,cb){
        userModel.findOne({_userID: id}, function(err, user) {
            if(err) cb(err);
            else cb(null, user);
        })
    },


    changePassword: function(body, token, done){
        return userModel.findOne({
            mail: body.mail
          }, function (err, user) {
    
            if (!user) {
              done('No account with that email address exists.', null, null);
            }
    
            user.resetPasswordToken = token;
            user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    
            user.save(function (err) {
              if (err) cb(err);
              done(err, token, user);
            });
          });
    },

    resetPassword: function(token, password, done){
        userModel.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: {
              $gt: Date.now()
            }
          }, function (err, user) {
            if (!user) {
              done('Password reset token is invalid or has expired.',null);
            } else {
                user.password = password;
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;
        
                user.save(function (err) {              
                  done(err, user);
                });
            }
    
        });
    },

    setActivationToken: function(body, token, done){
        return userModel.findOneAndUpdate({
            mail: body.mail
        }, {activationToken:token}, function(err, user) {            
            done(err, token, user);
        });
    },

    activateAccount: function(token, done){
        return userModel.findOneAndUpdate({
            activationToken: token
        }, {isActive:true, activationToken: undefined}, function(err, user) {            
            done(err, user);
        });
    },
}