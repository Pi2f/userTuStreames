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
    activationTokenExpires: {
        type: Date
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
        if(isValidMail(data.mail)){
            if(isStrongPassword(data.password)){
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
                        cb("Mail already assigned to an other user");
                    }
                });                
            } else {
                cb("Password must have 8 characters min\n including (one special character !@#\$%\^&\*, one digit 0-9, one uppercase A-Z and one lowercase a-z)");
            }
        } else {
            cb("Wrong mail (Example mail : my.example@host.org)")
        }  
    },

    signin: function(mail, password, cb){  
        userModel.findOne({mail: mail}, 
            function(err, user){
                if(err){
                    cb(err);
                } else if (!user){                    
                    cb("User doesn't exist");
                } else {
                    bcrypt.compare(password, user.password, function(err, result) {                        
                        if(result === true){                            
                            cb(null, user);
                        } else {                                            
                            cb("Wrong password");
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
        return userModel.findOneAndUpdate({
            mail: body.mail
          },{
                resetPasswordToken:token,
                resetPasswordExpires: Date.now() + 3600000,
          }, function (err, user) {
            if (!user) {
              done('No account with that email address exists.', null, null);
            } else {
                done(err, token, user);
            }
          });
    },

    resetPassword: function(token, password, done){
        return userModel.findOneAndUpdate({
            resetPasswordToken: token,
            resetPasswordExpires: {
              $gt: Date.now()
            }
          }, {
            password: password,
            resetPasswordToken: undefined,
            resetPasswordExpires: undefined
          }, function (err, user) {
            if (err) {
              done('Password reset token is invalid or has expired.',null);
            } else {
                done(err, user);
            }
        });
    },

    setActivationToken: function(body, token, done){
        return userModel.findOneAndUpdate({
            mail: body.mail
          }, { 
              activationToken: token,
              activationTokenExpires: Date.now() + 3600000,
            }, function (err, user) {            
            if (err) {
              done('No account with that email address exists.', null, null);
            } else {
                done(err, token, user);
            }  
        });
    },

    activateAccount: function(token, done){
        return userModel.findOneAndUpdate({
            activationToken: token,
            activationTokenExpires: {
              $gt: Date.now()
            }
          },{ 
            isActive: true,
            activationToken: undefined,
            activationTokenExpires: undefined
          },
          function (err,user) {
            if (err) {
              done('Activation token is invalid.',null);
            } else {            
                done(err, user);
            }  
        });
    },
}