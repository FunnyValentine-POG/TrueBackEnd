'use strict';

var mongoose = require('mongoose');
var bcrypt = require('bcrypt');

var userSchema = mongoose.Schema({
    email: { type: String, require: true },
    password: { type: String },
    role: { type: String, default: '' },
    company: {
        name: { type: String, default: '' },
        image: { type: String, default: '' }
    },
    passwordResetToken: { type: String, default: '' },
    passwordResetExpires: { type: Date, default: Date.now },
    facebook: { type: String, default: '' },
    tokens: Array,
    google: { type: String, default: '' },
    gtokens: Array,
});

userSchema.methods.encryptPassword = (password) => {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10), null);
}

userSchema.methods.validPassword = function(password) {

    return bcrypt.compareSync(password, this.password);
}

module.exports = mongoose.model('User', userSchema);