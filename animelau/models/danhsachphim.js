'use strict';

var mongoose = require('mongoose');

var listSchema = mongoose.Schema({
    biglink: { type: String, require: true },
    smalllink: { type: String, require: true },
    filmname: { type: String, require: true },
    filmtag: { type: String, require: true },
    sanxuat: { type: String, require: true },
    sotap1: { type: Number, require: true },
    sotap2: { type: Number, require: true },
    namphatsong: { type: String, require: true },
    noidung: { type: String, require: true },
    opening: { type: String },
    ending: { type: String },
});

module.exports = mongoose.model('ListFilm', listSchema);