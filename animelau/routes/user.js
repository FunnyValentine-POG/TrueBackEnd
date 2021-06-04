const passport = require('passport');

var nodemailer = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var async = require('async');

var crypto = require('crypto');
var User = require('../models/user');
var secret = require('../secret/secret');
const { response } = require("express");
var { default: user } = require("../models/user");
var ListFilm = require('../models/danhsachphim');

module.exports = (app) => {
    app.get('/', (req, res, next) => {
        ListFilm.find({}, (err, result) => {
            if (err) throw err;
            res.render('index', {
                title: '',
                cookie: req.session.cookie,
                listfilm: result
            });
        });
    });

    app.get('/signup', (req, res) => {
        var signupErrors = req.flash('error');
        res.render('user/signup', {
            title: 'Đăng ký thành viên',
            messages: signupErrors,
            hasError: signupErrors.length > 0,
            cookie: req.session.cookie
        });
    });

    app.post('/signup', signupValidate, passport.authenticate('local.signup', {
        failureRedirect: '/signup',
        failureFlash: true
    }), (req, res) => {
        req.session.cookie.originalMaxAge = 60 * 60 * 1000;
        res.redirect('/');
    });

    app.get('/signup/admin', (req, res) => {
        var signupErrors = req.flash('error');
        res.render('user/signup_admin', {
            title: 'Đăng ký thành viên',
            messages: signupErrors,
            hasError: signupErrors.length > 0,
            cookie: req.session.cookie
        });
    });

    app.post('/signup/admin', adminsignupValidate, passport.authenticate('local.adminsignup', {
        failureRedirect: '/signup/admin',
        failureFlash: true
    }), (req, res) => {
        req.session.cookie.originalMaxAge = 60 * 60 * 1000;

        res.redirect('/adminSite' + user.role);
    });

    app.get('/login', (req, res) => {
        var loginErrors = req.flash('error');
        res.render('user/login', {
            title: 'Đăng Nhập',
            messages: loginErrors,
            hasError: loginErrors.length > 0,
            cookie: req.session.cookie
        });
    });

    app.post('/login', loginValidate, passport.authenticate('local.login', {
        failureRedirect: '/login',
        failureFlash: true
    }), (req, res) => {
        if (req.body.rememberme !== undefined) {
            req.session.cookie.originalMaxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        } else {
            req.session.cookie.originalMaxAge = 5 * 60 * 1000; // 1 hour
        }
        User.findOne({ 'email': req.body.email }, (err, user) => {
            if (!user) {
                req.flash('error', 'No Account With That Email Exist or Email Is Invalid.');
                return res.redirect('/login');
            }
            if (user.role !== 'admin') {
                res.redirect('/' + user.role);
            } else {
                res.redirect('/adminSite' + user.role);
            }
        });
    });

    app.get('/thongtinchitiet', (req, res, next) => {
        res.render('thongtinchitiet', {
            title: 'Tên Phim',
            cookie: req.session.cookie
        });
    });

    app.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email' }));

    app.get('/auth/facebook/callback', passport.authenticate('facebook', {
        failureRedirect: '/login',
        failureFlash: true
    }), (req, res) => {
        if (req.body.rememberme !== undefined) {
            req.session.cookie.originalMaxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        } else {
            req.session.cookie.originalMaxAge = 5 * 60 * 1000; // 1 hour
        }
        User.findOne({ 'facebook': req.body.facebook }, (err, user) => {
            if (!user) {
                req.flash('error', 'No Account With That Facebook Exist or Facebook Is Invalid.');
                return res.redirect('/login');
            }
            if (user.role !== 'admin') {
                res.redirect('/' + user.role);
            } else {
                res.redirect('/adminSite' + user.role);
            }
        });
    });

    app.get('/auth/google', passport.authenticate('google', { scope: 'email' }));

    app.get('/auth/google/callback', passport.authenticate('google', {
        failureRedirect: '/login',
        failureFlash: true
    }), (req, res) => {
        if (req.body.rememberme !== undefined) {
            req.session.cookie.originalMaxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        } else {
            req.session.cookie.originalMaxAge = 5 * 60 * 1000; // 1 hour
        }
        User.findOne({ 'google': req.body.google }, (err, user) => {
            if (!user) {
                req.flash('error', 'No Account With That Google Account Exist or Google Account Is Invalid.');
                return res.redirect('/login');
            }
            if (user.role !== 'admin') {
                res.redirect('/' + user.role);
            } else {
                res.redirect('/adminSite' + user.role);
            }
        });
    });

    app.get('/adminSite', (req, res) => {
        res.render('adminSite', {
            title: 'Anime Lậu',
            cookie: req.session.cookie
        });
    });

    app.get('/forgot', (req, res) => {
        var forgotErrors = req.flash('error');
        var info = req.flash('info');
        res.render('user/forgot', {
            title: 'Quên Mật Khẩu',
            messages: forgotErrors,
            hasError: forgotErrors.length > 0,
            info: info,
            noError: info.length > 0,
            cookie: req.session.cookie
        });
    });

    app.post('/forgot', (req, res, next) => {
        async.waterfall([
            function(callback) {
                crypto.randomBytes(20, (err, buf) => {
                    var rand = buf.toString('hex');
                    callback(err, rand);
                });
            },

            function(rand, callback) {
                User.findOne({ 'email': req.body.email }, (err, user) => {
                    if (!user) {
                        req.flash('error', 'No Account With That Email Exist or Email Is Invalid.');
                        return res.redirect('/forgot');
                    }

                    user.passwordResetToken = rand;
                    user.passwordResetExpires = Date.now() + 60 * 60 * 1000 // 1 hour

                    user.save((err) => {
                        callback(err, rand, user);
                    });
                });
            },

            function(rand, user, callback) {
                var smtpTransport = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: secret.auth.user,
                        pass: secret.auth.pass
                    }
                });

                var mailOptions = {
                    to: user.email, //req.body.email
                    from: `BaiTH1 <${secret.auth.user}>`,
                    subject: 'BaiTH1 Application Password Reset Token',
                    text: 'You have requested for password reset token. \n\n' +
                        'Please click on the link to complete the process: \n\n' +
                        'http://localhost:3000/reset/' + rand + '\n\n'
                }

                smtpTransport.sendMail(mailOptions, (err, response) => {
                    req.flash('info', 'A password reset token has been sent to ' + user.email);
                    return callback(err, user);
                });
            }
        ], (err) => {
            if (err) {
                return next(err);
            }

            res.redirect('/forgot');
        });
    });

    app.get('/reset/:token', (req, res) => {
        //handle expired token or token is invalid, gt = greater than
        User.findOne({
            passwordResetToken: req.params.token,
            passwordResetExpires: { $gt: Date.now() }
        }, (err, user) => {
            if (!user) {
                req.flash('error', 'Password reset token has exprired or is invalid. Enter your email to get a new token.');
                // redirect to forgot
                return res.redirect('/forgot');
            }
            var errors = req.flash('error');
            var success = req.flash('success');
            res.render('user/reset', {
                title: 'Reset Password',
                messages: errors,
                hasError: errors.length > 0,
                success: success,
                noError: success.length > 0,
                cookie: req.session.cookie
            });
        });
    });

    app.post('/reset/:token', (req, res) => {
        async.waterfall([
            function(callback) {
                user = User.findOne({
                    passwordResetToken: req.params.token,
                    passwordResetExpires: { $gt: Date.now() }
                }, (err, user) => {
                    if (!user) {
                        req.flash('error', 'Password reset token has exprired or is invalid. Enter your email to get a new token.');
                        // redirect to forgot
                        return res.redirect('/forgot');
                    }

                    req.checkBody('password', 'Password is Required').notEmpty();
                    req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({ min: 5 });
                    req.check('password', 'Password Must Contain at least 1 Number and Lower character').matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, 'i');

                    var errors = req.validationErrors();
                    if (req.body.password === req.body.cpassword) {
                        if (errors) {
                            var messages = [];
                            errors.forEach((error) => {
                                messages.push(error.msg);
                            });
                            req.flash('error', messages);
                            res.redirect('/reset/' + req.params.token);
                        } else {
                            user.password = user.encryptPassword(req.body.password);
                            user.passwordResetToken = undefined;
                            user.passwordResetExpires = undefined;

                            user.save((err) => {
                                req.flash('success', 'Your password has been successfully updated.');
                                callback(err, user);
                            });
                            res.redirect('/login');
                        }
                    } else {
                        req.flash('error', 'Password and comfirm password are not equal.');
                        res.redirect('/reset/' + req.params.token);
                    }
                });
            }
        ]);
    });

    app.get('/logout', (req, res) => {
        req.logout();
        req.session.destroy((err) => {
            res.redirect('/');
        });
    });

    // app.get('/thongtinphim', (req, res) => {
    //     res.render('thongtinphim', {
    //         title: 'Thông tin phim',
    //         cookie: req.session.cookie
    //     });
    // });

    app.get('/thongtinphim/:filmname', (req, res) => {
        ListFilm.findOne({
            filmname: req.params.filmname
        }, (err, film) => {
            res.render('thongtinphim', {
                title: 'Thông tin phim' + film.filmname,
                cookie: req.session.cookie,
                film: film
            });
        });
    });

    app.get('/themphim', (req, res) => {
        var errors = req.flash('error');
        var success = req.flash('success');
        res.render('themphim', {
            title: 'Thêm phim mới',
            messages: errors,
            hasError: errors.length > 0,
            success: success,
            noError: success.length > 0,
            cookie: req.session.cookie
        });
    });

    app.post('/themphim', (req, res) => {
        async.waterfall([
            function(callback) {
                listfilm = ListFilm.findOne({
                        filmname: req.body.filmname
                    },
                    (err, listfilm) => {
                        req.checkBody('biglink', 'biglink is Required').notEmpty();
                        req.checkBody('smalllink', 'smaalllink is Required').notEmpty();
                        req.checkBody('filmname', 'filmname is Required').notEmpty();
                        req.checkBody('filmtag', 'filmtag is Required').notEmpty();
                        req.checkBody('sanxuat', 'sanxuat is Required').notEmpty();
                        req.checkBody('sotap1', 'sotap1 is Required').notEmpty();
                        req.checkBody('namphatsong', 'namphatsong is Required').notEmpty();
                        req.checkBody('noidung', 'noidung is Required').notEmpty();

                        var errors = req.validationErrors();
                        if (errors) {
                            var messages = [];
                            errors.forEach((error) => {
                                messages.push(error.msg);
                            });
                            req.flash('error', messages);
                            res.redirect('/themphim');
                        } else {
                            if (listfilm) {
                                listfilm.biglink = req.body.biglink;
                                listfilm.smalllink = req.body.smalllink;
                                listfilm.filmtag = req.body.filmtag;
                                listfilm.sanxuat = req.body.sanxuat;
                                listfilm.sotap1 = req.body.sotap1;
                                listfilm.sotap2 = req.body.sotap2;
                                listfilm.namphatsong = req.body.namphatsong;
                                listfilm.noidung = req.body.noidung;
                                listfilm.opening = req.body.opening;
                                listfilm.ending = req.body.ending;
                            } else {
                                listfilm = new ListFilm();
                                listfilm.biglink = req.body.biglink;
                                listfilm.smalllink = req.body.smalllink;
                                listfilm.filmname = req.body.filmname;
                                listfilm.filmtag = req.body.filmtag;
                                listfilm.sanxuat = req.body.sanxuat;
                                listfilm.sotap1 = req.body.sotap1;
                                listfilm.sotap2 = req.body.sotap2;
                                listfilm.namphatsong = req.body.namphatsong;
                                listfilm.noidung = req.body.noidung;
                                listfilm.opening = req.body.opening;
                                listfilm.ending = req.body.ending;
                            }
                            listfilm.save((err) => {
                                req.flash('success', 'Your film has been successfully updated.');
                                callback(err, listfilm);
                            });
                            res.redirect('/themphim');
                        }
                    });
            }
        ]);
    });
}

function signupValidate(req, res, next) {
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is Required').notEmpty();
    req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({ min: 5 });
    req.check('password', 'Password Must Contain at least 1 Number and Lower character').matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, 'i');

    var signupErrors = req.validationErrors();
    if (signupErrors) {
        var messages = [];
        signupErrors.forEach((error) => {
            messages.push(error.msg);
        });

        req.flash('error', messages);
        res.redirect('/signup');
    } else {
        return next();
    }
}

function adminsignupValidate(req, res, next) {
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is Required').notEmpty();
    req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({ min: 5 });
    req.check('password', 'Password Must Contain at least 1 Number and Lower character').matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, 'i');
    req.checkBody('code', 'Yêu cầu mã xác nhận').notEmpty();

    var signupErrors = req.validationErrors();
    if (signupErrors) {
        var messages = [];
        signupErrors.forEach((error) => {
            messages.push(error.msg);
        });

        req.flash('error', messages);
        res.redirect('/signup');
    } else {
        return next();
    }
}

function loginValidate(req, res, next) {
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is Required').notEmpty();
    req.checkBody('password', 'Password Must Not Be Less Than 5').isLength({ min: 5 });
    req.check('password', 'Pass/word Must Contain at least 1 Number and Lower character').matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, 'i');

    var loginErrors = req.validationErrors();
    if (loginErrors) {
        var messages = [];
        loginErrors.forEach((error) => {
            messages.push(error.msg);
        });

        req.flash('error', messages);
        res.redirect('/login');
    } else {
        return next();
    }
}