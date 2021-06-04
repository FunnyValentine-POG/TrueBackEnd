module.exports = {
    auth: {
        user: 'longca.acgnol@gmail.com',
        pass: 'ABC123456789@!abc'
    },
    facebook: {
        clientID: '171424288256703',
        clientSecret: 'a12d7df4bd7729be2c31a426cee46dc1',
        profileFields: ['email', 'displayName'],
        callbackURL: 'http://localhost:3000/auth/facebook/callback',
        passReqToCallback: true
    },
    google: {
        clientID: '444618388798-nv44u3cfopga0sm4ej5u8vofe2r2b8ks.apps.googleusercontent.com',
        clientSecret: 'C_VyNi1iaPTzHA2wiV8BEDcJ',
        profileFields: ['email', 'displayName'],
        callbackURL: 'http://localhost:3000/auth/google/callback',
        passReqToCallback: true
    }
}