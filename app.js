/** */

/******************************************************************************
 * Module dependencies.
 *****************************************************************************/

require('dotenv').config();
var path = require('path');
var express = require('express');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');
var bodyParser = require('body-parser');
var util = require('util');
var logger = require('morgan');
var querystring = require('querystring');
var methodOverride = require('method-override');
var passport = require('passport');
var bunyan = require('bunyan');
var config = require('./config');

// set up database for express session
var MongoStore = require('connect-mongo')(expressSession);
var mongoose = require('mongoose');

// Start QuickStart here

var OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
var Auth0Strategy = require('passport-auth0');

var log = bunyan.createLogger({
    name: 'Microsoft OIDC Example Web Application'
});

//variables del servidor
const port = process.env.PORT || 3000;
const hostname = 'localhost';

/******************************************************************************
 * Set up passport in the app 
 ******************************************************************************/

//-----------------------------------------------------------------------------
// To support persistent login sessions, Passport needs to be able to
// serialize users into and deserialize users out of the session.  Typically,
// this will be as simple as storing the user ID when serializing, and finding
// the user by ID when deserializing.
//-----------------------------------------------------------------------------
passport.serializeUser(function(user, done) {
  done(null, user.oid);
});

passport.deserializeUser(function(oid, done) {
  findByOid(oid, function (err, user) {
    done(err, user);
  });
});

// array to hold logged in users
var users = [];

var findByOid = function(oid, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
   log.info('we are using user: ', user);
    if (user.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

//-----------------------------------------------------------------------------
// Use the OIDCStrategy within Passport.
// 
// Strategies in passport require a `verify` function, which accepts credentials
// (in this case, the `oid` claim in id_token), and invoke a callback to find
// the corresponding user object.
// 
// The following are the accepted prototypes for the `verify` function
// (1) function(iss, sub, done)
// (2) function(iss, sub, profile, done)
// (3) function(iss, sub, profile, access_token, refresh_token, done)
// (4) function(iss, sub, profile, access_token, refresh_token, params, done)
// (5) function(iss, sub, profile, jwtClaims, access_token, refresh_token, params, done)
// (6) prototype (1)-(5) with an additional `req` parameter as the first parameter
//
// To do prototype (6), passReqToCallback must be set to true in the config.
//-----------------------------------------------------------------------------
passport.use(new OIDCStrategy({
    identityMetadata: process.env.AZUREAD_IDENTITYMETADATA,
    clientID: process.env.AZUREAD_CLIENT_ID,
    responseType: config.creds.responseType,
    responseMode: config.creds.responseMode,
    redirectUrl: process.env.AZUREAD_REDIRECTURL,
    allowHttpForRedirectUrl: config.creds.allowHttpForRedirectUrl,
    clientSecret: process.env.AZUREAD_CLIENT_SECRET,
    validateIssuer: config.creds.validateIssuer,
    isB2C: config.creds.isB2C,
    issuer: config.creds.issuer,
    passReqToCallback: config.creds.passReqToCallback,
    scope: config.creds.scope,
    loggingLevel: config.creds.loggingLevel,
    nonceLifetime: config.creds.nonceLifetime,
    nonceMaxAmount: config.creds.nonceMaxAmount,
    useCookieInsteadOfSession: config.creds.useCookieInsteadOfSession,
    cookieEncryptionKeys: config.creds.cookieEncryptionKeys,
    clockSkew: config.creds.clockSkew,
  },
  function(iss, sub, profile, accessToken, refreshToken, done) {
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByOid(profile.oid, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      });
    });
  }
));

// Configure Passport to use Auth0
passport.use(new Auth0Strategy(
    {
      domain: process.env.AUTH0_DOMAIN,
      clientID: process.env.AUTH0_CLIENT_ID,
      clientSecret: process.env.AUTH0_CLIENT_SECRET,
      callbackURL: process.env.AUTH0_CALLBACK_URL || 'http://localhost:3000/callback'
    },
    function (accessToken, refreshToken, extraParams, profile, done) {
      // accessToken is the token to call Auth0 API (not needed in the most cases)
      // extraParams.id_token has the JSON Web Token
      // profile has all the information from the user
      return done(null, profile);
    }
  )
)

//-----------------------------------------------------------------------------
// Config the app, include middlewares
//-----------------------------------------------------------------------------
var app = express();

app.use(express.logger());
app.use(methodOverride());
app.use(logger('dev'));
app.use(cookieParser());

// set up session middleware
if (config.useMongoDBSessionStore) {
  mongoose.connect(config.databaseUri);
  app.use(express.session({
    secret: 'secret',
    cookie: {maxAge: config.mongoDBSessionMaxAge * 1000},
    store: new MongoStore({
      mongooseConnection: mongoose.connection,
      clear_interval: config.mongoDBSessionMaxAge
    })
  }));
} else {
  app.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));
}

app.use(bodyParser.urlencoded({ extended : true }));

// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

//-----------------------------------------------------------------------------
// Set up the route controller
//
// 1. For 'login' route and 'returnURL' route, use `passport.authenticate`. 
// This way the passport middleware can redirect the user to login page, receive
// id_token etc from returnURL.
//
// 2. For the routes you want to check if user is already logged in, use 
// `ensureAuthenticated`. It checks if there is an user stored in session, if not
// it will call `passport.authenticate` to ask for user to log in.
//-----------------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
};

app.get('/', function(req, res) {
  console.log(req.user)
  // res.render('index', { user: req.user });
  if (req.user) {
    res.redirect('index.html');
  } else {
    res.redirect('login.html');
  }
});

// '/account' is only available to logged in user
app.get('/account', ensureAuthenticated, function(req, res) {
  // res.render('account', { user: req.user });
});

app.get('/login_azure',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        resourceURL: config.resourceURL,    // optional. Provide a value if you want to specify the resource.
        customState: 'my_state',            // optional. Provide a value if you want to provide custom state value.
        failureRedirect: '/' 
      }
    )(req, res, next);
  },
  function(req, res) {
    log.info('Login was called in the Sample');
    res.redirect('/');
});

// 'GET returnURL'
// `passport.authenticate` will try to authenticate the content returned in
// query (such as authorization code). If authentication fails, user will be
// redirected to '/' (home page); otherwise, it passes to the next middleware.
app.get('/auth/openid/return',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        failureRedirect: '/'  
      }
    )(req, res, next);
  },
  function(req, res) {
    log.info('We received a return from AzureAD.');
    res.redirect('/');
  });

// 'POST returnURL'
// `passport.authenticate` will try to authenticate the content returned in
// body (such as authorization code). If authentication fails, user will be
// redirected to '/' (home page); otherwise, it passes to the next middleware.
app.post('/auth/openid/return',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        failureRedirect: '/'  
      }
    )(req, res, next);
  },
  function(req, res) {
    log.info('We received a return from AzureAD.');
    res.redirect('/');
  });

// 'logout' route, logout from passport, and destroy the session with AAD.
app.get('/logout', function(req, res){
  req.session.destroy(function(err) {
    req.logOut();
    res.redirect(config.destroySessionUrl);
  });
});

app.post('/action_page', (req, res) => {
  const users = [
    {email: 'l.quezada@cimmyt.org', password: '12345'},
    {email: 'l.puebla@cimmyt.org', password: '12345' },
    {email: 'j.s.sosa@cimmyt.org', password: '12345'},
    {email: 'admin', password: 'admin'}
  ];

  const isLoggin = users.filter((user)=> JSON.stringify(user) === JSON.stringify(req.body)); 

  if(isLoggin.length){
    const email = req.body.email;
    const password = req.body.password;
    console.log(`Wellcome: your email address: ${email} and your password: ${password}`);
    res.redirect('index.html');
    // res.redirect('index.html' + '/' + req.body.user_name);
  } else {
    res.redirect('login.html');
  }
});

// Perform the login, after login Auth0 will redirect to callback
app.get('/login_auth0',
  passport.authenticate('auth0', {scope: 'openid email profile'}), function (req, res) {
  res.redirect('/');
});

// Perform the final stage of authentication and redirect to previously requested URL or '/user'
app.get('/callback', function (req, res, next) {
  passport.authenticate('auth0', function (err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.redirect('/login.html'); }
    console.log(user);
    res.redirect('/index.html');
    // req.logIn(user, function (err) {
    //   if (err) { return next(err); }
    //   const returnTo = req.session.returnTo;
    //   delete req.session.returnTo;
    //   res.redirect(returnTo || '/index.html');
    // });

  })(req, res, next);
});

// app.get('/callback',
//   passport.authenticate('auth0', { failureRedirect: '/login' }),
//   function(req, res) {
//     if (!req.user) {
//       throw new Error('user null');
//     }
//     // res.redirect("/");
//     res.send("");
//   }
// );

// Perform session logout and redirect to homepage
app.get('/logout_auth0', (req, res) => {
  req.logout();

  var returnTo = req.protocol + '://' + req.hostname;
  var port = req.connection.localPort;
  if (port !== undefined && port !== 80 && port !== 443) {
    returnTo += ':' + port;
  }
  var logoutURL = new URL(
    util.format('https://%s/logout', process.env.AUTH0_DOMAIN)
  );
  var searchString = querystring.stringify({
    client_id: process.env.AUTH0_CLIENT_ID,
    returnTo: returnTo
  });

  console.log("Search String");
  console.log(searchString);
  logoutURL.search = searchString;
  // res.redirect(logoutURL);
  res.redirect('login.html');
});

// Perform session logout and redirect to homepage

// Catch 404 and forward to error handler
app.use(function (req, res, next) {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// Production error handler
// No stacktraces leaked to user
// app.use(function (err, req, res, next) {
//   res.status(err.status || 500);
//    res.send('Error 500');
// });

app.listen(port, hostname, () =>
  console.log(`File server running at http://${hostname}:${port}/`)
);

