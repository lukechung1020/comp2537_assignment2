require("./utils.js");

require("dotenv").config();

const url = require("url");

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.set('view engine', 'ejs');

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Cats", link: "/members"},
    {name: "Admin", link: "/admin"}
];

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret,
    },
});

app.use(
    session({
        secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true,
    })
);

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized", navLinks: navLinks, currentURL: url.parse(req.url).pathname});
        return;
    }
    else {
        next();
    }
}

// Main Page with Sign up and Log in button
app.get("/", (req, res) => {
    var name = req.session.username;

    if (name) {
        res.render("loggedin", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
    } else {
        res.render("index", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
    }
});

app.get("/signup", (req, res) => {
    res.render("signup", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.get("/login", (req, res) => {
    res.render("login", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.post("/submitUser", async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        req.session.validationResult = validationResult.error._original;
        res.redirect("/signupSubmit");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
        user_type: "admin"
    });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.post("/loggingin", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            email: Joi.string().required(),
            password: Joi.string().max(20).required()
        }
    );
    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/loginSubmit");
        return;
    }

    const result = await userCollection
        .find({ email: email })
        .project({ username: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginSubmit");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        var username = result[0].username;
        var user_type = result[0].user_type;
        req.session.authenticated = true;
        req.session.username = username;
        req.session.user_type = user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/members");
        return;
    } else {
        console.log("incorrect password");
        res.redirect("/loginSubmit");
        return;
    }
});

app.get("/signupSubmit", (req, res) => {
    var result = req.session.validationResult;
    console.log(result);

    var numEmpty = 0;
    var helpMSG = `
        Please provide
    `;

    if (result.username === "") {
        helpMSG += "a name";
        numEmpty++;
    }
    if (result.email === "") {
        if (numEmpty >= 1) {
            helpMSG += ", ";
        }
        if (numEmpty >= 1 && result.email === "") {
            helpMSG += "and ";
        }
        helpMSG += "an email address";
        numEmpty++;
    }
    if (result.password === "") {
        if (numEmpty >= 1) {
            helpMSG += ", and ";
        }
        helpMSG += "a password";
    }

    res.render("signupSubmit", {helpMSG: helpMSG, navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.get("/members", (req, res) => {
    var name = req.session.username;
    if (!req.session.authenticated) {
        res.redirect("/");
        return;
    }
    res.render("cat", {navLinks: navLinks, currentURL: url.parse(req.url).pathname, username: name});
});

app.get("/loginSubmit", (req, res) => {
    res.render("loginSubmit", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result, navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.post('/admin/promote', async (req,res) => {
    var username = req.body.username;

    await userCollection.updateOne({username: username}, {$set: {user_type: "admin"}});
    if (req.session.username === username) {
        req.session.user_type = "admin";
    }
    res.redirect('/admin');
});

app.post('/admin/demote', async (req,res) => {
    var username = req.body.username;

    await userCollection.updateOne({username: username}, {$set: {user_type: "user"}});
    if (req.session.username === username) {
        req.session.user_type = "user";
    }

    res.redirect('/admin');
})

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});
