require("./utils.js");

require("dotenv").config();
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

// Main Page with Sign up and Log in button
app.get("/", (req, res) => {
    var name = req.session.username;
    if (name) {
        var htmlLoggedIn = `
            Hello, ${name}<br>
            <a href="/members"><button>Go to Members Area</button></a><br>
            <a href="/logout"><button>Logout</button></a>
        `;
        res.send(htmlLoggedIn);
    } else {
        var html = `
            <div><a href="/signup"><button>Sign up</button></a></div>
            <div><a href="/login"><button>Log in</button></a></div>
        `;
        res.send(html);
    }
});

app.get("/nosql-injection", async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(
            `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
        );
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(
            "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
        );
        return;
    }

    const result = await userCollection
        .find({ username: username })
        .project({ username: 1, email: 1, password: 1, _id: 1 })
        .toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/signup", (req, res) => {
    var html = `
        Create User
        <form action='/submitUser' method='post'>
        <input name="username" type="text" placeholder="Name"></input><br>
        <input name="email" type="email" placeholder="Email"></input><br>
        <input name="password" type="password" placeholder="Password"></input><br>
        <button>Submit</button>
        </form>
    `;
    res.send(html);
});

app.get("/login", (req, res) => {
    var html = `
    Log In
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='Email'><br>
    <input name='password' type='password' placeholder='Password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
        var result = "";
        if (!username) {
            result += 1;
        } else {
            result += 0;
        }
        if (!email) {
            result += 1;
        } else {
            result += 0;
        }
        if (!password) {
            result += 1;
        } else {
            result += 0;
        }
        res.redirect("/signupSubmit/" + result);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
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

    const schema = Joi.string().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/loginSubmit");
        return;
    }

    const result = await userCollection
        .find({ email: email })
        .project({ username: 1, email: 1, password: 1, _id: 1 })
        .toArray();

    var username = result[0].username;

    console.log(result);
    console.log();
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginSubmit");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/members");
        return;
    } else {
        console.log("incorrect password");
        res.redirect("/loginSubmit");
        return;
    }
});

app.get("/signupSubmit/:id", (req, res) => {
    var result = req.params.id;

    var numEmpty = 0;
    var html = `
        Please provide
    `;


    if (result.substring(0, 1) === "1") {
        html += "a name";
        numEmpty++;
    }
    if (result.substring(1, 2) === "1") {
        if (numEmpty >= 1) {
            html += ", ";
        }
        if (numEmpty >= 1 && result.substring(2, 3) === "0") {
            html += "and ";
        }
        html += "an email address";
        numEmpty++;
    }
    if (result.substring(2, 3) === "1") {
        if (numEmpty >= 1) {
            html += ", and ";
        }
        html += "a password";
    }

    html += `. 
        <br>
        <br>
        <a href="/signup">Try again</a>
    `;

    res.send(html);
});

app.get("/members", (req, res) => {
    var name = req.session.username;
    if (!req.session.authenticated) {
        res.redirect("/");
    }
    var html = `
        <h1>Hello, ${name}.</h1>
    `;
    // Generate a random number from 1,2,3
    var randomNum = Math.floor(Math.random() * (4 - 1)) + 1;
    if (randomNum == 1) {
        html += `
            <img src="/fluffy.gif" style="width:250px;"><br>
        `;
    } else if (randomNum == 2) {
        html += `
            <img src="/kitten.gif" style="width:250px;"><br>
        `;
    } else {
        html += `
            <img src="/socks.gif" style="width:250px;"><br>
        `;
    }
    html += `
        <a href="/logout"><button>Sign out</button></a>
    `;
    res.send(html);
});

app.get("/loginSubmit", (req, res) => {
    var html = `
        Invalid email/password combination
        <br>
        <br>
        <a href="/login">Try again<a>
    `;
    res.send(html);
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});
