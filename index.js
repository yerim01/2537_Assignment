
require("./utils.js");

require('dotenv').config();
const url = require('url');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
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

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

const { ObjectId } = require('mongodb');

app.set('view engine', 'ejs');

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Login", link: "/login"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/moon"}
]

app.use(express.urlencoded({extended: false})); //middle ware

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

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
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

//middle ware
app.use("/", (req,res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        res.render("index_noLogin");
    } else {
        res.render("index_loggedIn", {req: req});
    }
});

app.get('/nosql-injection', async (req,res) => {
	var name = req.query.user;

	if (!name) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+name);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(name);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({name: name}).project({name: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${name}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Yerim Moon</h1>");
});


app.get('/signup', (req,res) => {
    res.render("signup");
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/signupSubmit', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
		name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
		password: Joi.string().max(20).required()
	});
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
        var errorMessage = validationResult.error.message;
        console.log(validationResult.error);
        res.render("signupError", {errorMessage: errorMessage});
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
        email: Joi.string().email().required(),
		password: Joi.string().max(20).required()
	});
	
    const result = await userCollection.findOne({ email });
    if (!result) {
        return res.render("invalidLogin");
    }

    // const result2 = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, user_type: 1, _id: 1}).toArray();
    const passwordMatches = await bcrypt.compare(password, result.password);
    if (passwordMatches) {
        req.session.authenticated = true;
        req.session.name = result.name;
        req.session.email = email;
        req.session.user_type = result.user_type;
        req.session.cookie.maxAge = expireTime;

        return res.redirect('/members');
    } else {
        return res.render("invalidLogin");
    }
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        res.render("members");
    }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id: 1, user_type: 1}).toArray();
 
    res.render("admin", {users: result});
});

app.get('/promote/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await userCollection.updateOne({ _id: ObjectId(id) }, { $set: { user_type: 'admin' } });
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});
  
app.get('/demote/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await userCollection.updateOne({ _id: ObjectId(id) }, { $set: { user_type: 'user' } });
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});
  
app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 