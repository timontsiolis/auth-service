require('dotenv').config();

const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { request } = require('https');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set('view-engine', 'ejs');

var refreshTokens = []; //TODO change in production 
var users = []; //TODO change in production 

app.delete('/logout', (req, res) => {
	//TODO Logout production
	refreshTokens = refreshTokens.filter(token => token !== req.body.token);
	res.sendStatus(204);
})

app.post('/token', (req, res) => {
	const refreshToken = req.body.token;
	if (refreshToken == null) return res.sendStatus(401);
	if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
	jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
		if (err) return res.sendStatus(403);
		const accessToken = generateAccessToken({ name: user.name });
		res.json({ accessToken: accessToken });
	})
});

app.get('/login', (req, res) => {
	res.render('login.ejs')
});

app.post('/login', authUser, (req, res) => {
	//Authenticate user

	const username = req.body.username;
	const user = { name: username };

	const accessToken = generateAccessToken(user);
	const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
	refreshTokens.push(refreshToken);
	res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

app.get('/register', (req, res) => {
	res.render('register.ejs')
});

app.post('/register', async (req, res) => {
	try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10);
		users.push({
			id: Date.now().toString(),
			name: req.body.name,
			email: req.body.email,
			password: hashedPassword
		});
		res.redirect('/login');
	} catch (err) {
		res.redirect('/register');
	}
	console.log(users);
});

function generateAccessToken(user) {
	return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' });
}

function authUser(req, res) {
	bcrypt.compareSync(req.body.password, users.filter(email => req.body.email).password, (err, result) => {//todo
		if(result == true)return res.redirect('/login');
		res.sendStatus(401);
	});
}

app.listen(3000, () => {
	console.log('Auth server is listening on port 3000!')
});
