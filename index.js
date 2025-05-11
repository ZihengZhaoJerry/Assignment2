require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection string built from .env variables
const dbUser = process.env.MONGODB_USER;
const dbPass = process.env.MONGODB_PASSWORD;
const dbHost = process.env.MONGODB_HOST;
const dbName = process.env.MONGODB_DATABASE;

const dbUri = `mongodb+srv://${dbUser}:${dbPass}@${dbHost}/${dbName}?retryWrites=true&w=majority`;


// Connect to MongoDB
mongoose.connect(dbUri);

// Define User schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  user_type: { type: String, default: 'user' } // 'user' or 'admin'
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Session Setup
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: dbUri,
    ttl: 60 * 60 
  })
}));

// Home Page
app.get('/', (req, res) => {
  const user = req.session.user;
  res.render('home', { user });
});

// Sign Up GET
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

// Sign Up POST
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  
  if (!name || !email || !password) {
    return res.render('signup', { error: "Please fill in all fields." });
  }

  // Joi Validation
  const schema = Joi.object({
    name: Joi.string().alphanum().min(2).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(5).max(50).required()
  });

  const { error } = schema.validate({ name, email, password });

  if (error) {
    return res.render('signup', { error: error.details[0].message });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();

  req.session.user = { name };
  res.redirect('/members');
});

// Log In GET
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Log In POST
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', { error: "Please enter both email and password." });
  }

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(5).max(50).required()
  });

  const { error } = schema.validate({ email, password });

  if (error) {
    return res.render('login', { error: error.details[0].message });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.render('login', { error: "User and password not found." });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.render('login', { error: "User and password not found." });
  }

 // Corrected - Store the full user object, including user_type
  req.session.user = {
  _id: user._id,
  name: user.name,
  email: user.email,
  user_type: user.user_type 
};

  res.redirect('/members');
});

// Admin page
app.get('/admin', async (req, res) => {
  // Check if the user is logged in
  if (!req.session.user) {
      return res.redirect('/login');
  }

  // Check if the user is an admin
  if (req.session.user.user_type !== 'admin') {
      return res.status(403).send('Not authorized');
  }

  // Fetch all users from the database
  const users = await User.find().lean(); // Use lean() for faster rendering
  res.render('admin', { users });
});

// Promote a user to admin
app.get('/promote/:id', async (req, res) => {
  if (!req.session.user || req.session.user.user_type !== 'admin') {
      return res.status(403).send('Not authorized');
  }

  await User.updateOne({ _id: req.params.id }, { user_type: 'admin' });
  res.redirect('/admin');
});

// Demote a user to regular user
app.get('/demote/:id', async (req, res) => {
  if (!req.session.user || req.session.user.user_type !== 'admin') {
      return res.status(403).send('Not authorized');
  }

  await User.updateOne({ _id: req.params.id }, { user_type: 'user' });
  res.redirect('/admin');
});

// Members Page
app.get('/members', (req, res) => {
  if (!req.session.user) {
      return res.redirect('/');
  }

  // List all available images
  const images = ['Cat1.jpg', 'Cat2.jpg', 'Cat3.jpg'];
  const name = req.session.user.name;

  res.render('members', { name, images });
});


app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err); 
    }
    res.redirect('/');
  });
});

// 404 Page
app.use((req, res) => {
  res.status(404).render('404');
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});