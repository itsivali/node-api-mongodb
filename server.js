const express = require('express');
const app = express();
const port = 3000;
const User = require('./user')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult } = require('express-validator');


app.use(cors());


const rateLimit = require('express-rate-limit');


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
}); 

app.use(limiter);

app.post(
  '/register',
  body('username').isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  (req, res) => {
    const { username, password } = req.body;

    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const newUser = new User({
      username,
      password,
    });

    newUser.save((err) => {
      if (err) {
        console.error(err);
        res.status(500).send('Error registering new user');
      } else {
        res.status(200).send('User registered successfully');
      }
    });
  }
);

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username }, (err, user) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error logging in');
    } else if (!user) {
      res.status(401).send('User not found');
    } else {
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          console.error(err);
          res.status(500).send('Error logging in');
        } else if (isMatch) {

          const token = jwt.sign({ username: user.username }, 'your-secret-key');
          res.status(200).json({ token });
        } else {
          res.status(401).send('Incorrect password');
        }
      });
    }
  });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      console.error(err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.send('This is a protected endpoint');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  const newUser = new User({
    username,
    password,
  });

  newUser.save((err) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error registering new user');
    } else {
      res.status(200).send('User registered successfully');
    }
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username }, (err, user) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error logging in');
    } else if (!user) {
      res.status(401).send('User not found');
    } else {
      user.comparePassword(password, (err, isMatch) => {
        if (err) {
          console.error(err);
          res.status(500).send('Error logging in');
        } else if (isMatch) {
          res.status(200).send('Login successful');
        } else {
          res.status(401).send('Incorrect password');
        }
      });
    }
  });
});

app.use(express.json());
app.get('/', (req, res) => {
  res.send('API is running');
});

app.listen(port, () => {
  console.log(`Server listening on port http://localhost:${port}`);
});
