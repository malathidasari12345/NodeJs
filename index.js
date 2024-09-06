const express = require('express'); 
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const app = express();
app.set("view engine", "ejs");

// MongoDB connection
const url = 'mongodb://localhost:27017/Task';
mongoose.connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('connected', () => {
    console.log("Connected to MongoDB server successfully");
});
db.on('error', (err) => {
    console.log("Error occurred", err);
});
db.on('disconnected', () => {
    console.log("Disconnected from MongoDB server successfully");
});

// User schema and model
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    }
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Authentication middleware
const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        try {
            const decoded = jwt.verify(token, "asdfghjkl");
            req.user = await User.findById(decoded._id);
            next();
        } catch (err) {
            res.redirect("/login");
        }
    } else {
        res.redirect("/login");
    }
};

// Routes
app.get("/", isAuthenticated, (req, res) => {
    res.render("logout", { name: req.user.name });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) {
        return res.redirect("/login");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
        name,
        email,
        password : hashedPassword
    });
    const token = jwt.sign({ _id: newUser._id }, "asdfghjkl");
    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect('/');
});
app.get("/login", (req, res) => {
    res.render("login", { email: "", message: "" });
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    let user = await User.findOne({ email });
    if (!user) {
        return res.redirect("/register");
    }
    const isMatch = await bcrypt.compare(password,user.password)
    if (!isMatch) {
        return res.render("login", { email, message: "Password is Incorrect" });
    }
    const token = jwt.sign({ _id: user._id }, "asdfghjkl");
    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect('/');
});



app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now())
    });
    res.redirect('/');
});

// Start server
app.listen(5000, () => {
    console.log("Server is running on port 5000");
});
