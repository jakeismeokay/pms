// server.js - Basic Backend for Parking Management System (without Task Controllers)

// --- 1. Import necessary modules ---
const express = require("express"); // Web framework for Node.js
const mongoose = require("mongoose"); // ODM for MongoDB
const dotenv = require("dotenv"); // To load environment variables from .env file
const bcrypt = require("bcryptjs"); // For password hashing
const jwt = require("jsonwebtoken"); // For creating and verifying JSON Web Tokens

// Load environment variables from .env file
dotenv.config();

// --- 2. Initialize Express App ---
const app = express();
const PORT = process.env.PORT || 5001; // Default to 5001 if PORT not set in .env

// --- 3. Middleware ---
app.use(express.json()); // Body parser for JSON requests

// Basic CORS setup (for development, allows frontend to communicate)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // Allow all origins for simplicity
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

// --- 4. Database Connection ---
const MONGO_URI = process.env.MONGO_URI;

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected successfully!"))
  .catch((err) => console.error("MongoDB connection error:", err));

// --- 5. Mongoose Schemas (Models) ---
// In a real app, these would be in separate files like models/User.js

// User Schema
const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // Add any user profile fields here
    firstName: { type: String },
    lastName: { type: String },
    phoneNumber: { type: String },
  },
  { timestamps: true }
);

// Hash password before saving
UserSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

const User = mongoose.model("User", UserSchema);

// --- 6. Authentication Middleware ---
// In a real app, this would be in middleware/authMiddleware.js
const protect = (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1]; // Get token from header
      const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
      req.user = decoded.id; // Attach user ID to request
      next();
    } catch (error) {
      res.status(401).json({ message: "Not authorized, token failed" });
    }
  }
  if (!token) {
    res.status(401).json({ message: "Not authorized, no token" });
  }
};

// --- 7. Controllers (Route Handlers) ---
// In a real app, these would be in controllers/authController.js and controllers/paymentController.js

// Generate JWT Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1h" }); // Token expires in 1 hour
};

// @desc    Register a new user
// @route   POST /api/auth/signup
// @access  Public
const registerUser = async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }
    const user = await User.create({ username, email, password });
    if (user) {
      res.status(201).json({
        _id: user._id,
        username: user.username,
        email: user.email,
        token: generateToken(user._id),
      });
    } else {
      res.status(400).json({ message: "Invalid user data" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Authenticate user & get token
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      res.json({
        _id: user._id,
        username: user.username,
        email: user.email,
        token: generateToken(user._id),
      });
    } else {
      res.status(401).json({ message: "Invalid email or password" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
const updateUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user); // req.user set by 'protect' middleware
    if (user) {
      user.username = req.body.username || user.username;
      user.email = req.body.email || user.email;
      user.firstName = req.body.firstName || user.firstName;
      user.lastName = req.body.lastName || user.lastName;
      user.phoneNumber = req.body.phoneNumber || user.phoneNumber;
      if (req.body.password) {
        user.password = req.body.password; // Pre-save hook will hash it
      }
      const updatedUser = await user.save();
      res.json({
        _id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        phoneNumber: updatedUser.phoneNumber,
        token: generateToken(updatedUser._id), // Generate new token if profile updated
      });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Logout user (client-side token removal)
// @route   GET /api/auth/logout
// @access  Public (or Private if token invalidation is handled server-side)
// Note: True logout in JWT usually involves client-side token removal.
// This is a placeholder for a clear endpoint.
const logoutUser = (req, res) => {
  res.json({ message: "User logged out (token removed client-side)" });
};

// @desc    Process a payment
// @route   POST /api/payment
// @access  Private (usually, payment APIs are protected)
const processPayment = async (req, res) => {
  const { cardNumber, expiryDate, cvv, cardHolderName, amount } = req.body;

  // In a real application, this would involve:
  // 1. Sending card data to a payment gateway (e.g., Stripe, PayPal).
  // 2. Handling the gateway's response (success/failure).
  // 3. Storing transaction details in your database (e.g., a 'Payment' model).
  // 4. Updating parking slot status or user account based on payment success.

  if (!cardNumber || !expiryDate || !cvv || !cardHolderName || !amount) {
    return res.status(400).json({ message: "Missing payment details." });
  }

  try {
    // Simulate a payment processing delay
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // For this basic example, we'll just log the details and send a success message.
    console.log(
      `Processing payment for ${cardHolderName} with amount ${amount}`
    );
    console.log(
      `Card Number: ${cardNumber}, Expiry: ${expiryDate}, CVV: ${cvv}`
    );

    // You'd typically get a transaction ID or confirmation from the payment gateway here
    const transactionId = `TXN_${Date.now()}`;

    res.status(200).json({
      message: "Payment processed successfully!",
      transactionId: transactionId,
      amount: amount,
      status: "completed",
    });
  } catch (error) {
    console.error("Payment processing error:", error);
    res.status(500).json({ message: "Payment failed. Please try again." });
  }
};

// --- 8. Routes ---
// In a real app, these would be in separate files like routes/authRoutes.js, routes/paymentRoutes.js

// Auth Routes
app.post("/api/auth/signup", registerUser);
app.post("/api/auth/login", loginUser);
app.put("/api/auth/profile", protect, updateUserProfile);
app.get("/api/auth/logout", logoutUser); // Client-side token removal is primary logout

// Payment Route
app.post("/api/payment", protect, processPayment); // Protect payment route

// --- 9. Start the Server ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access frontend at http://localhost:3000 (if running)`);
  console.log(`Backend API base URL: http://localhost:${PORT}/api`);
});
