const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  phone: String,
  subscription: {
    plan: {
      type: String,
      enum: ['none', 'weekly', 'monthly', 'griller'],
      default: 'none'
    },
    status: {
      type: String,
      enum: ['active', 'paused', 'cancelled'],
      default: 'active'
    },
    startDate: Date,
    nextDelivery: Date
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  price: {
    type: Number,
    required: true,
    min: 0
  },
  unit: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['beef', 'poultry', 'pork', 'lamb', 'seafood', 'exotic']
  },
  image: {
    type: String,
    required: true
  },
  stock: {
    type: Number,
    default: 0,
    min: 0
  },
  featured: {
    type: Boolean,
    default: false
  },
  tags: [String]
}, {
  timestamps: true
});

module.exports = mongoose.model('Product', productSchema);

const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    quantity: {
      type: Number,
      required: true,
      min: 1
    },
    price: {
      type: Number,
      required: true
    }
  }],
  total: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  shippingAddress: {
    name: String,
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  paymentMethod: String,
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'failed'],
    default: 'pending'
  },
  stripePaymentIntentId: String
}, {
  timestamps: true
});

module.exports = mongoose.model('Order', orderSchema);

const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create new user
    const user = new User({ name, email, password });
    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d'
    });

    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        subscription: user.subscription
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get current user
router.get('/me', async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

module.exports = router;

const express = require('express');
const Product = require('../models/Product');
const router = express.Router();

// Get all products with filtering
router.get('/', async (req, res) => {
  try {
    const { category, featured, search, page = 1, limit = 12 } = req.query;
    
    let query = {};
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.featured = true;
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const products = await Product.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await Product.countDocuments(query);

    res.json({
      products,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get single product
router.get('/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Create product (admin only)
router.post('/', async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

module.exports = router;

const express = require('express');
const jwt = require('jsonwebtoken');
const Order = require('../models/Order');
const Product = require('../models/Product');
const router = express.Router();

// Middleware to verify token
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Create order
router.post('/', auth, async (req, res) => {
  try {
    const { items, shippingAddress, paymentMethod } = req.body;

    // Calculate total and verify products
    let total = 0;
    const orderItems = [];

    for (const item of items) {
      const product = await Product.findById(item.product);
      if (!product) {
        return res.status(400).json({ message: `Product ${item.product} not found` });
      }

      if (product.stock < item.quantity) {
        return res.status(400).json({ message: `Insufficient stock for ${product.name}` });
      }

      const itemTotal = product.price * item.quantity;
      total += itemTotal;

      orderItems.push({
        product: product._id,
        quantity: item.quantity,
        price: product.price
      });

      // Update stock
      product.stock -= item.quantity;
      await product.save();
    }

    const order = new Order({
      user: req.userId,
      items: orderItems,
      total,
      shippingAddress,
      paymentMethod
    });

    await order.save();
    res.status(201).json(order);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user orders
router.get('/my-orders', auth, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.userId })
      .populate('items.product')
      .sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get single order
router.get('/:id', auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('items.product');
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    if (order.user.toString() !== req.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.json(order);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

module.exports = router;

const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Subscribe to a plan
router.post('/subscribe', auth, async (req, res) => {
  try {
    const { plan } = req.body;
    
    if (!['weekly', 'monthly', 'griller'].includes(plan)) {
      return res.status(400).json({ message: 'Invalid subscription plan' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.subscription = {
      plan,
      status: 'active',
      startDate: new Date(),
      nextDelivery: calculateNextDelivery(plan)
    };

    await user.save();

    res.json({ 
      message: `Subscribed to ${plan} plan successfully`,
      subscription: user.subscription
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user subscription
router.get('/my-subscription', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user.subscription);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Cancel subscription
router.post('/cancel', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.subscription.status = 'cancelled';
    await user.save();

    res.json({ message: 'Subscription cancelled successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

function calculateNextDelivery(plan) {
  const nextDelivery = new Date();
  switch (plan) {
    case 'weekly':
      nextDelivery.setDate(nextDelivery.getDate() + 7);
      break;
    case 'monthly':
      nextDelivery.setMonth(nextDelivery.getMonth() + 1);
      break;
    case 'griller':
      nextDelivery.setMonth(nextDelivery.getMonth() + 1);
      break;
  }
  return nextDelivery;
}

module.exports = router;

const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Subscribe to a plan
router.post('/subscribe', auth, async (req, res) => {
  try {
    const { plan } = req.body;
    
    if (!['weekly', 'monthly', 'griller'].includes(plan)) {
      return res.status(400).json({ message: 'Invalid subscription plan' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.subscription = {
      plan,
      status: 'active',
      startDate: new Date(),
      nextDelivery: calculateNextDelivery(plan)
    };

    await user.save();

    res.json({ 
      message: `Subscribed to ${plan} plan successfully`,
      subscription: user.subscription
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user subscription
router.get('/my-subscription', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user.subscription);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Cancel subscription
router.post('/cancel', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.subscription.status = 'cancelled';
    await user.save();

    res.json({ message: 'Subscription cancelled successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

function calculateNextDelivery(plan) {
  const nextDelivery = new Date();
  switch (plan) {
    case 'weekly':
      nextDelivery.setDate(nextDelivery.getDate() + 7);
      break;
    case 'monthly':
      nextDelivery.setMonth(nextDelivery.getMonth() + 1);
      break;
    case 'griller':
      nextDelivery.setMonth(nextDelivery.getMonth() + 1);
      break;
  }
  return nextDelivery;
}

module.exports = router;

// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// Utility functions for API calls
const api = {
  async get(url) {
    const response = await fetch(`${API_BASE_URL}${url}`, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      }
    });
    return await response.json();
  },

  async post(url, data) {
    const response = await fetch(`${API_BASE_URL}${url}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });
    return await response.json();
  },

  async put(url, data) {
    const response = await fetch(`${API_BASE_URL}${url}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });
    return await response.json();
  },

  async delete(url) {
    const response = await fetch(`${API_BASE_URL}${url}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });
    return await response.json();
  }
};

// Product data - now fetched from backend
let products = [];
let cart = [];
let currentFilter = 'all';
let currentUser = null;

// Initialize the page
document.addEventListener('DOMContentLoaded', function() {
  checkAuthStatus();
  loadProducts();
  loadCartFromStorage();
  setupEventListeners();
});

// Check if user is logged in
async function checkAuthStatus() {
  const token = localStorage.getItem('token');
  if (token) {
    try {
      const userData = await api.get('/auth/me');
      currentUser = userData;
      updateUIForLoggedInUser();
    } catch (error) {
      localStorage.removeItem('token');
      console.error('Authentication failed:', error);
    }
  }
}

// Load products from backend
async function loadProducts() {
  try {
    const data = await api.get('/products');
    products = data.products || data;
    renderProducts();
  } catch (error) {
    console.error('Error loading products:', error);
    // Fallback to local products if API fails
    products = getFallbackProducts();
    renderProducts();
  }
}

// Fallback products if API is unavailable
function getFallbackProducts() {
  return [
    { 
      _id: 'steak-1', 
      name: 'Grass-fed Ribeye Steak', 
      price: 18.99, 
      unit: '250g', 
      category: 'beef',
      image: 'https://images.unsplash.com/photo-1588168333986-5078d3ae3976?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
      stock: 10
    },
    // ... include other fallback products
  ];
}

// Update UI when user logs in
function updateUIForLoggedInUser() {
  const accountBtn = document.getElementById('account-btn');
  if (currentUser) {
    accountBtn.innerHTML = `<i class="fas fa-user-check"></i>`;
    accountBtn.title = `Logged in as ${currentUser.name}`;
  }
}

// Modified authentication functions
async function login(email, password) {
  try {
    const result = await api.post('/auth/login', { email, password });
    
    if (result.token) {
      localStorage.setItem('token', result.token);
      currentUser = result.user;
      updateUIForLoggedInUser();
      showNotification('Login successful!');
      toggleAuthModal();
      return true;
    }
  } catch (error) {
    console.error('Login error:', error);
    alert('Login failed: ' + (error.message || 'Invalid credentials'));
  }
  return false;
}

async function register(name, email, password) {
  try {
    const result = await api.post('/auth/register', { name, email, password });
    
    if (result.token) {
      localStorage.setItem('token', result.token);
      currentUser = result.user;
      updateUIForLoggedInUser();
      showNotification('Account created successfully!');
      toggleAuthModal();
      return true;
    }
  } catch (error) {
    console.error('Registration error:', error);
    alert('Registration failed: ' + (error.message || 'Please try again'));
  }
  return false;
}

// Modified checkout function
async function checkout(orderData) {
  try {
    const result = await api.post('/orders', orderData);
    
    if (result._id) {
      // Clear cart
      cart = [];
      saveCartToStorage();
      renderCart();
      
      showNotification('Order placed successfully!');
      return true;
    }
  } catch (error) {
    console.error('Checkout error:', error);
    alert('Checkout failed: ' + (error.message || 'Please try again'));
  }
  return false;
}

// Modified subscription function
async function subscribe(plan) {
  try {
    const result = await api.post('/subscriptions/subscribe', { plan });
    
    if (result.message) {
      showNotification(result.message);
      return true;
    }
  } catch (error) {
    console.error('Subscription error:', error);
    alert('Subscription failed: ' + (error.message || 'Please try again'));
  }
  return false;
}

// Cart storage functions
function saveCartToStorage() {
  localStorage.setItem('meatmarket_cart', JSON.stringify(cart));
}

function loadCartFromStorage() {
  const savedCart = localStorage.getItem('meatmarket_cart');
  if (savedCart) {
    cart = JSON.parse(savedCart);
    renderCart();
  }
}

// Update your existing event listeners to use the new API functions
// Modify the login and signup event listeners:

document.getElementById('login-submit').addEventListener('click', async function() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  
  if (email && password) {
    await login(email, password);
  } else {
    alert('Please enter both email and password');
  }
});

document.getElementById('signup-submit').addEventListener('click', async function() {
  const name = document.getElementById('signup-name').value;
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;
  
  if (name && email && password && confirm) {
    if (password !== confirm) {
      alert('Passwords do not match');
      return;
    }
    await register(name, email, password);
  } else {
    alert('Please fill in all fields');
  }
});

// Update checkout form submission
document.getElementById('checkout-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  const shippingAddress = {
    name: document.getElementById('full-name').value,
    street: document.getElementById('address').value,
    city: document.getElementById('city').value,
    zipCode: document.getElementById('zip').value
  };
  
  const orderData = {
    items: cart.map(item => ({
      product: item.id || item._id,
      quantity: item.qty
    })),
    shippingAddress,
    paymentMethod: 'card'
  };
  
  const success = await checkout(orderData);
  if (success) {
    document.getElementById('checkout-page').style.display = 'none';
    document.body.style.overflow = '';
  }
});

// Update subscription confirmation
document.getElementById('confirm-subscription').addEventListener('click', async function() {
  const selectedPlan = document.querySelector('input[name="subscription-plan"]:checked').value;
  const success = await subscribe(selectedPlan);
  if (success) {
    toggleSubscriptionModal();
  }
});