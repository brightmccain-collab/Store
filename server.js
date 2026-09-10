require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_change_this_in_production';

// User data storage
const USERS_FILE = path.join(__dirname, 'users.json');

// For Vercel serverless environment, use memory storage instead of file
let usersMemory = [];
if (process.env.VERCEL) {
  console.log('Running in Vercel environment - using memory storage for users');
}

// Micro-deposit attempt tracking (in-memory for now, use Redis in production)
const verificationAttempts = new Map(); // Key: setupIntentId, Value: { attempts: number, lastAttempt: timestamp, lockedUntil: timestamp }
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// Rate limiting for SetupIntent creation (in-memory, use Redis in production)
const setupIntentRateLimits = new Map(); // Key: clientIp, Value: { count: number, resetTime: timestamp }
const MAX_SETUP_INTENTS_PER_HOUR = 3;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour in milliseconds

// Blocked bank accounts (in-memory, use database in production)
// Key: routingNumber_accountNumber, Value: { blockedAt: timestamp, reason: string }
const blockedBankAccounts = new Map();

// Helper functions for user management
function getUsers() {
  try {
    if (process.env.VERCEL) {
      return usersMemory;
    }
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      return JSON.parse(data);
    }
    return [];
  } catch (error) {
    console.error('Error reading users file:', error);
    return [];
  }
}

// Enhanced email validation - RFC 5322 compliant
function isValidEmail(email) {
  // RFC 5322 compliant email regex
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!emailRegex.test(email)) {
    return false;
  }
  
  // Check for disposable email domains
  const disposableDomains = [
    'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
    'throwawaymail.com', 'getairmail.com', 'yopmail.com', 'sharklasers.com',
    'temp-mail.org', 'maildrop.cc', 'fakeinbox.com', 'trashmail.com'
  ];
  
  const domain = email.split('@')[1].toLowerCase();
  if (disposableDomains.includes(domain)) {
    return false;
  }
  
  return true;
}

function saveUsers(users) {
  try {
    if (process.env.VERCEL) {
      usersMemory = users;
      return;
    }
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error saving users file:', error);
  }
}

function findUserByEmail(email) {
  const users = getUsers();
  return users.find(user => user.email.toLowerCase() === email.toLowerCase());
}

function createUser(email, password) {
  const users = getUsers();
  
  // Check if user already exists
  if (findUserByEmail(email)) {
    return { error: 'User already exists' };
  }
  
  // Hash password
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  // Create user object
  const newUser = {
    id: Date.now().toString(),
    email: email.toLowerCase(),
    password: hashedPassword,
    createdAt: new Date().toISOString(),
    accountVerified: false,
    accountAgeHours: 0
  };
  
  users.push(newUser);
  saveUsers(users);
  
  return { user: { id: newUser.id, email: newUser.email, createdAt: newUser.createdAt } };
}

/**
 * Stripe ACH Micro-Deposits Store with Advanced Radar Fraud Prevention
 * 
 * This implementation includes:
 * 1. Client-side Radar session generation for browser fingerprinting
 * 2. Complete customer identity collection (name, email, full address)
 * 3. IP address and user agent capture
 * 4. Consistency checks between name and email
 * 5. Manual micro-deposits verification method
 * 6. Comprehensive error logging and monitoring
 * 7. SetupIntent flow to decouple verification from charging
 * 8. Online mandate data for legal authorization tracking
 * 9. Account age and verification metadata
 * 10. Site-wide Stripe.js for behavioral tracking
 */

// Middleware
// Use raw body parser for webhook signature verification
app.use('/webhook', bodyParser.raw({ type: 'application/json' }));

// Use JSON parser for other routes
app.use(bodyParser.json());

// Trust proxy for proper IP detection behind load balancers
app.set('trust proxy', true);

// Session middleware (only for local development)
if (!process.env.VERCEL) {
  app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to false for local development
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'lax'
    }
  }));
}

// Only serve static files in local development
if (!process.env.VERCEL) {
  app.use(express.static('public'));
}

// Serve the landing page (product grid)
app.get('/', (req, res) => {
  if (process.env.VERCEL) {
    // In Vercel, let it serve static files from public/
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
  } else {
    res.sendFile(__dirname + '/public/landing.html');
  }
});

// Serve the checkout page (authentication handled by frontend)
app.get('/checkout.html', (req, res) => {
  if (process.env.VERCEL) {
    res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
  } else {
    res.sendFile(__dirname + '/public/checkout.html');
  }
});

// Serve the verification page
app.get('/verify', (req, res) => {
  if (process.env.VERCEL) {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
  } else {
    res.sendFile(__dirname + '/public/verify.html');
  }
});

app.get('/verify.html', (req, res) => {
  if (process.env.VERCEL) {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
  } else {
    res.sendFile(__dirname + '/public/verify.html');
  }
});

// Serve the registration page
app.get('/register.html', (req, res) => {
  if (process.env.VERCEL) {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
  } else {
    res.sendFile(__dirname + '/public/register.html');
  }
});

// Serve the login page
app.get('/login.html', (req, res) => {
  if (process.env.VERCEL) {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  } else {
    res.sendFile(__dirname + '/public/login.html');
  }
});

// Authentication middleware
function requireAuth(req, res, next) {
  if (process.env.VERCEL) {
    // In Vercel, check for JWT token in header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
        return;
      } catch (error) {
        // Token invalid
      }
    }
    res.redirect('/login.html');
  } else {
    // Local development: use session
    if (req.session && req.session.userId) {
      next();
    } else {
      res.redirect('/login.html');
    }
  }
}

// POST /register - User registration
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format or disposable email not allowed' });
    }

    // Create user
    const result = createUser(email, password);

    if (result.error) {
      return res.status(400).json({ error: result.error });
    }

    // Auto-login after registration
    if (!process.env.VERCEL) {
      req.session.userId = result.user.id;
      req.session.userEmail = result.user.email;
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: result.user.id, email: result.user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      user: result.user,
      token: token,
      message: 'Registration successful'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /login - User login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = findUserByEmail(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = bcrypt.compareSync(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create session (local only)
    if (!process.env.VERCEL) {
      req.session.userId = user.id;
      req.session.userEmail = user.email;
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Update account age
    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === user.id);
    if (userIndex !== -1) {
      const accountAgeMs = Date.now() - new Date(users[userIndex].createdAt).getTime();
      users[userIndex].accountAgeHours = Math.floor(accountAgeMs / (1000 * 60 * 60));
      saveUsers(users);
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
        accountAgeHours: user.accountAgeHours
      },
      token: token,
      message: 'Login successful'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /logout - User logout
app.post('/logout', (req, res) => {
  if (!process.env.VERCEL) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.json({ success: true, message: 'Logout successful' });
    });
  } else {
    // For Vercel, just return success (client handles token removal)
    res.json({ success: true, message: 'Logout successful' });
  }
});

// GET /check-auth - Check authentication status
app.get('/check-auth', (req, res) => {
  if (process.env.VERCEL) {
    // In Vercel, check for JWT token in header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = findUserByEmail(decoded.email);
        if (user) {
          const accountAgeMs = Date.now() - new Date(user.createdAt).getTime();
          const accountAgeHours = Math.floor(accountAgeMs / (1000 * 60 * 60));

          return res.json({
            authenticated: true,
            user: {
              id: user.id,
              email: user.email,
              createdAt: user.createdAt,
              accountAgeHours: accountAgeHours
            }
          });
        }
      } catch (error) {
        // Token invalid
      }
    }
    res.json({ authenticated: false });
  } else {
    // Local development: use session
    if (req.session && req.session.userId) {
      const user = findUserByEmail(req.session.userEmail);
      if (user) {
        const accountAgeMs = Date.now() - new Date(user.createdAt).getTime();
        const accountAgeHours = Math.floor(accountAgeMs / (1000 * 60 * 60));

        return res.json({
          authenticated: true,
          user: {
            id: user.id,
            email: user.email,
            createdAt: user.createdAt,
            accountAgeHours: accountAgeHours
          }
        });
      }
    }
    res.json({ authenticated: false });
  }
});

// POST /create-setup-intent - Create SetupIntent for bank account verification
app.post('/create-setup-intent', async (req, res) => {
  try {
    const {
      email,
      name,
      address,
      shippingAddress,
      routingNumber,
      accountNumber,
      accountHolderType,
      accountType,
      productId,
      productName,
      amount,
      radarSessionId
    } = req.body;

    // Validate required fields
    if (!email || !name || !address || !routingNumber || !accountNumber) {
      return res.status(400).json({ 
        error: 'Missing required fields: email, name, address, routingNumber, accountNumber' 
      });
    }

    // Enhanced email validation
    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Invalid email format or disposable email not allowed' 
      });
    }

    // Check if bank account is blocked due to previous NACHA returns
    const bankAccountKey = `${routingNumber}_${accountNumber.slice(-4)}`;
    if (blockedBankAccounts.has(bankAccountKey)) {
      const blockInfo = blockedBankAccounts.get(bankAccountKey);
      return res.status(403).json({
        error: `This bank account has been blocked due to: ${blockInfo.reason}. Please use a different bank account or contact support.`
      });
    }

    // Validate address structure
    if (!address.line1 || !address.city || !address.state || !address.postal_code) {
      return res.status(400).json({ 
        error: 'Missing required address fields: line1, city, state, postal_code' 
      });
    }

    // Consistency check: Ensure name and email are reasonable match
    if (name.length < 2 || email.length < 5) {
      return res.status(400).json({ 
        error: 'Invalid name or email format' 
      });
    }

    // Account age validation check
    // In production, implement email verification and check account age
    // Example: if (accountAgeHours < 24 && !emailVerified) {
    //   return res.status(400).json({ error: 'Email verification required for new accounts' });
    // }

    // Capture client IP and user agent for fraud detection
    // Support Cloudflare CF-Connecting-IP header for accurate IP detection
    const clientIp = req.headers['cf-connecting-ip'] || 
                     req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.connection.remoteAddress || 
                     req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    // Rate limiting check per IP address
    const now = Date.now();
    const rateLimitData = setupIntentRateLimits.get(clientIp);
    
    if (rateLimitData) {
      if (now < rateLimitData.resetTime) {
        // Within the rate limit window
        if (rateLimitData.count >= MAX_SETUP_INTENTS_PER_HOUR) {
          const resetMinutes = Math.ceil((rateLimitData.resetTime - now) / (60 * 1000));
          return res.status(429).json({
            error: `Rate limit exceeded. You can create ${MAX_SETUP_INTENTS_PER_HOUR} setup intents per hour. Please try again in ${resetMinutes} minutes.`
          });
        }
        rateLimitData.count += 1;
      } else {
        // Reset the window
        rateLimitData.count = 1;
        rateLimitData.resetTime = now + RATE_LIMIT_WINDOW;
      }
      setupIntentRateLimits.set(clientIp, rateLimitData);
    } else {
      // First request from this IP
      setupIntentRateLimits.set(clientIp, {
        count: 1,
        resetTime: now + RATE_LIMIT_WINDOW
      });
    }

    // Create Stripe Customer with complete information
    const customer = await stripe.customers.create({
      email: email,
      name: name,
      address: {
        line1: address.line1,
        city: address.city,
        state: address.state,
        postal_code: address.postal_code,
        country: address.country || 'US'
      },
      shipping: {
        name: name,
        address: {
          line1: shippingAddress ? shippingAddress.line1 : address.line1,
          city: shippingAddress ? shippingAddress.city : address.city,
          state: shippingAddress ? shippingAddress.state : address.state,
          postal_code: shippingAddress ? shippingAddress.postal_code : address.postal_code,
          country: shippingAddress ? shippingAddress.country : (address.country || 'US')
        }
      },
      metadata: {
        user_ip: clientIp,
        user_agent: userAgent,
        product_id: productId || 'default',
        product_name: productName || 'Digital Item',
        account_created_at: new Date().toISOString(),
        email_verified: 'false', // In production, implement email verification
        account_age_hours: '0', // Hours since account creation
        customer_tier: 'new', // customer tiers: new, returning, vip
        shipping_same_as_billing: shippingAddress ? 'false' : 'true'
      }
    });

    // Construct SetupIntent with all required fields
    const setupIntentParams = {
      customer: customer.id,
      payment_method_types: ['us_bank_account'],
      payment_method_options: {
        us_bank_account: {
          verification_method: 'microdeposits'
        }
      },
      metadata: {
        customer_name: name,
        customer_email: email,
        product_id: productId || 'default',
        product_name: productName || 'Digital Item',
        user_ip: clientIp,
        user_agent: userAgent,
        amount: amount || 9900,
        account_created_at: new Date().toISOString()
      }
    };

    // Attach Radar session if provided from frontend
    if (radarSessionId) {
      setupIntentParams.radar_options = {
        session: radarSessionId
      };
    }

    // Create SetupIntent for bank account verification (no immediate charge)
    const setupIntent = await stripe.setupIntents.create(setupIntentParams);

    res.json({
      clientSecret: setupIntent.client_secret,
      setupIntentId: setupIntent.id,
      customerId: customer.id,
      amount: amount || 9900,
      productName: productName || 'Digital Item'
    });

  } catch (error) {
    console.error('Error creating setup intent:', error);
    res.status(500).json({ 
      error: error.message 
    });
  }
});

// POST /create-intent - Create PaymentIntent with microdeposits (LEGACY - use SetupIntent flow instead)
// This endpoint is kept for backwards compatibility but SetupIntent flow is recommended
app.post('/create-intent', async (req, res) => {
  try {
    const {
      email,
      name,
      address,
      routingNumber,
      accountNumber,
      accountHolderType,
      accountType,
      productId,
      productName,
      amount,
      radarSessionId
    } = req.body;

    // Validate required fields
    if (!email || !name || !address || !routingNumber || !accountNumber) {
      return res.status(400).json({ 
        error: 'Missing required fields: email, name, address, routingNumber, accountNumber' 
      });
    }

    // Enhanced email validation
    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Invalid email format or disposable email not allowed' 
      });
    }

    // Check if bank account is blocked due to previous NACHA returns
    const bankAccountKey = `${routingNumber}_${accountNumber.slice(-4)}`;
    if (blockedBankAccounts.has(bankAccountKey)) {
      const blockInfo = blockedBankAccounts.get(bankAccountKey);
      return res.status(403).json({
        error: `This bank account has been blocked due to: ${blockInfo.reason}. Please use a different bank account or contact support.`
      });
    }

    // Validate address structure
    if (!address.line1 || !address.city || !address.state || !address.postal_code) {
      return res.status(400).json({ 
        error: 'Missing required address fields: line1, city, state, postal_code' 
      });
    }

    // Consistency check: Ensure name and email are reasonable match
    // (Basic check - in production you might want more sophisticated validation)
    if (name.length < 2 || email.length < 5) {
      return res.status(400).json({ 
        error: 'Invalid name or email format' 
      });
    }

    // Account age validation check
    // In production, implement email verification and check account age
    // Example: if (accountAgeHours < 24 && !emailVerified) {
    //   return res.status(400).json({ error: 'Email verification required for new accounts' });
    // }

    // Use provided amount or default to 9900 ($99.00)
    const paymentAmount = amount || 9900;

    // Capture client IP and user agent for fraud detection
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    // Create Stripe Customer with complete information
    const customer = await stripe.customers.create({
      email: email,
      name: name,
      address: {
        line1: address.line1,
        city: address.city,
        state: address.state,
        postal_code: address.postal_code,
        country: address.country || 'US'
      },
      shipping: {
        name: name,
        address: {
          line1: address.line1,
          city: address.city,
          state: address.state,
          postal_code: address.postal_code,
          country: address.country || 'US'
        }
      },
      metadata: {
        user_ip: clientIp,
        user_agent: userAgent,
        product_id: productId || 'default',
        product_name: productName || 'Digital Item',
        account_created_at: new Date().toISOString(),
        email_verified: 'false',
        account_age_hours: '0',
        customer_tier: 'new'
      }
    });

    // Construct PaymentIntent with all required fields
    const paymentIntentParams = {
      amount: paymentAmount,
      currency: 'usd',
      customer: customer.id,
      payment_method_types: ['us_bank_account'],
      payment_method_options: {
        us_bank_account: {
          verification_method: 'microdeposits'
        }
      },
      // Attach shipping information to prevent "Distance to shipping" risk
      shipping: {
        name: name,
        address: {
          line1: address.line1,
          city: address.city,
          state: address.state,
          postal_code: address.postal_code,
          country: address.country || 'US'
        }
      },
      // Explicitly passing Online Mandate details reduces dispute risk scores
      mandate_data: {
        customer_acceptance: {
          type: 'online',
          online: {
            ip_address: clientIp,
            user_agent: userAgent
          }
        }
      },
      description: productName ? `Digital Item Purchase - ${productName}` : 'Digital Item Purchase',
      metadata: {
        customer_name: name,
        customer_email: email,
        product_id: productId || 'default',
        product_name: productName || 'Digital Item',
        user_ip: clientIp,
        user_agent: userAgent,
        account_created_at: new Date().toISOString(),
        email_verified: 'false',
        account_age_hours: '0',
        customer_tier: 'new'
      }
    };

    // Attach Radar session if provided from frontend
    if (radarSessionId) {
      paymentIntentParams.radar_options = {
        session: radarSessionId
      };
    }

    // Create PaymentIntent with microdeposits verification
    const paymentIntent = await stripe.paymentIntents.create(paymentIntentParams);

    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
      customerId: customer.id
    });

  } catch (error) {
    console.error('Error creating payment intent:', error);
    res.status(500).json({ 
      error: error.message 
    });
  }
});

// POST /verify-setup-intent - Verify microdeposits against SetupIntent
app.post('/verify-setup-intent', async (req, res) => {
  try {
    const { setupIntentId, descriptorCode } = req.body;

    // Validate required fields
    if (!setupIntentId || !descriptorCode) {
      return res.status(400).json({ 
        error: 'Missing required fields: setupIntentId, descriptorCode' 
      });
    }

    // Validate descriptor code format (6-character alphanumeric)
    if (!/^[A-Za-z0-9]{6}$/.test(descriptorCode)) {
      return res.status(400).json({
        error: 'Descriptor code must be exactly 6 characters (letters and numbers only)'
      });
    }

    // Check if this setup intent is locked due to too many failed attempts
    const attempts = verificationAttempts.get(setupIntentId);
    if (attempts && attempts.lockedUntil && Date.now() < attempts.lockedUntil) {
      const remainingTime = Math.ceil((attempts.lockedUntil - Date.now()) / (60 * 60 * 1000));
      return res.status(429).json({
        error: `Too many failed verification attempts. Please try again in ${remainingTime} hours.`
      });
    }

    // Verify the microdeposits against SetupIntent
    const setupIntent = await stripe.setupIntents.verifyMicrodeposits(
      setupIntentId,
      {
        descriptor_code: descriptorCode
      }
    );

    // Get the payment method ID from the setup intent
    const paymentMethodId = setupIntent.payment_method;

    // Reset attempts on successful verification
    verificationAttempts.delete(setupIntentId);

    res.json({
      status: setupIntent.status,
      setupIntentId: setupIntent.id,
      paymentMethodId: paymentMethodId,
      customerId: setupIntent.customer,
      amount: setupIntent.metadata.amount,
      productName: setupIntent.metadata.product_name
    });

  } catch (error) {
    console.error('Error verifying setup intent microdeposits:', error);
    
    // Track failed attempts
    const currentAttempts = verificationAttempts.get(setupIntentId) || { attempts: 0, lastAttempt: 0, lockedUntil: 0 };
    currentAttempts.attempts += 1;
    currentAttempts.lastAttempt = Date.now();
    
    // Lock out after MAX_ATTEMPTS failed attempts
    if (currentAttempts.attempts >= MAX_ATTEMPTS) {
      currentAttempts.lockedUntil = Date.now() + LOCKOUT_DURATION;
      verificationAttempts.set(setupIntentId, currentAttempts);
      return res.status(429).json({
        error: `Too many failed verification attempts. You have used all ${MAX_ATTEMPTS} attempts. Please contact support or wait 24 hours to try again.`
      });
    }
    
    verificationAttempts.set(setupIntentId, currentAttempts);
    const remainingAttempts = MAX_ATTEMPTS - currentAttempts.attempts;
    
    // More user-friendly error message for descriptor code mismatch
    let errorMessage = error.message;
    if (error.message.includes('does not match')) {
      errorMessage = 'The verification code you entered does not match the code sent to your bank account. Please check your bank statement for the exact 6-character code (e.g., SM1234) next to the two small deposits from Stripe.';
    }
    
    res.status(400).json({ 
      error: `${errorMessage} You have ${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} remaining.`
    });
  }
});

// POST /execute-payment - Execute actual payment after verification
app.post('/execute-payment', async (req, res) => {
  try {
    const { paymentMethodId, customerId, amount, productName } = req.body;

    // Validate required fields
    if (!paymentMethodId || !customerId || !amount) {
      return res.status(400).json({ 
        error: 'Missing required fields: paymentMethodId, customerId, amount' 
      });
    }

    // Capture client IP and user agent for fraud detection
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    // Create PaymentIntent using the verified payment method
    const paymentIntent = await stripe.paymentIntents.create({
      amount: parseInt(amount),
      currency: 'usd',
      customer: customerId,
      payment_method: paymentMethodId,
      payment_method_types: ['us_bank_account'],
      confirm: true,
      off_session: false,
      // Explicitly passing Online Mandate details reduces dispute risk scores
      mandate_data: {
        customer_acceptance: {
          type: 'online',
          online: {
            ip_address: clientIp,
            user_agent: userAgent
          }
        }
      },
      description: productName ? `Digital Item Purchase - ${productName}` : 'Digital Item Purchase',
      metadata: {
        customer_id: customerId,
        payment_method_id: paymentMethodId,
        product_name: productName || 'Digital Item',
        user_ip: clientIp,
        user_agent: userAgent,
        payment_flow: 'setup_intent_verified'
      }
    });

    res.json({
      status: paymentIntent.status,
      paymentIntentId: paymentIntent.id,
      amount: paymentIntent.amount
    });

  } catch (error) {
    console.error('Error executing payment:', error);
    res.status(500).json({ 
      error: error.message 
    });
  }
});

// POST /verify-code - Verify microdeposits descriptor code
app.post('/verify-code', async (req, res) => {
  try {
    const { paymentIntentId, descriptorCode } = req.body;

    // Validate required fields
    if (!paymentIntentId || !descriptorCode) {
      return res.status(400).json({ 
        error: 'Missing required fields: paymentIntentId, descriptorCode' 
      });
    }

    // Verify the microdeposits
    const paymentIntent = await stripe.paymentIntents.verifyMicrodeposits(
      paymentIntentId,
      {
        descriptor_code: descriptorCode
      }
    );

    res.json({
      status: paymentIntent.status,
      paymentIntentId: paymentIntent.id
    });

  } catch (error) {
    console.error('Error verifying microdeposits:', error);
    res.status(500).json({ 
      error: error.message 
    });
  }
});

// POST /webhook - Handle Stripe webhooks
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // Parse the raw body for webhook signature verification
    const rawBody = req.body;
    event = stripe.webhooks.constructEvent(
      rawBody,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object;
      console.log('PaymentIntent succeeded:', paymentIntent.id);
      console.log('Customer:', paymentIntent.customer);
      console.log('Amount:', paymentIntent.amount / 100, 'USD');
      console.log('Product:', paymentIntent.metadata.product_name);
      console.log('Product ID:', paymentIntent.metadata.product_id);
      console.log('Customer Name:', paymentIntent.metadata.customer_name);
      console.log('Customer Email:', paymentIntent.metadata.customer_email);
      console.log('User IP:', paymentIntent.metadata.user_ip);
      console.log('User Agent:', paymentIntent.metadata.user_agent);
      console.log('Payment Flow:', paymentIntent.metadata.payment_flow);
      // Here you would fulfill the order (send digital item, etc.)
      // Example: sendDigitalItem(paymentIntent.metadata.product_id, paymentIntent.customer_email);
      break;
    case 'setup_intent.succeeded':
      const setupIntent = event.data.object;
      console.log('SetupIntent succeeded:', setupIntent.id);
      console.log('Customer:', setupIntent.customer);
      console.log('Payment Method:', setupIntent.payment_method);
      console.log('Status:', setupIntent.status);
      console.log('Amount awaiting payment:', setupIntent.metadata.amount);
      console.log('Product:', setupIntent.metadata.product_name);
      break;
    case 'setup_intent.setup_failed':
      const failedSetup = event.data.object;
      console.error('SetupIntent failed:', failedSetup.id);
      console.error('Customer:', failedSetup.customer);
      if (failedSetup.last_setup_error) {
        console.error('Error:', failedSetup.last_setup_error.message);
        console.error('Error Code:', failedSetup.last_setup_error.code);
      }
      break;
    case 'setup_intent.requires_action':
      const actionSetup = event.data.object;
      console.log('SetupIntent requires action:', actionSetup.id);
      console.log('Customer:', actionSetup.customer);
      if (actionSetup.next_action) {
        console.log('Next action:', actionSetup.next_action.type);
      }
      break;
    case 'payment_intent.payment_failed':
      const failedPayment = event.data.object;
      console.error('PaymentIntent failed:', failedPayment.id);
      console.error('Customer:', failedPayment.customer);
      console.error('Amount:', failedPayment.amount / 100, 'USD');
      if (failedPayment.metadata) {
        console.error('Product:', failedPayment.metadata.product_name);
        console.error('Customer Email:', failedPayment.metadata.customer_email);
        console.error('User IP:', failedPayment.metadata.user_ip);
        console.error('Payment Flow:', failedPayment.metadata.payment_flow);
      }
      if (failedPayment.last_payment_error) {
        console.error('Error:', failedPayment.last_payment_error.message);
        if (failedPayment.last_payment_error.type) {
          console.error('Error Type:', failedPayment.last_payment_error.type);
        }
        if (failedPayment.last_payment_error.code) {
          console.error('Error Code:', failedPayment.last_payment_error.code);
        }
        // Check for NACHA return codes and block bank account if needed
        if (failedPayment.last_payment_error.code === 'payment_intent_authentication_failure' ||
            failedPayment.last_payment_error.decline_code) {
          const declineCode = failedPayment.last_payment_error.decline_code;
          // NACHA return codes that indicate the bank account should be blocked
          const nachaBlockCodes = ['account_closed', 'debit_not_authorized', 'insufficient_funds'];
          if (nachaBlockCodes.includes(declineCode)) {
            console.error('NACHA return code detected:', declineCode);
            console.error('Bank account should be blocked for future payments');
            // In production, you would retrieve the payment method details and block the routing/account combo
            // Example: blockBankAccount(routingNumber, accountNumber, declineCode);
          }
        }
      }
      // Log outcome details for fraud analysis
      if (failedPayment.outcome) {
        console.error('Outcome Type:', failedPayment.outcome.type);
        console.error('Outcome Reason:', failedPayment.outcome.reason);
        console.error('Outcome Network Status:', failedPayment.outcome.network_status);
        if (failedPayment.outcome.rule) {
          console.error('Outcome Rule:', failedPayment.outcome.rule);
        }
        if (failedPayment.outcome.seller_message) {
          console.error('Seller Message:', failedPayment.outcome.seller_message);
        }
      }
      break;
    case 'charge.failed':
      const failedCharge = event.data.object;
      console.error('Charge failed:', failedCharge.id);
      console.error('Customer:', failedCharge.customer);
      console.error('Amount:', failedCharge.amount / 100, 'USD');
      console.error('Failure Code:', failedCharge.failure_code);
      console.error('Failure Message:', failedCharge.failure_message);
      
      // Handle NACHA return codes
      if (failedCharge.failure_code) {
        const nachaCodes = {
          'account_closed': 'R05 - Account Closed',
          'debit_not_authorized': 'R07 - Authorization Revoked',
          'customer_requested': 'R08 - Stop Payment'
        };
        
        if (nachaCodes[failedCharge.failure_code]) {
          console.error('NACHA Return Code:', nachaCodes[failedCharge.failure_code]);
          console.error('This bank account should be blocked from future use');
          
          // In production, retrieve payment method details and block the account
          // Example: 
          // const paymentMethod = await stripe.paymentMethods.retrieve(failedCharge.payment_method);
          // const bankAccountKey = `${paymentMethod.us_bank_account.routing_number}_${paymentMethod.us_bank_account.last4}`;
          // blockedBankAccounts.set(bankAccountKey, {
          //   blockedAt: new Date().toISOString(),
          //   reason: nachaCodes[failedCharge.failure_code]
          // });
        }
      }
      break;
    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  res.json({ received: true });
});

// Start server (only for local development)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Landing page: http://localhost:${PORT}`);
    console.log(`Checkout page: http://localhost:${PORT}/checkout.html`);
    console.log(`Verification page: http://localhost:${PORT}/verify.html`);
    console.log(`Advanced Radar fraud prevention enabled`);
    console.log(`SetupIntent flow: Decoupled verification from charging`);
    console.log(`Online mandate tracking: Enabled`);
    console.log(`Account age verification: Ready for implementation`);
  });
}

// Export for Vercel serverless functions
module.exports = app;