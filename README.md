# Denim Co. - Premium Jeans Store

A Node.js + Express e-commerce store using Stripe ACH Direct Debit with manual micro-deposit verification.

## Features

- **Stripe ACH Direct Debit** with manual micro-deposit verification
- **SetupIntent Flow** - Decouples bank account verification from payment processing
- **Advanced Radar Fraud Prevention** - Browser fingerprinting and risk analysis
- **User Authentication** - Registration, login, session management
- **Premium UI** - Apple-inspired liquid glass design with custom SVG graphics
- **Responsive Design** - Mobile-friendly shopping experience

## Payment Flow

1. User registers/logs in
2. Selects product and proceeds to checkout
3. Enters bank account details (ACH)
4. Stripe sends two micro-deposits (<$1.00 each) to bank account
5. User waits 1-2 business days for deposits
6. User enters 6-character descriptor code from bank statement
7. Micro-deposits verified, payment processed automatically
8. Order fulfilled via webhook

## Local Development

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your Stripe keys

# Start server
npm start
```

Visit `http://localhost:3000`

## Environment Variables

- `STRIPE_SECRET_KEY` - Your Stripe secret key
- `STRIPE_PUBLISHABLE_KEY` - Your Stripe publishable key  
- `STRIPE_WEBHOOK_SECRET` - Your Stripe webhook signing secret
- `JWT_SECRET` - Secret for session JWT tokens
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)

## Stripe Webhook Setup

```bash
# Install Stripe CLI
stripe listen --forward-to localhost:3000/webhook

# Or configure webhook in Stripe Dashboard
# Endpoint: https://your-domain.com/webhook
# Events: payment_intent.succeeded, payment_intent.payment_failed, setup_intent.succeeded, setup_intent.setup_failed
```

## Vercel Deployment

1. Push code to GitHub
2. Import project in Vercel
3. Configure environment variables in Vercel dashboard:
   - `STRIPE_SECRET_KEY`
   - `STRIPE_PUBLISHABLE_KEY`
   - `STRIPE_WEBHOOK_SECRET`
   - `JWT_SECRET`
4. Deploy

## Production Considerations

- **HTTPS Required** - Stripe requires HTTPS for live payments
- **Webhook Secret** - Must be configured for payment fulfillment
- **User Storage** - Currently uses memory/file storage - consider database for production
- **Rate Limiting** - Add rate limiting for API endpoints
- **Email Verification** - Implement email verification for new users
- **Monitoring** - Add error tracking and monitoring

## Security Notes

- Live Stripe keys are currently in use - consider rotating them
- JWT secret should be changed from default
- Sessions use secure cookies in production
- Stripe Radar is enabled for fraud prevention

## Tech Stack

- Node.js + Express
- Stripe Node SDK
- Stripe.js (frontend)
- Express Sessions
- Bcrypt (password hashing)
- Custom SVG graphics