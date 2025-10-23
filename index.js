// index.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static assets (CSS, images, etc.) from /public
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'ctf-idor-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// In-memory "DB"
const users = [
  { id: 1, username: 'alice', password: 'alicepass' },
  { id: 2, username: 'bob',   password: 'bobpass' },
  { id: 3, username: 'carol', password: 'carolpass' }
];

// invoices: id is sequential and predictable (intentional)
const invoices = [
  { id: -1,  ownerUserId: 2, title: 'Bob - Invoice #3',     notes: 'flag{xakack12}' }, // <-- FLAG here
  { id: 1,  ownerUserId: 1, title: 'Alice - Invoice #1',    notes: 'Consulting services - paid.' },
  { id: 2,  ownerUserId: 1, title: 'Alice - Invoice #2',    notes: 'Travel reimbursement.' },
  { id: 3,  ownerUserId: 2, title: 'Bob - Invoice #1',      notes: 'Monthly subscription.' },
  { id: 4,  ownerUserId: 3, title: 'Carol - Invoice #1',    notes: 'One-time setup fee.' },
  { id: 5,  ownerUserId: 2, title: 'Bob - Invoice #2',      notes: 'License renewal.' },
  { id: 6,  ownerUserId: 4, title: 'Dave - Invoice #1',     notes: 'Hardware purchase.' },
  { id: 7,  ownerUserId: 5, title: 'Eve - Invoice #1',      notes: 'Consultation follow-up.' },
  { id: 8,  ownerUserId: 1, title: 'Alice - Invoice #3',    notes: 'Additional hours.' },
  { id: 9,  ownerUserId: 2, title: 'Bob - Invoice #3',      notes: 'Maintenance contract.' },
  { id: 10, ownerUserId: 3, title: 'Carol - Invoice #2',    notes: 'Refund processed.' },
  { id: 11, ownerUserId: 4, title: 'Dave - Invoice #2',     notes: 'Maintenance contract.' },
  { id: 12, ownerUserId: 5, title: 'Eve - Invoice #2',      notes: 'Quarterly review.' },
  { id: 13, ownerUserId: 1, title: 'Alice - Invoice #4',    notes: 'Project milestone 1.' },
  { id: 14, ownerUserId: 2, title: 'Bob - Invoice #4',      notes: 'Project milestone 2.' },
  { id: 15, ownerUserId: 3, title: 'Carol - Invoice #3',    notes: 'Audit fee.' },
  { id: 16, ownerUserId: 4, title: 'Dave - Invoice #3',     notes: 'Custom development.' },
  { id: 17, ownerUserId: 5, title: 'Eve - Invoice #3',      notes: 'Service charge.' },
  { id: 18, ownerUserId: 2, title: 'Bob - Invoice #5',      notes: 'Final payment.' },
  { id: 19, ownerUserId: 1, title: 'Alice - Invoice #5',    notes: 'Bonus hours.' },
  { id: 20, ownerUserId: 3, title: 'Carol - Invoice #4',    notes: 'Year-end adjustment.' }
];


function findUserByUsername(username) {
  return users.find(u => u.username === username);
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

/* ROUTES */
app.get('/', (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  res.render('index', { user });
});

// Login form
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = findUserByUsername(username);
  if (!u || u.password !== password) {
    return res.render('login', { error: 'Invalid credentials' });
  }
  req.session.userId = u.id;
  res.redirect('/my-invoices');
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// My invoices - UI lists only owned invoices
app.get('/my-invoices', requireAuth, (req, res) => {
  const myInvoices = invoices.filter(inv => inv.ownerUserId === req.session.userId);
  res.render('my-invoices', { invoices: myInvoices });
});

/*
  VULNERABLE ENDPOINT:
  /invoice/:id returns invoice details but does NOT check whether
  the logged-in user owns that invoice — IDOR vulnerability.
*/
app.get('/invoice/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const inv = invoices.find(i => i.id === id);
  if (!inv) return res.status(404).send('Invoice not found');
  // NO ownership check — vulnerable by design
  // Render an invoice page instead of returning JSON
  const owner = users.find(u => u.id === inv.ownerUserId);
  res.render('invoice', { invoice: inv, owner });
});

/* Small helper API to aid enumeration:
   /api/max-invoice returns the highest invoice id (this mimics an info leak
   or a convenient API found by players). This nudges players to enumerate ids 1..N. */
app.get('/api/max-invoice', requireAuth, (req, res) => {
  const maxId = Math.max(...invoices.map(i => i.id));
  res.json({ maxInvoiceId: maxId });
});

const port = PORT;
app.listen(port, () => console.log(`CTF IDOR app running on http://localhost:${port}`));

