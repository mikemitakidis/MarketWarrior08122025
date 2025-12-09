const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Environment variables
const CF_API_TOKEN = process.env.CF_API_TOKEN;
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const D1_DATABASE_ID = process.env.D1_DATABASE_ID;
const JWT_SECRET = process.env.JWT_SECRET || 'market-warrior-2025';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

// Stripe (only load if key exists)
let stripe = null;
if (STRIPE_SECRET_KEY) {
    stripe = require('stripe')(STRIPE_SECRET_KEY);
}

// Database query function
async function db(sql, params = []) {
    if (!CF_API_TOKEN || !CF_ACCOUNT_ID || !D1_DATABASE_ID) {
        throw new Error('Missing database config: CF_API_TOKEN, CF_ACCOUNT_ID, or D1_DATABASE_ID');
    }
    
    const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}/query`;
    
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${CF_API_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sql, params })
    });
    
    const data = await response.json();
    
    if (!data.success) {
        console.error('DB Error:', JSON.stringify(data.errors));
        throw new Error(data.errors?.[0]?.message || 'Database query failed');
    }
    
    return data.result[0];
}

// UUID generator
function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

// Affiliate code generator
function affCode(name) {
    const clean = name.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase();
    return clean + Math.random().toString(36).substring(2, 6).toUpperCase();
}

// Main handler
module.exports = async (req, res) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const action = req.query.action;

    try {
        // ============ TEST - Check if API works ============
        if (action === 'test') {
            return res.json({
                success: true,
                message: 'API is working',
                hasDbConfig: !!(CF_API_TOKEN && CF_ACCOUNT_ID && D1_DATABASE_ID),
                hasStripe: !!STRIPE_SECRET_KEY
            });
        }

        // ============ DB TEST - Check database connection ============
        if (action === 'dbtest') {
            try {
                const result = await db('SELECT COUNT(*) as count FROM users');
                return res.json({
                    success: true,
                    message: 'Database connected',
                    userCount: result.results[0].count
                });
            } catch (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Database connection failed: ' + err.message
                });
            }
        }

        // ============ REGISTER ============
        if (action === 'register' && req.method === 'POST') {
            const { email, password, full_name, referral_code, gdpr_consent } = req.body || {};
            
            // Validation
            if (!email || !password || !full_name) {
                return res.status(400).json({ success: false, error: 'Email, password, and name required' });
            }
            if (password.length < 6) {
                return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
            }
            if (!gdpr_consent) {
                return res.status(400).json({ success: false, error: 'You must accept terms' });
            }
            
            // Check existing user
            const existing = await db('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
            if (existing.results && existing.results.length > 0) {
                return res.status(400).json({ success: false, error: 'Email already registered' });
            }
            
            // Create user
            const userId = uuid();
            const passwordHash = await bcrypt.hash(password, 10);
            const affiliateCode = affCode(full_name);
            
            // Check referrer
            let referredBy = null;
            if (referral_code) {
                const ref = await db('SELECT id FROM users WHERE affiliate_code = ?', [referral_code.toUpperCase()]);
                if (ref.results && ref.results.length > 0) {
                    referredBy = ref.results[0].id;
                }
            }
            
            // Insert user
            await db(
                `INSERT INTO users (id, email, password_hash, full_name, created_at, payment_status, affiliate_code, referred_by, affiliate_earnings, device_count, is_admin)
                 VALUES (?, ?, ?, ?, datetime('now'), 'pending', ?, ?, 0, 0, 0)`,
                [userId, email.toLowerCase(), passwordHash, full_name, affiliateCode, referredBy]
            );
            
            // Unlock Day 1
            await db(
                `INSERT INTO user_progress (id, user_id, day_number, unlocked_at) VALUES (?, ?, 1, datetime('now'))`,
                [uuid(), userId]
            );
            
            // Create token
            const token = jwt.sign({ userId, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '7d' });
            
            return res.json({
                success: true,
                token,
                user: { id: userId, email: email.toLowerCase(), full_name, payment_status: 'pending', affiliate_code: affiliateCode }
            });
        }

        // ============ LOGIN ============
        if (action === 'login' && req.method === 'POST') {
            const { email, password } = req.body || {};
            
            if (!email || !password) {
                return res.status(400).json({ success: false, error: 'Email and password required' });
            }
            
            const result = await db(
                'SELECT id, email, password_hash, full_name, payment_status, affiliate_code, affiliate_earnings, is_admin FROM users WHERE email = ?',
                [email.toLowerCase()]
            );
            
            if (!result.results || result.results.length === 0) {
                return res.status(401).json({ success: false, error: 'Invalid email or password' });
            }
            
            const user = result.results[0];
            const valid = await bcrypt.compare(password, user.password_hash);
            
            if (!valid) {
                return res.status(401).json({ success: false, error: 'Invalid email or password' });
            }
            
            await db("UPDATE users SET last_login = datetime('now') WHERE id = ?", [user.id]);
            
            const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
            
            return res.json({
                success: true,
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    full_name: user.full_name,
                    payment_status: user.payment_status,
                    affiliate_code: user.affiliate_code,
                    affiliate_earnings: user.affiliate_earnings || 0,
                    is_admin: user.is_admin === 1
                }
            });
        }

        // ============ VERIFY TOKEN ============
        if (action === 'verify') {
            const auth = req.headers.authorization;
            if (!auth || !auth.startsWith('Bearer ')) {
                return res.status(401).json({ success: false, error: 'No token' });
            }
            
            try {
                const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
                const result = await db(
                    'SELECT id, email, full_name, payment_status, affiliate_code, affiliate_earnings, is_admin FROM users WHERE id = ?',
                    [decoded.userId]
                );
                
                if (!result.results || result.results.length === 0) {
                    return res.status(401).json({ success: false, error: 'User not found' });
                }
                
                const user = result.results[0];
                return res.json({ success: true, valid: true, user });
            } catch (err) {
                return res.status(401).json({ success: false, error: 'Invalid token' });
            }
        }

        // ============ PROGRESS ============
        if (action === 'progress') {
            const auth = req.headers.authorization;
            if (!auth) return res.status(401).json({ success: false, error: 'Not authenticated' });
            
            try {
                const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
                
                const userResult = await db('SELECT * FROM users WHERE id = ?', [decoded.userId]);
                if (!userResult.results || !userResult.results.length) {
                    return res.status(404).json({ success: false, error: 'User not found' });
                }
                const user = userResult.results[0];
                
                const progressResult = await db('SELECT * FROM user_progress WHERE user_id = ? ORDER BY day_number', [decoded.userId]);
                const progress = progressResult.results || [];
                
                // Calculate stats
                const completedDays = progress.filter(p => p.completed_at).length;
                const quizScores = progress.filter(p => p.quiz_score !== null).map(p => p.quiz_score);
                const avgScore = quizScores.length ? Math.round(quizScores.reduce((a, b) => a + b, 0) / quizScores.length) : 0;
                const currentDay = progress.length > 0 ? Math.max(...progress.map(p => p.day_number)) : 1;
                
                return res.json({
                    success: true,
                    user,
                    progress,
                    stats: { currentDay, completedDays, averageScore: avgScore, totalDays: 30 }
                });
            } catch (err) {
                return res.status(401).json({ success: false, error: 'Invalid token' });
            }
        }

        // ============ QUIZ SUBMIT ============
        if (action === 'quiz' && req.method === 'POST') {
            const auth = req.headers.authorization;
            if (!auth) return res.status(401).json({ success: false, error: 'Not authenticated' });
            
            try {
                const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
                const { day, score } = req.body || {};
                
                if (!day || score === undefined) {
                    return res.status(400).json({ success: false, error: 'Day and score required' });
                }
                
                const passed = score >= 60;
                
                await db(
                    'UPDATE user_progress SET quiz_score = ?, quiz_passed = ? WHERE user_id = ? AND day_number = ?',
                    [score, passed ? 1 : 0, decoded.userId, day]
                );
                
                // Unlock next day if passed
                if (passed && day < 30) {
                    const nextDay = day + 1;
                    const existing = await db('SELECT id FROM user_progress WHERE user_id = ? AND day_number = ?', [decoded.userId, nextDay]);
                    if (!existing.results || !existing.results.length) {
                        await db(
                            'INSERT INTO user_progress (id, user_id, day_number, unlocked_at) VALUES (?, ?, ?, datetime("now"))',
                            [uuid(), decoded.userId, nextDay]
                        );
                    }
                }
                
                return res.json({ success: true, passed, score, message: passed ? 'Passed! Next day unlocked.' : 'Need 60% to pass.' });
            } catch (err) {
                return res.status(401).json({ success: false, error: 'Invalid token' });
            }
        }

        // ============ CHECK DAY ACCESS ============
        if (action === 'check-access') {
            const auth = req.headers.authorization;
            const day = parseInt(req.query.day) || 1;
            
            if (!auth) return res.status(401).json({ success: false, error: 'Not authenticated' });
            
            try {
                const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
                
                // Day 1 always accessible
                if (day === 1) {
                    return res.json({ success: true, hasAccess: true });
                }
                
                // Check payment
                const userResult = await db('SELECT payment_status FROM users WHERE id = ?', [decoded.userId]);
                if (!userResult.results?.length || userResult.results[0].payment_status !== 'paid') {
                    return res.json({ success: true, hasAccess: false, reason: 'Payment required' });
                }
                
                // Check if day unlocked
                const progress = await db('SELECT id FROM user_progress WHERE user_id = ? AND day_number = ?', [decoded.userId, day]);
                const hasAccess = progress.results && progress.results.length > 0;
                
                return res.json({ success: true, hasAccess, reason: hasAccess ? null : 'Complete previous day first' });
            } catch (err) {
                return res.status(401).json({ success: false, error: 'Invalid token' });
            }
        }

        // ============ CHECKOUT ============
        if (action === 'checkout' && req.method === 'POST') {
            if (!stripe) {
                return res.status(500).json({ success: false, error: 'Stripe not configured' });
            }
            
            const auth = req.headers.authorization;
            if (!auth) return res.status(401).json({ success: false, error: 'Not authenticated' });
            
            try {
                const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
                const { promo_code } = req.body || {};
                
                const userResult = await db('SELECT email FROM users WHERE id = ?', [decoded.userId]);
                const email = userResult.results?.[0]?.email || '';
                
                // Promo codes
                const promos = { 'LAUNCH50': 50, 'WELCOME25': 25, 'EARLYBIRD': 30, 'FRIEND20': 20 };
                let discount = 0;
                if (promo_code && promos[promo_code.toUpperCase()]) {
                    discount = promos[promo_code.toUpperCase()];
                }
                
                const basePrice = 3999; // $39.99
                const finalPrice = Math.round(basePrice * (1 - discount / 100));
                
                const session = await stripe.checkout.sessions.create({
                    payment_method_types: ['card'],
                    line_items: [{
                        price_data: {
                            currency: 'usd',
                            product_data: { name: 'Market Warrior - 30 Day Trading Challenge' },
                            unit_amount: finalPrice
                        },
                        quantity: 1
                    }],
                    mode: 'payment',
                    success_url: `${process.env.SITE_URL || 'https://marketwarriorlive.vercel.app'}/pages/dashboard.html?payment=success`,
                    cancel_url: `${process.env.SITE_URL || 'https://marketwarriorlive.vercel.app'}/pages/dashboard.html?payment=cancelled`,
                    customer_email: email,
                    metadata: { user_id: decoded.userId }
                });
                
                return res.json({ success: true, url: session.url });
            } catch (err) {
                console.error('Checkout error:', err);
                return res.status(500).json({ success: false, error: 'Checkout failed: ' + err.message });
            }
        }

        // Default
        return res.status(400).json({
            success: false,
            error: 'Invalid action. Use: test, dbtest, register, login, verify, progress, quiz, check-access, checkout'
        });

    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ success: false, error: error.message });
    }
};
