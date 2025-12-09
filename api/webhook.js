const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const CF_API_TOKEN = process.env.CF_API_TOKEN;
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const D1_DATABASE_ID = process.env.D1_DATABASE_ID;

async function db(sql, params = []) {
    const response = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}/query`,
        {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${CF_API_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sql, params })
        }
    );
    return (await response.json()).result[0];
}

function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;

    try {
        // Get raw body
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        const rawBody = Buffer.concat(chunks).toString('utf8');

        event = stripe.webhooks.constructEvent(rawBody, sig, webhookSecret);
    } catch (err) {
        console.error('Webhook signature failed:', err.message);
        return res.status(400).json({ error: 'Webhook signature verification failed' });
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const userId = session.metadata?.user_id;

        if (userId) {
            try {
                // Update payment status
                await db("UPDATE users SET payment_status = 'paid' WHERE id = ?", [userId]);

                // Unlock all days 2-30
                for (let day = 2; day <= 30; day++) {
                    const existing = await db('SELECT id FROM user_progress WHERE user_id = ? AND day_number = ?', [userId, day]);
                    if (!existing.results || !existing.results.length) {
                        await db(
                            'INSERT INTO user_progress (id, user_id, day_number, unlocked_at) VALUES (?, ?, ?, datetime("now"))',
                            [uuid(), userId, day]
                        );
                    }
                }

                // Credit affiliate
                const user = await db('SELECT referred_by FROM users WHERE id = ?', [userId]);
                if (user.results?.[0]?.referred_by) {
                    const commission = 9.99; // 25% of $39.99
                    await db(
                        'UPDATE users SET affiliate_earnings = affiliate_earnings + ? WHERE id = ?',
                        [commission, user.results[0].referred_by]
                    );
                }

                console.log('Payment processed for user:', userId);
            } catch (err) {
                console.error('Error processing payment:', err);
            }
        }
    }

    return res.json({ received: true });
};

module.exports.config = {
    api: {
        bodyParser: false
    }
};
