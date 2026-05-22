// server.js — NextEra Backend (PostgreSQL / Render)
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path    = require('path');
const db      = require('./database');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nextera_secret_2024_CHANGE_ME';

// ============================================================
// MIDDLEWARES GLOBAUX
// ============================================================
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());
// Servir le frontend (dossier public/)
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// MIDDLEWARES AUTH
// ============================================================
async function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Non authentifié' });
    }
    try {
        const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
        req.userId    = decoded.userId;
        req.userEmail = decoded.email;
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Token invalide' });
    }
}

async function adminMiddleware(req, res, next) {
    const user = await db.getUserById(req.userId);
    if (!user || !user.is_admin) {
        return res.status(403).json({ success: false, message: 'Accès refusé — Admin requis' });
    }
    next();
}

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password, referralCode } = req.body;

        if (!name || !email || !phone || !password)
            return res.status(400).json({ success: false, message: 'Tous les champs sont requis' });
        if (password.length < 6)
            return res.status(400).json({ success: false, message: 'Mot de passe trop court (min 6 caractères)' });

        const normalEmail = email.toLowerCase().trim();
        if (await db.getUserByEmail(normalEmail))
            return res.status(400).json({ success: false, message: 'Cet email est déjà utilisé' });

        const userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4);
        const generatedCode = 'NEXT-' + userId.slice(-8).toUpperCase();

        let referredBy = null;
        if (referralCode && referralCode.trim()) {
            const rows = await db.query('SELECT id FROM users WHERE referral_code = $1', [referralCode.trim()]);
            if (rows.length > 0) referredBy = rows[0].id;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.createUser({ id: userId, name, email: normalEmail, phone, password: hashedPassword, referralCode: generatedCode, referredBy });

        const token = jwt.sign({ userId, email: normalEmail }, JWT_SECRET, { expiresIn: '30d' });
        res.json({
            success: true, token,
            user: { id: userId, name, email: normalEmail, phone, referralCode: generatedCode, isAdmin: false }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ success: false, message: 'Email et mot de passe requis' });

        const user = await db.getUserByEmail(email.toLowerCase().trim());
        if (!user || !(await bcrypt.compare(password, user.password)))
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });

        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
        res.json({
            success: true, token,
            user: { id: user.id, name: user.name, email: user.email, phone: user.phone, referralCode: user.referral_code, isAdmin: user.is_admin === true }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// PORTEFEUILLE & INVESTISSEMENTS
// ============================================================
app.get('/api/portfolio', authMiddleware, async (req, res) => {
    try {
        const p = await db.getPortfolio(req.userId);
        res.json({
            success: true,
            portfolio: {
                balance:          parseInt(p?.balance          || 0),
                totalInvested:    parseInt(p?.total_invested   || 0),
                referralEarnings: parseInt(p?.referral_earnings || 0),
                totalGains:       parseInt(p?.total_gains      || 0)
            }
        });
    } catch (err) {
        console.error('Portfolio error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.get('/api/investments', authMiddleware, async (req, res) => {
    try {
        const rows = await db.getUserInvestments(req.userId);
        const investments = rows.map(inv => ({
            id:                 inv.id,
            machineId:          inv.machine_id,
            name:               inv.machine_name,
            icon:               inv.machine_icon || '⚡',
            amount:             parseInt(inv.amount),
            dailyYield:         parseInt(inv.daily_yield),
            date:               inv.created_at,
            totalGainsReceived: parseInt(inv.total_gains_received || 0),
            status:             inv.status
        }));
        res.json({ success: true, investments });
    } catch (err) {
        console.error('Investments error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.get('/api/transactions', authMiddleware, async (req, res) => {
    try {
        const rows = await db.query(
            'SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
            [req.userId]
        );
        const transactions = rows.map(tx => ({
            ...tx,
            amount:    parseInt(tx.amount),
            fee:       parseInt(tx.fee || 0),
            netAmount: parseInt(tx.net_amount || tx.amount),
            createdAt: tx.created_at
        }));
        res.json({ success: true, transactions });
    } catch (err) {
        console.error('Transactions error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// MARCHÉ (Machines depuis la BDD)
// ============================================================
app.get('/api/machines', async (req, res) => {
    try {
        const machines = await db.getMachines();
        res.json({ success: true, machines });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.post('/api/invest', authMiddleware, async (req, res) => {
    try {
        const { machineId, amount } = req.body;
        const numAmount = parseInt(amount);

        const machines = await db.getMachines();
        const machine  = machines.find(m => String(m.id) === String(machineId));
        if (!machine)
            return res.status(400).json({ success: false, message: 'Machine introuvable' });
        if (numAmount < parseInt(machine.price))
            return res.status(400).json({ success: false, message: `Montant minimum: ${machine.price} XAF` });

        const portfolio = await db.getPortfolio(req.userId);
        if (!portfolio || parseInt(portfolio.balance) < numAmount)
            return res.status(400).json({ success: false, message: 'Solde insuffisant' });

        const investmentId = uuidv4();
        await db.createInvestment({
            id: investmentId, userId: req.userId,
            machineId: machine.id, machineName: machine.name,
            machineIcon: machine.icon || '⚡',
            amount: numAmount, dailyYield: parseInt(machine.daily_yield)
        });

        await db.updateBalance(req.userId, numAmount, 'subtract');
        await db.query('UPDATE portfolios SET total_invested = total_invested + $1 WHERE user_id = $2', [numAmount, req.userId]);

        // Commissions parrainage
        const user = await db.getUserById(req.userId);
        if (user?.referred_by) await processReferralCommissions(req.userId, numAmount);

        await db.addTransaction(req.userId, 'investment', numAmount, {
            description: `Achat ${machine.icon || '⚡'} ${machine.name}`
        });

        const newP = await db.getPortfolio(req.userId);
        res.json({ success: true, message: `✅ ${machine.icon} ${machine.name} acheté !`, newBalance: parseInt(newP.balance) });
    } catch (err) {
        console.error('Invest error:', err);
        res.status(500).json({ success: false, message: 'Erreur lors de l\'investissement' });
    }
});

// ============================================================
// PARRAINAGE PYRAMIDAL (10% / 5% / 3%)
// ============================================================
async function processReferralCommissions(investorId, amount) {
    const levels = [{ percent: 10 }, { percent: 5 }, { percent: 3 }];
    let currentId = (await db.getUserById(investorId))?.referred_by;

    for (let i = 0; i < 3 && currentId; i++) {
        const commission = Math.round(amount * levels[i].percent / 100);
        if (commission > 0) {
            await db.updateBalance(currentId, commission);
            await db.query('UPDATE portfolios SET referral_earnings = referral_earnings + $1 WHERE user_id = $2', [commission, currentId]);
            await db.addTransaction(currentId, 'referral', commission, {
                description: `Commission parrainage Niveau ${i + 1} (${levels[i].percent}%)`
            });
        }
        currentId = (await db.getUserById(currentId))?.referred_by;
    }
}

// ============================================================
// PAIEMENTS — Dépôt (simulation + stubs MTN / Orange)
// ============================================================

// Helper commun
async function processDeposit(req, res, operator) {
    try {
        const { amount, phone } = req.body;
        const numAmount = parseInt(amount);
        if (!numAmount || numAmount < 1000)
            return res.status(400).json({ success: false, message: 'Montant minimum: 1 000 XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Mobile Money invalide' });

        await db.updateBalance(req.userId, numAmount);
        await db.addTransaction(req.userId, 'deposit', numAmount, {
            operator, phone, description: `Dépôt via ${operator.toUpperCase()} Money`
        });
        const p = await db.getPortfolio(req.userId);
        res.json({ success: true, message: `✅ ${numAmount.toLocaleString('fr-FR')} XAF déposés !`, newBalance: parseInt(p.balance) });
    } catch (err) {
        console.error('Deposit error:', err);
        res.status(500).json({ success: false, message: 'Erreur lors du dépôt' });
    }
}

// Route générique
app.post('/api/payment/deposit', authMiddleware, (req, res) => processDeposit(req, res, req.body.operator || 'mtn'));

// Route MTN — stub prêt pour l'intégration réelle
app.post('/api/payment/mtn/deposit', authMiddleware, async (req, res) => {
    /*
    ══════════════════════════════════════════════════════════════
    INTÉGRATION MTN MOMO — À compléter avec vos vraies clés API
    ══════════════════════════════════════════════════════════════
    Variables .env nécessaires :
        MTN_BASE_URL=https://sandbox.momodeveloper.mtn.com
        MTN_PRIMARY_KEY=<votre primary key>
        MTN_API_USER=<votre api user UUID>
        MTN_API_KEY=<votre api key>
        MTN_TARGET_ENV=sandbox   (changer en "mtnci" ou "mtncm" en prod)
        MTN_CURRENCY=XAF

    Flux :
        1. Obtenir un token Bearer via /collection/token/
        2. POST /collection/v1_0/requesttopay avec le montant et le téléphone
        3. Écouter le webhook ou poller /collection/v1_0/requesttopay/{referenceId}
        4. Quand status == SUCCESSFUL → appeler updateBalance() ici

    Exemple d'implémentation disponible sur :
        https://momodeveloper.mtn.com/docs/services/collection
    ══════════════════════════════════════════════════════════════
    */
    return processDeposit(req, res, 'mtn');
});

// Route Orange Money — stub prêt pour l'intégration réelle
app.post('/api/payment/orange/deposit', authMiddleware, async (req, res) => {
    /*
    ══════════════════════════════════════════════════════════════
    INTÉGRATION ORANGE MONEY — À compléter avec vos vraies clés
    ══════════════════════════════════════════════════════════════
    Variables .env nécessaires :
        ORANGE_BASE_URL=https://api.orange.com/orange-money-webpay/cm/v1
        ORANGE_CLIENT_ID=<votre client id>
        ORANGE_CLIENT_SECRET=<votre client secret>
        ORANGE_MERCHANT_KEY=<votre merchant key>

    Flux :
        1. POST /oauth/v3/token → obtenir access_token
        2. POST /webpayment → créer la transaction, récupérer pay_token et payment_url
        3. Rediriger l'utilisateur vers payment_url
        4. Orange rappelle votre callback → vérifier et appeler updateBalance()

    Exemple d'implémentation :
        https://developer.orange.com/apis/orange-money-webpay-cm
    ══════════════════════════════════════════════════════════════
    */
    return processDeposit(req, res, 'orange');
});

// Retrait
app.post('/api/payment/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, phone, operator } = req.body;
        const numAmount = parseInt(amount);
        if (!numAmount || numAmount < 1000)
            return res.status(400).json({ success: false, message: 'Montant minimum: 1 000 XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Mobile Money invalide' });

        const portfolio = await db.getPortfolio(req.userId);
        if (!portfolio || parseInt(portfolio.balance) < numAmount)
            return res.status(400).json({ success: false, message: 'Solde insuffisant' });

        const fee       = Math.round(numAmount * 0.01);
        const netAmount = numAmount - fee;

        await db.updateBalance(req.userId, numAmount, 'subtract');
        await db.addTransaction(req.userId, 'withdrawal', numAmount, {
            fee, netAmount, operator: operator || 'mtn', phone,
            description: `Retrait via ${(operator || 'mtn').toUpperCase()} Money`
        });
        res.json({
            success: true,
            message: `✅ ${netAmount.toLocaleString('fr-FR')} XAF envoyés (frais: ${fee} XAF)`,
            netAmount, fee, newBalance: parseInt(portfolio.balance) - numAmount
        });
    } catch (err) {
        console.error('Withdraw error:', err);
        res.status(500).json({ success: false, message: 'Erreur lors du retrait' });
    }
});

// ============================================================
// BONUS & GAINS
// ============================================================
app.post('/api/bonus/claim', authMiddleware, async (req, res) => {
    try {
        if (await db.hasClaimedBonusToday(req.userId))
            return res.status(400).json({ success: false, message: 'Bonus déjà réclamé aujourd\'hui' });
        await db.claimBonus(req.userId, 100);
        const p = await db.getPortfolio(req.userId);
        res.json({ success: true, message: '🎉 +100 XAF de bonus journalier !', newBalance: parseInt(p.balance) });
    } catch (err) {
        console.error('Bonus error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.post('/api/gains/distribute', authMiddleware, async (req, res) => {
    try {
        const totalGain = await db.applyDailyGains(req.userId);
        const p = await db.getPortfolio(req.userId);
        res.json({ success: true, totalGain, newBalance: parseInt(p?.balance || 0) });
    } catch (err) {
        console.error('Gains error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// PARRAINAGE — STATS
// ============================================================
app.get('/api/referral/stats', authMiddleware, async (req, res) => {
    try {
        const user      = await db.getUserById(req.userId);
        const portfolio = await db.getPortfolio(req.userId);

        const level1 = await db.query('SELECT id, name, email FROM users WHERE referred_by = $1', [req.userId]);
        const l1Ids  = level1.map(u => u.id);

        let level2 = [];
        if (l1Ids.length > 0) {
            const ph = l1Ids.map((_, i) => `$${i + 1}`).join(',');
            level2 = await db.query(`SELECT id, name FROM users WHERE referred_by IN (${ph})`, l1Ids);
        }
        const l2Ids = level2.map(u => u.id);

        let level3 = [];
        if (l2Ids.length > 0) {
            const ph = l2Ids.map((_, i) => `$${i + 1}`).join(',');
            level3 = await db.query(`SELECT id, name FROM users WHERE referred_by IN (${ph})`, l2Ids);
        }

        res.json({
            success: true,
            referralCode:    user?.referral_code,
            totalEarnings:   parseInt(portfolio?.referral_earnings || 0),
            directReferrals: level1,
            counts: { level1: level1.length, level2: level2.length, level3: level3.length }
        });
    } catch (err) {
        console.error('Referral error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// ADMIN
// ============================================================
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users      = await db.query('SELECT id, name, email, phone, is_admin, referral_code, referred_by, created_at FROM users ORDER BY created_at DESC');
        const portfolios = await db.query('SELECT user_id, balance, total_invested, referral_earnings, total_gains FROM portfolios');
        const stats      = await db.query(`
            SELECT
                (SELECT COUNT(*) FROM users)::int                      AS "totalUsers",
                (SELECT COUNT(*) FROM investments WHERE status='active')::int AS "totalInvestments",
                (SELECT COUNT(*) FROM transactions)::int               AS "totalTransactions",
                (SELECT COALESCE(SUM(balance),0) FROM portfolios)::bigint AS "totalBalance"
        `);

        const normalizedPortfolios = portfolios.map(p => ({
            userId:           p.user_id,
            balance:          parseInt(p.balance || 0),
            totalInvested:    parseInt(p.total_invested || 0),
            referralEarnings: parseInt(p.referral_earnings || 0),
            totalGains:       parseInt(p.total_gains || 0)
        }));

        res.json({ success: true, users, portfolios: normalizedPortfolios, stats: stats[0] });
    } catch (err) {
        console.error('Admin users error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.put('/api/admin/user/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const { balance, totalInvested } = req.body;
        if (balance      !== undefined) await db.query('UPDATE portfolios SET balance = $1 WHERE user_id = $2', [balance, userId]);
        if (totalInvested !== undefined) await db.query('UPDATE portfolios SET total_invested = $1 WHERE user_id = $2', [totalInvested, userId]);
        res.json({ success: true, message: 'Utilisateur mis à jour' });
    } catch (err) {
        console.error('Admin update user error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.put('/api/admin/machine/:machineId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { machineId } = req.params;
        const { name, price, dailyYield } = req.body;
        if (name)       await db.query('UPDATE machines SET name = $1 WHERE id = $2',        [name, machineId]);
        if (price)      await db.query('UPDATE machines SET price = $1 WHERE id = $2',       [price, machineId]);
        if (dailyYield) await db.query('UPDATE machines SET daily_yield = $1 WHERE id = $2', [dailyYield, machineId]);
        res.json({ success: true, message: 'Machine mise à jour' });
    } catch (err) {
        console.error('Admin update machine error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', async (req, res) => {
    try {
        const r = await db.query('SELECT COUNT(*) AS cnt FROM users');
        res.json({ success: true, status: 'online', users: parseInt(r[0].cnt), timestamp: new Date().toISOString() });
    } catch (err) {
        res.status(500).json({ success: false, status: 'db_error', message: err.message });
    }
});

// ============================================================
// SPA FALLBACK — toutes les routes non-API → index.html
// ============================================================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// DÉMARRAGE
// ============================================================
async function createDefaultAccounts() {
    const admin = await db.getUserByEmail('admin@nextera.com');
    if (!admin) {
        const id = 'user_admin';
        const hash = await bcrypt.hash('admin123', 10);
        await db.query(
            'INSERT INTO users (id, name, email, phone, password, is_admin, referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id, 'Administrateur', 'admin@nextera.com', '699999999', hash, true, 'NEXT-ADMIN001']
        );
        await db.query(
            'INSERT INTO portfolios (user_id, balance, total_invested, referral_earnings, total_gains) VALUES ($1, 500000, 0, 0, 0) ON CONFLICT (user_id) DO NOTHING',
            [id]
        );
        console.log('✅ Compte admin créé: admin@nextera.com / admin123');
    }

    const test = await db.getUserByEmail('test@nextera.com');
    if (!test) {
        const id = 'user_test';
        const hash = await bcrypt.hash('test123', 10);
        await db.query(
            'INSERT INTO users (id, name, email, phone, password, is_admin, referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id, 'Jean Dupont', 'test@nextera.com', '690000000', hash, false, 'NEXT-TEST001']
        );
        await db.query(
            'INSERT INTO portfolios (user_id, balance, total_invested, referral_earnings, total_gains) VALUES ($1, 25000, 0, 0, 0) ON CONFLICT (user_id) DO NOTHING',
            [id]
        );
        console.log('✅ Compte test créé: test@nextera.com / test123');
    }
}

app.listen(PORT, async () => {
    const connected = await db.testConnection();
    if (!connected) {
        console.error('❌ Impossible de se connecter à PostgreSQL. Vérifiez DATABASE_URL.');
        process.exit(1);
    }

    // Initialiser les tables et données
    await db.initTables();
    await createDefaultAccounts();

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🌿 NextEra — Serveur démarré sur le port ${String(PORT).padEnd(28)}║
║  📊 Health : /api/health                                     ║
║  🔑 Admin  : admin@nextera.com / admin123                    ║
║  🧪 Test   : test@nextera.com  / test123                     ║
╚══════════════════════════════════════════════════════════════╝`);
});
