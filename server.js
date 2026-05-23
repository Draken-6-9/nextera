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
// MIDDLEWARES
// ============================================================
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// MIDDLEWARES AUTH
// ============================================================
async function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer '))
        return res.status(401).json({ success: false, message: 'Non authentifié' });
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
    if (!user || !user.is_admin)
        return res.status(403).json({ success: false, message: 'Accès refusé — Admin requis' });
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
        res.json({
            success: true,
            investments: rows.map(inv => ({
                id:                 inv.id,
                machineId:          inv.machine_id,
                name:               inv.machine_name,
                icon:               inv.machine_icon || '⚡',
                amount:             parseInt(inv.amount),
                dailyYield:         parseInt(inv.daily_yield),
                date:               inv.created_at,
                totalGainsReceived: parseInt(inv.total_gains_received || 0),
                status:             inv.status
            }))
        });
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
        res.json({
            success: true,
            transactions: rows.map(tx => ({
                ...tx,
                amount:    parseInt(tx.amount),
                fee:       parseInt(tx.fee || 0),
                netAmount: parseInt(tx.net_amount || tx.amount),
                createdAt: tx.created_at
            }))
        });
    } catch (err) {
        console.error('Transactions error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// MARCHÉ
// ============================================================
app.get('/api/machines', async (req, res) => {
    try {
        res.json({ success: true, machines: await db.getMachines() });
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
    const levels = [
        { level: 1, percent: 10 },
        { level: 2, percent: 5  },
        { level: 3, percent: 3  }
    ];

    // Partir du filleul et remonter la chaîne de parrainage
    let investorUser = await db.getUserById(investorId);
    let currentId    = investorUser?.referred_by;

    for (let i = 0; i < 3 && currentId; i++) {
        const { level, percent } = levels[i];
        const commission = Math.round(amount * percent / 100);

        if (commission > 0) {
            // Créditer le parrain
            await db.updateBalance(currentId, commission);
            // Mettre à jour le total des gains de parrainage
            await db.query(
                'UPDATE portfolios SET referral_earnings = referral_earnings + $1 WHERE user_id = $2',
                [commission, currentId]
            );
            // Enregistrer la transaction visible dans l'historique du parrain
            await db.addTransaction(currentId, 'referral', commission, {
                description: `🎁 Commission parrainage Niveau ${level} (${percent}%) — investissement de ${amount.toLocaleString('fr-FR')} XAF`
            });

            const parrain = await db.getUserById(currentId);
            console.log(`[Parrainage] Niveau ${level} → ${parrain?.name || currentId} reçoit +${commission} XAF (${percent}% de ${amount} XAF)`);
        }

        // Remonter au niveau supérieur
        const parentUser = await db.getUserById(currentId);
        currentId = parentUser?.referred_by || null;
    }
}

// ============================================================
// PAIEMENTS — DÉPÔT
// ============================================================
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

app.post('/api/payment/deposit',        authMiddleware, (req, res) => processDeposit(req, res, req.body.operator || 'mtn'));
app.post('/api/payment/mtn/deposit',    authMiddleware, (req, res) => processDeposit(req, res, 'mtn'));
app.post('/api/payment/orange/deposit', authMiddleware, (req, res) => processDeposit(req, res, 'orange'));

// ============================================================
// PAIEMENTS — RETRAIT (1 par jour, minimum 1500 XAF, frais 1%)
// ============================================================
app.post('/api/payment/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, phone, operator } = req.body;
        const numAmount = parseInt(amount);

        // Minimum 1500 XAF
        if (!numAmount || numAmount < 1500)
            return res.status(400).json({ success: false, message: 'Montant minimum de retrait : 1 500 XAF' });

        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Mobile Money invalide' });

        // ── LIMITE : 1 SEUL RETRAIT PAR JOUR ──────────────────
        const alreadyWithdrawn = await db.query(
            `SELECT id FROM transactions
             WHERE user_id = $1
               AND type = 'withdrawal'
               AND created_at::date = CURRENT_DATE`,
            [req.userId]
        );
        if (alreadyWithdrawn.length > 0)
            return res.status(400).json({ success: false, message: '⛔ Un seul retrait autorisé par jour. Revenez demain.' });
        // ──────────────────────────────────────────────────────

        const portfolio = await db.getPortfolio(req.userId);
        if (!portfolio || parseInt(portfolio.balance) < numAmount)
            return res.status(400).json({ success: false, message: 'Solde insuffisant' });

        const fee       = Math.round(numAmount * 0.01);  // 1% de frais
        const netAmount = numAmount - fee;

        await db.updateBalance(req.userId, numAmount, 'subtract');
        await db.addTransaction(req.userId, 'withdrawal', numAmount, {
            fee, netAmount, operator: operator || 'mtn', phone,
            description: `Retrait via ${(operator || 'mtn').toUpperCase()} Money`
        });

        res.json({
            success: true,
            message: `✅ ${netAmount.toLocaleString('fr-FR')} XAF envoyés (frais: ${fee} XAF)`,
            netAmount, fee,
            newBalance: parseInt(portfolio.balance) - numAmount
        });
    } catch (err) {
        console.error('Withdraw error:', err);
        res.status(500).json({ success: false, message: 'Erreur lors du retrait' });
    }
});

// ============================================================
// BONUS JOURNALIER (manuel, 1 fois/jour)
// ============================================================
app.post('/api/bonus/claim', authMiddleware, async (req, res) => {
    try {
        if (await db.hasClaimedBonusToday(req.userId))
            return res.status(400).json({ success: false, message: 'Bonus déjà réclamé aujourd\'hui. Revenez demain !' });
        await db.claimBonus(req.userId, 100);
        const p = await db.getPortfolio(req.userId);
        res.json({ success: true, message: '🎉 +100 XAF de bonus journalier !', newBalance: parseInt(p.balance) });
    } catch (err) {
        console.error('Bonus error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ============================================================
// GAINS JOURNALIERS — distribution manuelle (admin/debug)
// ============================================================
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
            const ph = l1Ids.map((_, i) => `$${i+1}`).join(',');
            level2 = await db.query(`SELECT id, name FROM users WHERE referred_by IN (${ph})`, l1Ids);
        }
        const l2Ids = level2.map(u => u.id);
        let level3 = [];
        if (l2Ids.length > 0) {
            const ph = l2Ids.map((_, i) => `$${i+1}`).join(',');
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
                (SELECT COUNT(*) FROM users)::int                           AS "totalUsers",
                (SELECT COUNT(*) FROM investments WHERE status='active')::int AS "totalInvestments",
                (SELECT COUNT(*) FROM transactions)::int                    AS "totalTransactions",
                (SELECT COALESCE(SUM(balance),0) FROM portfolios)::bigint   AS "totalBalance"
        `);
        res.json({
            success: true, users,
            portfolios: portfolios.map(p => ({
                userId:           p.user_id,
                balance:          parseInt(p.balance || 0),
                totalInvested:    parseInt(p.total_invested || 0),
                referralEarnings: parseInt(p.referral_earnings || 0),
                totalGains:       parseInt(p.total_gains || 0)
            })),
            stats: stats[0]
        });
    } catch (err) {
        console.error('Admin users error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

app.put('/api/admin/user/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const { balance, totalInvested } = req.body;
        if (balance       !== undefined) await db.query('UPDATE portfolios SET balance = $1 WHERE user_id = $2',       [balance, userId]);
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
// HEALTH CHECK (sert aussi de cible au keepalive interne)
// ============================================================
app.get('/api/health', async (req, res) => {
    try {
        const r = await db.query('SELECT COUNT(*) AS cnt FROM users');
        res.json({ success: true, status: 'online', users: parseInt(r[0].cnt), timestamp: new Date().toISOString() });
    } catch (err) {
        res.status(500).json({ success: false, status: 'db_error', message: err.message });
    }
});

// SPA fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// CRON INTERNE — TÂCHES AUTOMATIQUES
// ============================================================

// ── 1. KEEPALIVE anti-sleep Render ───────────────────────────
// Render endort les services gratuits après 15 min d'inactivité.
// Ce cron auto-ping toutes les 14 min pour maintenir l'éveil 24h/24.
function startKeepalive() {
    const SELF_URL = process.env.RENDER_EXTERNAL_URL
        ? `${process.env.RENDER_EXTERNAL_URL}/api/health`
        : `http://localhost:${PORT}/api/health`;

    setInterval(async () => {
        try {
            const http = SELF_URL.startsWith('https') ? require('https') : require('http');
            http.get(SELF_URL, (res) => {
                console.log(`[Keepalive] Ping → ${res.statusCode} — ${new Date().toLocaleTimeString('fr-FR')}`);
            }).on('error', (e) => {
                console.warn('[Keepalive] Ping failed:', e.message);
            });
        } catch (e) {
            console.warn('[Keepalive] Error:', e.message);
        }
    }, 14 * 60 * 1000); // toutes les 14 minutes

    console.log('✅ [Keepalive] Démarré — ping toutes les 14 minutes');
}

// ── 2. DISTRIBUTION AUTOMATIQUE DES GAINS JOURNALIERS ────────
// Tous les jours à minuit UTC : crédite les gains de chaque
// investissement actif sur le compte de l'utilisateur.
function startDailyGainsCron() {
    async function distributeAllUsersGains() {
        console.log('[Gains CRON] ⏰ Distribution journalière démarrée...');
        try {
            const users = await db.query("SELECT DISTINCT user_id FROM investments WHERE status = 'active'");
            let totalUsers = 0;
            let totalXAF   = 0;

            for (const row of users) {
                try {
                    const gain = await db.applyDailyGains(row.user_id);
                    if (gain > 0) { totalUsers++; totalXAF += gain; }
                } catch (e) {
                    console.error(`[Gains CRON] Erreur user ${row.user_id}:`, e.message);
                }
            }

            console.log(`[Gains CRON] ✅ Terminé — ${totalUsers} utilisateurs crédités, +${totalXAF.toLocaleString('fr-FR')} XAF total`);
        } catch (e) {
            console.error('[Gains CRON] Erreur globale:', e.message);
        }
    }

    // Calculer le délai jusqu'au prochain minuit UTC
    function msUntilMidnightUTC() {
        const now       = new Date();
        const midnight  = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 30));
        return midnight - now;
    }

    // Premier lancement à minuit UTC, puis toutes les 24h
    const delay = msUntilMidnightUTC();
    console.log(`✅ [Gains CRON] Prochaine distribution dans ${Math.round(delay/1000/60)} minutes (minuit UTC)`);

    setTimeout(() => {
        distributeAllUsersGains();           // premier fire à minuit UTC
        setInterval(distributeAllUsersGains, 24 * 60 * 60 * 1000); // puis chaque 24h
    }, delay);
}

// ── 3. NETTOYAGE DES ANCIENS LOGS (optionnel) ─────────────────
// Supprime les transactions de plus de 1 an pour garder la BDD légère
function startCleanupCron() {
    setInterval(async () => {
        try {
            const result = await db.query(
                "DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '365 days'"
            );
            if (result.length > 0 || result.rowCount > 0)
                console.log('[Cleanup CRON] Vieilles transactions supprimées');
        } catch (e) {
            // Silencieux — pas critique
        }
    }, 24 * 60 * 60 * 1000); // chaque 24h
}

// ============================================================
// COMPTES PAR DÉFAUT
// ============================================================
async function createDefaultAccounts() {
    const admin = await db.getUserByEmail('admin@nextera.com');
    if (!admin) {
        const id = 'user_admin';
        const hash = await bcrypt.hash('admin123', 10);
        await db.query(
            'INSERT INTO users (id,name,email,phone,password,is_admin,referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id,'Administrateur','admin@nextera.com','699999999',hash,true,'NEXT-ADMIN001']
        );
        await db.query(
            'INSERT INTO portfolios (user_id,balance,total_invested,referral_earnings,total_gains) VALUES ($1,500000,0,0,0) ON CONFLICT (user_id) DO NOTHING',
            [id]
        );
        console.log('✅ Compte admin créé: admin@nextera.com / admin123');
    }
    const test = await db.getUserByEmail('test@nextera.com');
    if (!test) {
        const id = 'user_test';
        const hash = await bcrypt.hash('test123', 10);
        await db.query(
            'INSERT INTO users (id,name,email,phone,password,is_admin,referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id,'Jean Dupont','test@nextera.com','690000000',hash,false,'NEXT-TEST001']
        );
        await db.query(
            'INSERT INTO portfolios (user_id,balance,total_invested,referral_earnings,total_gains) VALUES ($1,25000,0,0,0) ON CONFLICT (user_id) DO NOTHING',
            [id]
        );
        console.log('✅ Compte test créé: test@nextera.com / test123');
    }
}

// ============================================================
// DÉMARRAGE
// ============================================================
app.listen(PORT, async () => {
    const connected = await db.testConnection();
    if (!connected) {
        console.error('❌ Impossible de se connecter à PostgreSQL.');
        process.exit(1);
    }

    await db.initTables();
    await createDefaultAccounts();

    // Lancer les crons
    startKeepalive();
    startDailyGainsCron();
    startCleanupCron();

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🌿 NextEra — Démarré sur le port ${String(PORT).padEnd(27)}║
║  📊 Health   : /api/health                                   ║
║  🔑 Admin    : admin@nextera.com / admin123                  ║
║  🧪 Test     : test@nextera.com  / test123                   ║
║  ⏰ Gains    : distribution automatique chaque nuit (minuit) ║
║  💓 Keepalive: ping toutes les 14 min (anti-sleep Render)    ║
╚══════════════════════════════════════════════════════════════╝`);
});
