// ================================================================
// server.js — NextEra Backend (PostgreSQL / Render)
// ================================================================
//
// FICHIERS MODIFIÉS DANS CETTE VERSION :
//   ✅ server.js   ← CE FICHIER (paiements Campay + bonus inscription)
//   ✅ .env.example ← Clés API Campay à renseigner
//
// PAIEMENTS : Campay gère MTN MoMo ET Orange Money en même temps.
//   → Une seule intégration, deux opérateurs couverts.
//   → Clés à renseigner dans Render > Environment (voir .env.example)
//
// ================================================================

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

// ================================================================
// MIDDLEWARES
// ================================================================
app.use(cors({
    origin: '*',
    methods: ['GET','POST','PUT','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ================================================================
// MIDDLEWARES AUTH
// ================================================================
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

// ================================================================
//  ██████╗ █████╗ ███╗   ███╗██████╗  █████╗ ██╗   ██╗
// ██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔══██╗╚██╗ ██╔╝
// ██║     ███████║██╔████╔██║██████╔╝███████║ ╚████╔╝
// ██║     ██╔══██║██║╚██╔╝██║██╔═══╝ ██╔══██║  ╚██╔╝
// ╚██████╗██║  ██║██║ ╚═╝ ██║██║     ██║  ██║   ██║
//  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝
//
// Campay unifie MTN Mobile Money + Orange Money en une seule API.
// Tu n'as qu'un seul compte marchand et un seul jeu de clés.
//
// ─── OÙ METTRE TES CLÉS ────────────────────────────────────────
//
//   Sur Render : Dashboard → nextera-api → Environment → Add Variable
//
//   CAMPAY_USERNAME  = ton nom d'utilisateur Campay
//   CAMPAY_PASSWORD  = ton mot de passe Campay
//   CAMPAY_APP_NAME  = le nom de ton application dans Campay
//
//   Ces trois variables suffisent pour MTN + Orange en production.
//
// ─── OBTENIR TES CLÉS CAMPAY ───────────────────────────────────
//
//   1. Va sur https://campay.net → "Get Started"
//   2. Crée un compte marchand (entreprise ou particulier)
//   3. Fournis : nom, numéro de téléphone Cameroun, pièce d'identité
//   4. Une fois validé, dans Dashboard → API → copie :
//      - Username  → CAMPAY_USERNAME
//      - Password  → CAMPAY_PASSWORD
//      - App Name  → CAMPAY_APP_NAME
//   5. Ajoute ces 3 variables dans Render et le service redémarre
//
// ─── MODE SIMULATION ───────────────────────────────────────────
//
//   Si les clés Campay ne sont pas encore configurées, l'app
//   fonctionne en mode simulation : les dépôts créditent directement
//   le solde sans appeler Campay.
//   Le log du serveur indique clairement l'état :
//     ✅ Campay : ACTIF (argent réel)
//     ⚠️  Campay : SIMULATION (CAMPAY_USERNAME non configuré)
//
// ================================================================

// ── URL de base Campay ─────────────────────────────────────────
// Sandbox (tests) : https://demo.campay.net/api
// Production      : https://campay.net/api
// ✏️  Changer CAMPAY_BASE_URL=https://campay.net/api quand tu passes en prod
// Vérification : fetch() est natif depuis Node 18.
// Si tu vois "fetch is not defined", mets à jour Node ou ajoute node-fetch.
if (typeof fetch === 'undefined') {
    console.error('❌ fetch() non disponible — Node.js 18+ requis. Version actuelle:', process.version);
    process.exit(1);
}

const CAMPAY_BASE_URL = process.env.CAMPAY_BASE_URL || 'https://demo.campay.net/api';

// ── Vérifie si Campay est configuré ───────────────────────────
function campayIsConfigured() {
    // Retourne true uniquement si les deux variables sont définies,
    // non vides, et ne contiennent pas les valeurs placeholder du .env.example.
    const u = (process.env.CAMPAY_USERNAME || '').trim();
    const p = (process.env.CAMPAY_PASSWORD || '').trim();
    return u.length > 0
        && p.length > 0
        && !u.includes('VOTRE')
        && !u.includes('votre');
}

// ── Obtenir un token d'accès Campay ───────────────────────────
// Campay utilise OAuth2 : on échange username/password contre un token Bearer.
// Le token dure 60 minutes — on en génère un nouveau à chaque appel.
async function getCampayToken() {
    const response = await fetch(`${CAMPAY_BASE_URL}/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: process.env.CAMPAY_USERNAME,  // ← variable CAMPAY_USERNAME dans Render
            password: process.env.CAMPAY_PASSWORD   // ← variable CAMPAY_PASSWORD dans Render
        })
    });

    if (!response.ok) {
        const txt = await response.text();
        throw new Error(`Campay auth error ${response.status}: ${txt}`);
    }

    const data = await response.json();
    // data.token contient le Bearer token à utiliser dans les prochains appels
    return data.token;
}

// ── Initier un dépôt via Campay (MTN ou Orange selon le numéro) ─
// Campay détecte automatiquement l'opérateur depuis le numéro de téléphone :
//   - 67X, 65X → MTN Mobile Money
//   - 69X, 65X → Orange Money
// L'utilisateur reçoit une notification push et entre son PIN.
async function campayCollect({ amount, phone, userId, referenceId }) {
    const token = await getCampayToken();

    // Formater le numéro : supprimer espaces, +, et ajouter 237 si absent
    const clean = phone.replace(/[\s\-\(\)]/g, '').replace(/^\+/, '');
    const fullPhone = clean.startsWith('237') ? clean : `237${clean}`;

    const response = await fetch(`${CAMPAY_BASE_URL}/collect/`, {
        method: 'POST',
        headers: {
            'Authorization': `Token ${token}`,
            'Content-Type':  'application/json'
        },
        body: JSON.stringify({
            amount:           String(amount),   // Montant en XAF (string)
            currency:         'XAF',            // Devise Cameroun
            from:             fullPhone,         // Numéro avec indicatif pays
            description:      `Dépôt NextEra — ${amount} XAF`,  // Affiché sur le tel
            external_reference: referenceId,    // Ta référence interne (pour le webhook)
            // app_name : le nom de ton app enregistré dans Campay
            // ✏️  Doit correspondre exactement à ce que tu as mis dans Campay Dashboard
            app_name:         process.env.CAMPAY_APP_NAME || ''
        })
    });

    if (!response.ok) {
        const txt = await response.text();
        throw new Error(`Campay collect error ${response.status}: ${txt}`);
    }

    const data = await response.json();
    // data.reference : référence Campay pour suivre la transaction
    // data.ussd_code : code USSD si l'utilisateur doit le composer manuellement
    return data;
}

// ── Vérifier le statut d'une transaction Campay ───────────────
// Statuts possibles : "SUCCESSFUL", "FAILED", "PENDING"
async function campayCheckStatus(reference) {
    const token = await getCampayToken();

    const response = await fetch(`${CAMPAY_BASE_URL}/transaction/${reference}/`, {
        method: 'GET',
        headers: { 'Authorization': `Token ${token}` }
    });

    if (!response.ok) {
        const txt = await response.text();
        throw new Error(`Campay status error ${response.status}: ${txt}`);
    }

    return await response.json();
    // Retourne : { status, amount, currency, operator, phone, ... }
}

// ── Initier un retrait via Campay (Disbursement) ───────────────
// Envoie de l'argent depuis ton compte Campay vers l'utilisateur.
// Nécessite un solde suffisant dans ton compte marchand Campay.
async function campayWithdraw({ amount, phone, userId, referenceId }) {
    const token = await getCampayToken();

    const clean = phone.replace(/[\s\-\(\)]/g, '').replace(/^\+/, '');
    const fullPhone = clean.startsWith('237') ? clean : `237${clean}`;

    const response = await fetch(`${CAMPAY_BASE_URL}/disburse/`, {
        method: 'POST',
        headers: {
            'Authorization': `Token ${token}`,
            'Content-Type':  'application/json'
        },
        body: JSON.stringify({
            amount:             String(amount),
            currency:           'XAF',
            to:                 fullPhone,   // Numéro destinataire
            description:        `Retrait NextEra — ${amount} XAF`,
            external_reference: referenceId,
            app_name:           process.env.CAMPAY_APP_NAME || ''
        })
    });

    if (!response.ok) {
        const txt = await response.text();
        throw new Error(`Campay disburse error ${response.status}: ${txt}`);
    }

    return await response.json();
}

// ================================================================
// AUTH — INSCRIPTION ET CONNEXION
// ================================================================

// ── INSCRIPTION ────────────────────────────────────────────────
// Chaque nouvel inscrit reçoit automatiquement 1 000 XAF de bonus.
// ✏️  Pour changer le montant du bonus → cherche BONUS_INSCRIPTION ci-dessous
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

        const userId        = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4);
        const generatedCode = 'NEXT-' + userId.slice(-8).toUpperCase();

        // Vérifier le code parrainage
        let referredBy = null;
        if (referralCode && referralCode.trim()) {
            const rows = await db.query('SELECT id FROM users WHERE referral_code = $1', [referralCode.trim()]);
            if (rows.length > 0) referredBy = rows[0].id;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.createUser({
            id: userId, name, email: normalEmail, phone,
            password: hashedPassword, referralCode: generatedCode, referredBy
        });

        // ── BONUS_INSCRIPTION ────────────────────────────────────
        // Crédite 1 000 XAF sur le compte du nouvel inscrit.
        // ✏️  Pour changer le montant : modifie la valeur 1000 ci-dessous.
        const BONUS_INSCRIPTION = 1000; // XAF offerts à chaque inscription
        await db.updateBalance(userId, BONUS_INSCRIPTION);
        await db.addTransaction(userId, 'bonus', BONUS_INSCRIPTION, {
            description: `🎁 Bonus de bienvenue — ${BONUS_INSCRIPTION} XAF offerts à l'inscription !`
        });
        console.log(`[Inscription] Bonus ${BONUS_INSCRIPTION} XAF crédité → ${name} (${normalEmail})`);
        // ────────────────────────────────────────────────────────

        const token = jwt.sign({ userId, email: normalEmail }, JWT_SECRET, { expiresIn: '30d' });
        res.json({
            success: true, token,
            user: { id: userId, name, email: normalEmail, phone, referralCode: generatedCode, isAdmin: false },
            // On informe le frontend du bonus pour afficher un message de bienvenue
            welcomeBonus: BONUS_INSCRIPTION
        });

    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ── CONNEXION ──────────────────────────────────────────────────
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

// ================================================================
// PORTEFEUILLE & INVESTISSEMENTS
// ================================================================
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

// ================================================================
// MARCHÉ
// ================================================================
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
        await db.query(
            'UPDATE portfolios SET total_invested = total_invested + $1 WHERE user_id = $2',
            [numAmount, req.userId]
        );

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

// ================================================================
// PARRAINAGE PYRAMIDAL (10% / 5% / 3%)
// ================================================================
async function processReferralCommissions(investorId, amount) {
    const levels = [
        { level: 1, percent: 10 },
        { level: 2, percent: 5  },
        { level: 3, percent: 3  }
    ];

    let investorUser = await db.getUserById(investorId);
    let currentId    = investorUser?.referred_by;

    for (let i = 0; i < 3 && currentId; i++) {
        const { level, percent } = levels[i];
        const commission = Math.round(amount * percent / 100);

        if (commission > 0) {
            await db.updateBalance(currentId, commission);
            await db.query(
                'UPDATE portfolios SET referral_earnings = referral_earnings + $1 WHERE user_id = $2',
                [commission, currentId]
            );
            await db.addTransaction(currentId, 'referral', commission, {
                description: `🎁 Commission parrainage Niveau ${level} (${percent}%) — investissement de ${amount.toLocaleString('fr-FR')} XAF`
            });
            const parrain = await db.getUserById(currentId);
            console.log(`[Parrainage] Niveau ${level} → ${parrain?.name || currentId} +${commission} XAF`);
        }

        const parentUser = await db.getUserById(currentId);
        currentId = parentUser?.referred_by || null;
    }
}

// ================================================================
//  ██████╗ █████╗ ███╗   ███╗██████╗  █████╗ ██╗   ██╗
// ██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔══██╗╚██╗ ██╔╝
// ██║     ███████║██╔████╔██║██████╔╝███████║ ╚████╔╝
// ██║     ██╔══██║██║╚██╔╝██║██╔═══╝ ██╔══██║  ╚██╔╝
// ╚██████╗██║  ██║██║ ╚═╝ ██║██║     ██║  ██║   ██║
//  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝
//
// ROUTE DÉPÔT — MTN + Orange en une seule route
// ================================================================

// ── depositHandler : logique centrale de dépôt ────────────────
// Appelée par /api/payment/deposit, /api/payment/mtn/deposit, /api/payment/orange/deposit
async function depositHandler(req, res) {
    try {
        const { amount, phone, operator } = req.body;
        const numAmount = parseInt(amount);

        if (!numAmount || numAmount < 1000)
            return res.status(400).json({ success: false, message: 'Montant minimum: 1 000  XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Mobile Money invalide (min 9 chiffres)' });

        // ── MODE SIMULATION ────────────────────────────────────────
        // Actif quand CAMPAY_USERNAME n'est pas encore configuré dans Render.
        // Crédite directement — pratique pour tester l'app avant d'avoir les clés.
        if (!campayIsConfigured()) {
            console.warn('[Campay] ⚠️  Clés non configurées — mode simulation');
            await db.updateBalance(req.userId, numAmount);
            await db.addTransaction(req.userId, 'deposit', numAmount, {
                operator: operator || 'campay', phone,
                description: `[SIMULATION] Dépôt ${numAmount} XAF — configurer CAMPAY_USERNAME pour l'argent réel`
            });
            const p = await db.getPortfolio(req.userId);
            return res.json({
                success:   true,
                simulated: true,
                message:   `✅ [TEST] ${numAmount.toLocaleString('fr-FR')} XAF déposés (simulation)`,
                newBalance: parseInt(p.balance)
            });
        }
        // ─────────────────────────────────────────────────────────

        // ── VRAI PAIEMENT CAMPAY ───────────────────────────────────
        const referenceId = uuidv4(); // ID unique pour cette transaction

        // Stocker la transaction en "attente" avant d'appeler Campay
        // (au cas où le serveur redémarre avant le webhook)
        await db.addTransaction(req.userId, 'deposit', numAmount, {
            operator: operator || 'campay', phone,
            reference: referenceId,
            description: `⏳ Dépôt en attente — ${numAmount} XAF (confirmation Mobile Money requise)`
        });

        // Sauvegarder le paiement en attente en BDD
        await db.query(
            `INSERT INTO pending_payments (reference_id, user_id, amount, operator, created_at)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
             ON CONFLICT (reference_id) DO NOTHING`,
            [referenceId, req.userId, numAmount, operator || 'campay']
        );

        // Appeler Campay → l'utilisateur reçoit la notif push sur son téléphone
        const campayResponse = await campayCollect({
            amount: numAmount, phone, userId: req.userId, referenceId
        });

        console.log(`[Campay] Dépôt initié — ref: ${referenceId}, user: ${req.userId}, ${numAmount} XAF, tel: ${phone}`);

        // Répondre immédiatement — le crédit se fait via le webhook
        res.json({
            success:   true,
            pending:   true,
            referenceId,
            campayRef: campayResponse.reference,
            message:   `📱 Confirmez le paiement de ${numAmount.toLocaleString('fr-FR')} XAF sur votre téléphone !`
        });
        // ─────────────────────────────────────────────────────────

    } catch (err) {
        console.error('[Campay] Deposit error:', err);
        res.status(500).json({ success: false, message: `Erreur paiement: ${err.message}` });
    }
}

// Route principale — les alias ci-dessous appellent aussi depositHandler
app.post('/api/payment/deposit', authMiddleware, depositHandler);

// Alias MTN et Orange → Campay les gère automatiquement.
// Ces routes existent pour la compatibilité avec l'ancien frontend.
// Elles injectent l'opérateur dans req.body et appellent la même logique.
app.post('/api/payment/mtn/deposit',    authMiddleware, async (req, res) => {
    req.body.operator = 'mtn';
    return depositHandler(req, res);
});
app.post('/api/payment/orange/deposit', authMiddleware, async (req, res) => {
    req.body.operator = 'orange';
    return depositHandler(req, res);
});

// ================================================================
// CAMPAY — WEBHOOK (Confirmation de paiement)
// ================================================================
// Campay appelle cette URL automatiquement quand un paiement est
// confirmé (SUCCESSFUL) ou refusé (FAILED) par l'utilisateur.
//
// ✏️  Dans ton Dashboard Campay → Settings → Webhook URL, entre :
//     https://nextera-api.onrender.com/api/payment/campay/callback
//
app.post('/api/payment/campay/callback', async (req, res) => {
    try {
        // Campay envoie ces champs dans le body du webhook :
        const {
            reference,          // Référence Campay de la transaction
            external_reference, // Ta référence interne (referenceId qu'on a envoyé)
            status,             // "SUCCESSFUL" ou "FAILED"
            amount,
            operator,           // "MTN" ou "Orange"
            phone
        } = req.body;

        console.log(`[Campay Webhook] ref: ${external_reference}, status: ${status}, ${amount} XAF`);

        // Toujours répondre 200 en premier — Campay retente sinon
        res.status(200).json({ received: true });

        const refId = external_reference || reference;
        if (!refId) return;

        if (status === 'SUCCESSFUL') {
            // Récupérer le paiement en attente (et vérifier qu'il n'est pas déjà crédité)
            const pending = await db.query(
                'SELECT * FROM pending_payments WHERE reference_id = $1 AND paid = FALSE',
                [refId]
            );

            if (pending.length > 0) {
                const { user_id, amount: pendingAmount } = pending[0];
                const numAmount = parseInt(pendingAmount);

                // Anti-double-crédit : marquer comme payé en premier
                await db.query(
                    'UPDATE pending_payments SET paid = TRUE, paid_at = CURRENT_TIMESTAMP WHERE reference_id = $1',
                    [refId]
                );

                // Créditer le solde de l'utilisateur
                await db.updateBalance(user_id, numAmount);

                // Mettre à jour la description de la transaction
                await db.query(
                    `UPDATE transactions SET description = $1 WHERE reference = $2`,
                    [`✅ Dépôt ${operator || 'Mobile Money'} confirmé — ${numAmount.toLocaleString('fr-FR')} XAF`, refId]
                );

                console.log(`[Campay Webhook] ✅ Crédité — user: ${user_id}, +${numAmount} XAF via ${operator}`);
            }

        } else if (status === 'FAILED') {
            // Supprimer le paiement en attente et noter l'échec
            await db.query('DELETE FROM pending_payments WHERE reference_id = $1', [refId]);
            await db.query(
                `UPDATE transactions SET description = $1 WHERE reference = $2`,
                [`❌ Dépôt échoué — paiement refusé ou expiré`, refId]
            );
            console.log(`[Campay Webhook] ❌ Paiement refusé — ref: ${refId}`);
        }

    } catch (err) {
        console.error('[Campay Webhook] Erreur:', err);
    }
});

// ================================================================
// CAMPAY — VÉRIFICATION MANUELLE DU STATUT
// ================================================================
// L'utilisateur peut vérifier si son paiement est passé sans attendre.
// Utile si le webhook tarde ou si la connexion a coupé.
app.get('/api/payment/status/:referenceId', authMiddleware, async (req, res) => {
    try {
        const { referenceId } = req.params;

        if (!campayIsConfigured())
            return res.json({ success: true, status: 'SIMULATED', message: 'Mode simulation actif' });

        const data = await campayCheckStatus(referenceId);
        res.json({ success: true, status: data.status, operator: data.operator, data });

    } catch (err) {
        console.error('[Campay Status]', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// RETRAIT (1 par jour · minimum 1 500 XAF · frais 1%)
// ================================================================
app.post('/api/payment/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, phone, operator } = req.body;
        const numAmount = parseInt(amount);

        // Validations
        if (!numAmount || numAmount < 1500)
            return res.status(400).json({ success: false, message: 'Montant minimum de retrait : 1 500 XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Mobile Money invalide' });

        // 1 seul retrait par jour par compte
        const alreadyWithdrawn = await db.query(
            `SELECT id FROM transactions
             WHERE user_id = $1 AND type = 'withdrawal' AND created_at::date = CURRENT_DATE`,
            [req.userId]
        );
        if (alreadyWithdrawn.length > 0)
            return res.status(400).json({ success: false, message: '⛔ Un seul retrait autorisé par jour. Revenez demain.' });

        const portfolio = await db.getPortfolio(req.userId);
        if (!portfolio || parseInt(portfolio.balance) < numAmount)
            return res.status(400).json({ success: false, message: 'Solde insuffisant' });

        const fee       = Math.round(numAmount * 0.01); // 1% de frais
        const netAmount = numAmount - fee;

        // Débiter immédiatement (avant d'envoyer via Campay)
        await db.updateBalance(req.userId, numAmount, 'subtract');

        // ── RETRAIT VIA CAMPAY (si configuré) ─────────────────────
        if (campayIsConfigured()) {
            try {
                const referenceId = uuidv4();
                await campayWithdraw({
                    amount: netAmount, phone, userId: req.userId, referenceId
                });
                await db.addTransaction(req.userId, 'withdrawal', numAmount, {
                    fee, netAmount, operator: operator || 'campay', phone,
                    reference: referenceId,
                    description: `✅ Retrait envoyé via Campay — ${netAmount.toLocaleString('fr-FR')} XAF nets`
                });
                console.log(`[Campay] Retrait envoyé — user: ${req.userId}, ${netAmount} XAF → ${phone}`);
            } catch (campayErr) {
                // Si Campay échoue, rembourser le solde
                await db.updateBalance(req.userId, numAmount);
                console.error('[Campay] Retrait échoué, remboursé:', campayErr.message);
                return res.status(500).json({ success: false, message: `Retrait échoué: ${campayErr.message}` });
            }
        } else {
            // Mode simulation : juste décrémenter le solde
            await db.addTransaction(req.userId, 'withdrawal', numAmount, {
                fee, netAmount, operator: operator || 'mtn', phone,
                description: `[SIMULATION] Retrait ${netAmount.toLocaleString('fr-FR')} XAF`
            });
        }
        // ─────────────────────────────────────────────────────────

        res.json({
            success:    true,
            message:    `✅ ${netAmount.toLocaleString('fr-FR')} XAF en cours d'envoi (frais: ${fee} XAF)`,
            netAmount, fee,
            newBalance: parseInt(portfolio.balance) - numAmount
        });

    } catch (err) {
        console.error('Withdraw error:', err);
        res.status(500).json({ success: false, message: 'Erreur lors du retrait' });
    }
});

// ================================================================
// BONUS JOURNALIER (100 XAF / jour, à réclamer manuellement)
// ================================================================
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

// ================================================================
// PARRAINAGE — STATS
// ================================================================
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

// ================================================================
// ADMIN
// ================================================================
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users      = await db.query('SELECT id, name, email, phone, is_admin, referral_code, referred_by, created_at FROM users ORDER BY created_at DESC');
        const portfolios = await db.query('SELECT user_id, balance, total_invested, referral_earnings, total_gains FROM portfolios');
        const stats      = await db.query(`
            SELECT
                (SELECT COUNT(*) FROM users)::int                            AS "totalUsers",
                (SELECT COUNT(*) FROM investments WHERE status='active')::int AS "totalInvestments",
                (SELECT COUNT(*) FROM transactions)::int                     AS "totalTransactions",
                (SELECT COALESCE(SUM(balance),0) FROM portfolios)::bigint    AS "totalBalance"
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
        if (balance       !== undefined) await db.query('UPDATE portfolios SET balance = $1 WHERE user_id = $2',        [balance, userId]);
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

// ================================================================
// HEALTH CHECK
// ================================================================
app.get('/api/health', async (req, res) => {
    try {
        const r = await db.query('SELECT COUNT(*) AS cnt FROM users');
        res.json({
            success:   true,
            status:    'online',
            users:     parseInt(r[0].cnt),
            campay:    campayIsConfigured() ? 'actif' : 'simulation',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ success: false, status: 'db_error', message: err.message });
    }
});

// SPA fallback — toutes les routes non-API → index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ================================================================
// CRONS AUTOMATIQUES
// ================================================================

// ── 1. KEEPALIVE anti-sleep Render (ping toutes les 14 min) ───
function startKeepalive() {
    const SELF_URL = process.env.RENDER_EXTERNAL_URL
        ? `${process.env.RENDER_EXTERNAL_URL}/api/health`
        : `http://localhost:${PORT}/api/health`;

    setInterval(() => {
        try {
            const http = SELF_URL.startsWith('https') ? require('https') : require('http');
            http.get(SELF_URL, (r) => {
                console.log(`[Keepalive] ${r.statusCode} — ${new Date().toLocaleTimeString('fr-FR')}`);
            }).on('error', (e) => console.warn('[Keepalive] Ping failed:', e.message));
        } catch (e) { console.warn('[Keepalive] Error:', e.message); }
    }, 14 * 60 * 1000);

    console.log('✅ [Keepalive] Ping toutes les 14 minutes');
}

// ── 2. GAINS JOURNALIERS — distribution automatique à minuit UTC
function startDailyGainsCron() {
    async function distributeAllUsersGains() {
        console.log('[Gains CRON] ⏰ Distribution journalière...');
        try {
            const users = await db.query("SELECT DISTINCT user_id FROM investments WHERE status = 'active'");
            let totalUsers = 0, totalXAF = 0;
            for (const row of users) {
                try {
                    const gain = await db.applyDailyGains(row.user_id);
                    if (gain > 0) { totalUsers++; totalXAF += gain; }
                } catch (e) { console.error(`[Gains CRON] Erreur user ${row.user_id}:`, e.message); }
            }
            console.log(`[Gains CRON] ✅ ${totalUsers} utilisateurs crédités, +${totalXAF.toLocaleString('fr-FR')} XAF`);
        } catch (e) { console.error('[Gains CRON] Erreur:', e.message); }
    }

    function msUntilMidnightUTC() {
        const now = new Date();
        return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 30)) - now;
    }

    const delay = msUntilMidnightUTC();
    console.log(`✅ [Gains CRON] Prochaine distribution dans ${Math.round(delay/1000/60)} min (minuit UTC)`);
    setTimeout(() => {
        distributeAllUsersGains();
        setInterval(distributeAllUsersGains, 24 * 60 * 60 * 1000);
    }, delay);
}

// ── 3. NETTOYAGE — supprime les paiements expirés après 24h
function startCleanupCron() {
    setInterval(async () => {
        try {
            await db.query("DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '365 days'");
            await db.query("DELETE FROM pending_payments WHERE paid = FALSE AND created_at < NOW() - INTERVAL '24 hours'");
        } catch (e) { /* Silencieux */ }
    }, 24 * 60 * 60 * 1000);
}

// ================================================================
// COMPTES PAR DÉFAUT (créés si absents au démarrage)
// ================================================================
async function createDefaultAccounts() {
    // Compte admin
    const admin = await db.getUserByEmail('admin@nextera.com');
    if (!admin) {
        const id   = 'user_admin';
        const hash = await bcrypt.hash('admin123', 10);
        await db.query(
            'INSERT INTO users (id,name,email,phone,password,is_admin,referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id, 'Administrateur', 'admin@nextera.com', '699999999', hash, true, 'NEXT-ADMIN001']
        );
        await db.query(
            'INSERT INTO portfolios (user_id,balance,total_invested,referral_earnings,total_gains) VALUES ($1,500000,0,0,0) ON CONFLICT (user_id) DO NOTHING',
            [id]
        );
        console.log('✅ Compte admin: admin@nextera.com / admin123');
    }

    // Compte de test
    const test = await db.getUserByEmail('test@nextera.com');
    if (!test) {
        const id   = 'user_test';
        const hash = await bcrypt.hash('test123', 10);
        await db.query(
            'INSERT INTO users (id,name,email,phone,password,is_admin,referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id, 'Jean Dupont', 'test@nextera.com', '690000000', hash, false, 'NEXT-TEST001']
        );
        await db.query(
            'INSERT INTO portfolios (user_id,balance,total_invested,referral_earnings,total_gains) VALUES ($1,1000,0,0,0) ON CONFLICT (user_id) DO NOTHING',
            [id]
        );
        console.log('✅ Compte test: test@nextera.com / test123');
    }
}

// ================================================================
// DÉMARRAGE DU SERVEUR
// ================================================================
app.listen(PORT, async () => {
    const connected = await db.testConnection();
    if (!connected) {
        console.error('❌ Impossible de se connecter à PostgreSQL. Vérifier DATABASE_URL dans Render.');
        process.exit(1);
    }

    await db.initTables();
    await createDefaultAccounts();

    startKeepalive();
    startDailyGainsCron();
    startCleanupCron();

    const campayOk = campayIsConfigured();

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🌿 NextEra — Port ${String(PORT).padEnd(42)}║
║  📊 Health   : /api/health                                   ║
║  🔑 Admin    : admin@nextera.com / admin123                  ║
║  🧪 Test     : test@nextera.com  / test123                   ║
║  🎁 Bonus    : 1 000 XAF offerts à chaque inscription        ║
║                                                              ║
║  CAMPAY (MTN + Orange) :                                     ║
║  ${campayOk ? '✅ ACTIF — argent réel (clés configurées)         ' : '⚠️  SIMULATION — ajouter CAMPAY_USERNAME dans Render'}   ║
╚══════════════════════════════════════════════════════════════╝`);
});
