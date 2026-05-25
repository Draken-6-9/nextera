// ================================================================
// server.js — NextEra Backend (PostgreSQL / Render)
// ================================================================
// FICHIERS MODIFIÉS DANS CETTE VERSION :
//   → server.js   (CE FICHIER) — paiements MTN + Orange réels
//   → database.js              — table pending_payments ajoutée
//   → .env.example             — clés API documentées
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
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
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
//
//  ██████╗  █████╗ ██╗███████╗███╗   ███╗███████╗███╗   ██╗████████╗███████╗
//  ██╔══██╗██╔══██╗██║██╔════╝████╗ ████║██╔════╝████╗  ██║╚══██╔══╝██╔════╝
//  ██████╔╝███████║██║█████╗  ██╔████╔██║█████╗  ██╔██╗ ██║   ██║   ███████╗
//  ██╔═══╝ ██╔══██║██║██╔══╝  ██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
//  ██║     ██║  ██║██║███████╗██║ ╚═╝ ██║███████╗██║ ╚████║   ██║   ███████║
//  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
//
// ══════════════════════════════════════════════════════════════
// MTN MOBILE MONEY — DÉPÔT (Collection)
// ══════════════════════════════════════════════════════════════
//
// CLÉS À RENSEIGNER dans Render → Dashboard → nextera-api → Environment :
//
//   MTN_BASE_URL      = https://sandbox.momodeveloper.mtn.com
//                       ↑ sandbox pour tester / prod : même URL,
//                         changer seulement MTN_TARGET_ENV
//
//   MTN_PRIMARY_KEY   = ta clé d'abonnement "Collection"
//                       Où la trouver :
//                       momodeveloper.mtn.com → Profile → Subscriptions
//                       → copier "Primary Key" du produit Collection
//
//   MTN_API_USER      = UUID de ton API User
//                       Comment le créer : voir .env.example section MTN
//
//   MTN_API_KEY       = clé secrète liée à ton API User
//                       Comment la créer : voir .env.example section MTN
//
//   MTN_TARGET_ENV    = sandbox    (pour les tests avec argent fictif)
//                       mtncameroon (pour la production Cameroun)
//
//   MTN_CURRENCY      = XAF
//
//   MTN_CALLBACK_URL  = https://TON-SERVICE.onrender.com/api/payment/mtn/callback
//                       ↑ Remplacer TON-SERVICE par le vrai nom de ton service Render
//
// ══════════════════════════════════════════════════════════════

// ── Vérifie si MTN est configuré (sinon → mode simulation) ──
function mtnIsConfigured() {
    const k = (process.env.MTN_PRIMARY_KEY || '').trim();
    const u = (process.env.MTN_API_USER    || '').trim();
    const a = (process.env.MTN_API_KEY     || '').trim();
    return k.length > 0 && u.length > 0 && a.length > 0
        && !k.includes('VOTRE') && !u.includes('VOTRE') && !a.includes('VOTRE');
}

// ── Obtenir un token Bearer MTN ──────────────────────────────
// MTN utilise OAuth2 Basic : on encode apiUser:apiKey en Base64.
// Le token dure 3600 secondes.
async function getMtnToken() {
    const apiUser = (process.env.MTN_API_USER || '').trim();
    const apiKey  = (process.env.MTN_API_KEY  || '').trim();
    const subKey  = (process.env.MTN_PRIMARY_KEY || '').trim();
    const baseUrl = (process.env.MTN_BASE_URL || 'https://sandbox.momodeveloper.mtn.com').trim();
    const targetEnv = (process.env.MTN_TARGET_ENV || 'sandbox').trim();

    if (!apiUser || !apiKey || !subKey)
        throw new Error('Clés MTN manquantes (MTN_API_USER, MTN_API_KEY ou MTN_PRIMARY_KEY vides dans Render)');

    const credentials = Buffer.from(`${apiUser}:${apiKey}`).toString('base64');

    let resText = '';
    try {
        const res = await fetch(`${baseUrl}/collection/token/`, {
            method: 'POST',
            headers: {
                'Authorization':              `Basic ${credentials}`,
                'Ocp-Apim-Subscription-Key': subKey,
                // Requis en sandbox MTN (ignoré en prod mais inoffensif)
                'X-Target-Environment':       targetEnv,
            }
        });
        resText = await res.text();
        if (!res.ok) {
            // Fournir des messages d'erreur clairs selon le code HTTP
            if (res.status === 401) throw new Error(`MTN token 401 — API User ou API Key incorrect. Vérifiez MTN_API_USER et MTN_API_KEY dans Render. Détail: ${resText}`);
            if (res.status === 403) throw new Error(`MTN token 403 — Primary Key refusée ou quota dépassé. Vérifiez MTN_PRIMARY_KEY dans Render. Détail: ${resText}`);
            throw new Error(`MTN token ${res.status}: ${resText}`);
        }
        const data = JSON.parse(resText);
        if (!data.access_token) throw new Error(`MTN token: réponse sans access_token. Reçu: ${resText}`);
        return data.access_token;
    } catch (err) {
        if (err.message.startsWith('MTN token')) throw err;
        throw new Error(`MTN token — impossible de joindre ${baseUrl} : ${err.message}`);
    }
}

// ── Initier un paiement MTN (Request To Pay) ─────────────────
// MTN envoie une notification push sur le téléphone de l'utilisateur.
// L'utilisateur entre son PIN → MTN appelle le webhook de confirmation.
async function mtnRequestToPay({ amount, phone, referenceId, userId }) {
    const token     = await getMtnToken();
    const baseUrl   = (process.env.MTN_BASE_URL   || 'https://sandbox.momodeveloper.mtn.com').trim();
    const targetEnv = (process.env.MTN_TARGET_ENV || 'sandbox').trim();
    const subKey    = (process.env.MTN_PRIMARY_KEY || '').trim();
    const currency: (process.env.MTN_TARGET_ENV === 'sandbox') ? 'EUR' : (process.env.MTN_CURRENCY || 'XAF'),//currency  = (process.env.MTN_CURRENCY   || 'XAF').trim();
    const callbackUrl = (process.env.MTN_CALLBACK_URL || '').trim();

    // Formatage du numéro : 069XXXXXX → 237690XXXXXX
    const clean  = phone.replace(/[\s\-\(\)\+]/g, '');
    const msisdn = clean.startsWith('237') ? clean : `237${clean.replace(/^0/, '')}`;

    let resText = '';
    try {
        const headers = {
            'Authorization':              `Bearer ${token}`,
            'X-Reference-Id':             referenceId,
            'X-Target-Environment':       targetEnv,
            'Ocp-Apim-Subscription-Key': subKey,
            'Content-Type':               'application/json',
        };
        if (callbackUrl) headers['X-Callback-Url'] = callbackUrl;

        const res = await fetch(`${baseUrl}/collection/v1_0/requesttopay`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                amount:    String(amount),
                currency:  currency,
                externalId: userId,
                payer: { partyIdType: 'MSISDN', partyId: msisdn },
                payerMessage: `Depot NextEra ${amount} XAF`,
                payeeNote:    `Compte ${userId}`
            })
        });
        resText = await res.text();
        // MTN répond 202 Accepted (pas 200) quand la demande est bien initiée
        if (res.status !== 202) {
            if (res.status === 400) throw new Error(`MTN 400 — Numéro invalide ou montant incorrect. Numéro envoyé: ${msisdn}. Détail: ${resText}`);
            if (res.status === 401) throw new Error(`MTN 401 — API User/Key incorrect. Vérifiez MTN_API_USER et MTN_API_KEY. Détail: ${resText}`);
            if (res.status === 403) throw new Error(`MTN 403 — Primary Key refusée. Vérifiez MTN_PRIMARY_KEY. Détail: ${resText}`);
            if (res.status === 409) throw new Error(`MTN 409 — Reference ID en double. Réessayez. Détail: ${resText}`);
            throw new Error(`MTN requestToPay ${res.status}: ${resText}`);
        }
    } catch (err) {
        if (err.message.startsWith('MTN')) throw err;
        throw new Error(`MTN — réseau inaccessible: ${err.message}`);
    }
    return referenceId;
}

// ── Vérifier le statut d'un paiement MTN ─────────────────────
// Statuts : "SUCCESSFUL", "FAILED", "PENDING"
async function mtnCheckStatus(referenceId) {
    const token = await getMtnToken();
    const res = await fetch(
        `${process.env.MTN_BASE_URL}/collection/v1_0/requesttopay/${referenceId}`,
        {
            headers: {
                'Authorization':              `Bearer ${token}`,
                'X-Target-Environment':       process.env.MTN_TARGET_ENV,
                'Ocp-Apim-Subscription-Key': process.env.MTN_PRIMARY_KEY,
            }
        }
    );
    if (!res.ok) throw new Error(`MTN status ${res.status}: ${await res.text()}`);
    return await res.json(); // { status, amount, currency, payer, ... }
}

// ══════════════════════════════════════════════════════════════
// ORANGE MONEY — DÉPÔT (Web Pay)
// ══════════════════════════════════════════════════════════════
//
// CLÉS À RENSEIGNER dans Render → Dashboard → nextera-api → Environment :
//
//   ORANGE_CLIENT_ID      = ton Client ID Orange Developer
//                           Où le trouver :
//                           developer.orange.com → My Apps → ton app → Credentials
//
//   ORANGE_CLIENT_SECRET  = ton Client Secret Orange Developer
//                           Même endroit que le Client ID
//                           ⚠️  Ne jamais partager cette valeur
//
//   ORANGE_MERCHANT_KEY   = clé marchande fournie par Orange Cameroun
//                           → En sandbox  : clé de test dans la doc Orange
//                           → En prod     : fournie par Orange Cameroun Business
//                                           Contacter : +237 655 000 000
//
//   ORANGE_MERCHANT_PHONE = ton numéro de compte marchand Orange avec indicatif
//                           Exemple : 237690000001
//
//   ORANGE_NOTIF_URL      = https://TON-SERVICE.onrender.com/api/payment/orange/callback
//                           ↑ URL appelée par Orange quand le paiement est confirmé
//
//   ORANGE_RETURN_URL     = https://TON-SERVICE.onrender.com?payment=success
//                           ↑ Page affichée à l'utilisateur après le paiement
//
//   ORANGE_CANCEL_URL     = https://TON-SERVICE.onrender.com?payment=cancelled
//                           ↑ Page affichée si l'utilisateur annule
//
// ══════════════════════════════════════════════════════════════

// ── Vérifie si Orange est configuré (sinon → mode simulation) ─
function orangeIsConfigured() {
    const id  = (process.env.ORANGE_CLIENT_ID     || '').trim();
    const sec = (process.env.ORANGE_CLIENT_SECRET || '').trim();
    const key = (process.env.ORANGE_MERCHANT_KEY  || '').trim();
    return id.length > 0 && sec.length > 0 && key.length > 0
        && !id.includes('VOTRE') && !sec.includes('VOTRE') && !key.includes('VOTRE');
}

// ── Obtenir un token OAuth2 Orange ───────────────────────────
// Orange utilise OAuth2 client_credentials.
// Le token dure 3600 secondes.
async function getOrangeToken() {
    const credentials = Buffer.from(
        `${process.env.ORANGE_CLIENT_ID}:${process.env.ORANGE_CLIENT_SECRET}`
    ).toString('base64');

    const res = await fetch('https://api.orange.com/oauth/v3/token', {
        method: 'POST',
        headers: {
            // Authorization : Basic <base64(clientId:clientSecret)>
            'Authorization': `Basic ${credentials}`,
            'Content-Type':  'application/x-www-form-urlencoded',
            'Accept':        'application/json',
        },
        body: 'grant_type=client_credentials' // obligatoire pour OAuth2
    });
    if (!res.ok) throw new Error(`Orange token ${res.status}: ${await res.text()}`);
    const data = await res.json();
    return data.access_token;
}

// ── Créer une session de paiement Orange Money ───────────────
// Retourne payment_url → le frontend redirige l'utilisateur vers cette URL.
// L'utilisateur entre son PIN sur la page Orange → Orange appelle le webhook.
async function orangeCreatePayment({ amount, phone, orderId, userId }) {
    const token = await getOrangeToken();

    // Formatage du numéro : 069XXXXXX → 237690XXXXXX
    const clean = phone.replace(/[\s\-\(\)\+]/g, '');
    const msisdn = clean.startsWith('237') ? clean : `237${clean.replace(/^0/, '')}`;

    const res = await fetch(
        `${process.env.ORANGE_BASE_URL || 'https://api.orange.com/orange-money-webpay/cm/v1'}/webpayment`,
        {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type':  'application/json',
                'Accept':        'application/json',
            },
            body: JSON.stringify({
                merchant_key: process.env.ORANGE_MERCHANT_KEY,  // Ta clé marchande
                currency:     'OAF',                            // OAF = XAF pour l'API Orange
                order_id:     orderId,                          // Ton identifiant unique
                amount:       amount,                           // Montant en XAF (entier)
                return_url:   process.env.ORANGE_RETURN_URL,   // Après paiement réussi
                cancel_url:   process.env.ORANGE_CANCEL_URL,   // Si l'utilisateur annule
                notif_url:    process.env.ORANGE_NOTIF_URL,    // Webhook Orange → ton serveur
                lang:         'fr',                             // Langue de la page Orange
                reference:    userId,                           // Ta référence interne
            })
        }
    );
    if (!res.ok) throw new Error(`Orange createPayment ${res.status}: ${await res.text()}`);
    const data = await res.json();
    // data.payment_url : URL vers laquelle rediriger l'utilisateur
    // data.pay_token   : token pour vérifier le statut plus tard
    return { paymentUrl: data.payment_url, payToken: data.pay_token };
}

// ================================================================
// AUTH — INSCRIPTION ET CONNEXION
// ================================================================

// ── INSCRIPTION ────────────────────────────────────────────────
// Chaque nouvel inscrit reçoit 1 000 XAF de bonus de bienvenue.
// ✏️  Pour changer ce montant : modifie BONUS_INSCRIPTION ci-dessous.
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

        let referredBy = null;
        if (referralCode && referralCode.trim()) {
            const rows = await db.query('SELECT id FROM users WHERE referral_code = $1', [referralCode.trim()]);
            if (rows.length > 0) referredBy = rows[0].id;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.createUser({ id: userId, name, email: normalEmail, phone, password: hashedPassword, referralCode: generatedCode, referredBy });

        // ── BONUS DE BIENVENUE ─────────────────────────────────
        // ✏️  Changer 1000 par le montant souhaité (en XAF)
        const BONUS_INSCRIPTION = 1000;
        await db.updateBalance(userId, BONUS_INSCRIPTION);
        await db.addTransaction(userId, 'bonus', BONUS_INSCRIPTION, {
            description: `🎁 Bonus de bienvenue — ${BONUS_INSCRIPTION} XAF offerts !`
        });
        console.log(`[Inscription] +${BONUS_INSCRIPTION} XAF bonus → ${name} (${normalEmail})`);
        // ──────────────────────────────────────────────────────

        const token = jwt.sign({ userId, email: normalEmail }, JWT_SECRET, { expiresIn: '30d' });
        res.json({
            success: true, token,
            user: { id: userId, name, email: normalEmail, phone, referralCode: generatedCode, isAdmin: false },
            welcomeBonus: BONUS_INSCRIPTION // le frontend peut afficher ce message de bienvenue
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
        const machines  = await db.getMachines();
        const machine   = machines.find(m => String(m.id) === String(machineId));
        if (!machine)
            return res.status(400).json({ success: false, message: 'Machine introuvable' });
        if (numAmount < parseInt(machine.price))
            return res.status(400).json({ success: false, message: `Montant minimum: ${machine.price} XAF` });
        const portfolio = await db.getPortfolio(req.userId);
        if (!portfolio || parseInt(portfolio.balance) < numAmount)
            return res.status(400).json({ success: false, message: 'Solde insuffisant' });

        const investmentId = uuidv4();
        await db.createInvestment({ id: investmentId, userId: req.userId, machineId: machine.id, machineName: machine.name, machineIcon: machine.icon || '⚡', amount: numAmount, dailyYield: parseInt(machine.daily_yield) });
        await db.updateBalance(req.userId, numAmount, 'subtract');
        await db.query('UPDATE portfolios SET total_invested = total_invested + $1 WHERE user_id = $2', [numAmount, req.userId]);

        const user = await db.getUserById(req.userId);
        if (user?.referred_by) await processReferralCommissions(req.userId, numAmount);

        await db.addTransaction(req.userId, 'investment', numAmount, { description: `Achat ${machine.icon || '⚡'} ${machine.name}` });
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
    const levels = [{ level:1, percent:10 }, { level:2, percent:5 }, { level:3, percent:3 }];
    let currentId = (await db.getUserById(investorId))?.referred_by;
    for (let i = 0; i < 3 && currentId; i++) {
        const { level, percent } = levels[i];
        const commission = Math.round(amount * percent / 100);
        if (commission > 0) {
            await db.updateBalance(currentId, commission);
            await db.query('UPDATE portfolios SET referral_earnings = referral_earnings + $1 WHERE user_id = $2', [commission, currentId]);
            await db.addTransaction(currentId, 'referral', commission, {
                description: `🎁 Commission parrainage Niveau ${level} (${percent}%) — investissement de ${amount.toLocaleString('fr-FR')} XAF`
            });
            const parrain = await db.getUserById(currentId);
            console.log(`[Parrainage] Niveau ${level} → ${parrain?.name || currentId} +${commission} XAF`);
        }
        currentId = (await db.getUserById(currentId))?.referred_by || null;
    }
}

// ================================================================
// PAIEMENTS — MTN MOBILE MONEY (DÉPÔT)
// ================================================================
// Flux : utilisateur saisit montant + numéro MTN → notification push
// → il entre son PIN sur son téléphone → MTN appelle le webhook
// → le webhook crédite le solde en base.

app.post('/api/payment/mtn/deposit', authMiddleware, async (req, res) => {
    try {
        const { amount, phone } = req.body;
        const numAmount = parseInt(amount);

        if (!numAmount || numAmount < 1000)
            return res.status(400).json({ success: false, message: 'Montant minimum: 1 000 XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro MTN invalide (min 9 chiffres)' });

        // ── MODE SIMULATION ────────────────────────────────────
        // Si les clés MTN ne sont pas encore configurées dans Render,
        // le dépôt est crédité directement (pour tests internes).
        // Le log affiche un avertissement clair.
        if (!mtnIsConfigured()) {
            console.warn('[MTN] ⚠️  Clés non configurées — simulation active');
            await db.updateBalance(req.userId, numAmount);
            await db.addTransaction(req.userId, 'deposit', numAmount, {
                operator: 'mtn', phone,
                description: `[SIMULATION] Dépôt MTN ${numAmount} XAF — ajouter MTN_PRIMARY_KEY dans Render`
            });
            const p = await db.getPortfolio(req.userId);
            return res.json({ success: true, simulated: true, message: `✅ [TEST] ${numAmount.toLocaleString('fr-FR')} XAF déposés (simulation MTN)`, newBalance: parseInt(p.balance) });
        }
        // ────────────────────────────────────────────────────────

        // ── VRAI PAIEMENT MTN ──────────────────────────────────
        const referenceId = uuidv4();

        // 1. Enregistrer la transaction en "attente" avant d'appeler MTN
        //    (évite de perdre la trace si le serveur redémarre)
        await db.addTransaction(req.userId, 'deposit', numAmount, {
            operator: 'mtn', phone, reference: referenceId,
            description: `⏳ Dépôt MTN en attente — ${numAmount} XAF`
        });
        await db.query(
            `INSERT INTO pending_payments (reference_id, user_id, amount, operator, created_at)
             VALUES ($1, $2, $3, 'mtn', CURRENT_TIMESTAMP) ON CONFLICT (reference_id) DO NOTHING`,
            [referenceId, req.userId, numAmount]
        );

        // 2. Appeler MTN → notification push envoyée sur le téléphone
        await mtnRequestToPay({ amount: numAmount, phone, referenceId, userId: req.userId });
        console.log(`[MTN] Dépôt initié — ref:${referenceId} user:${req.userId} ${numAmount} XAF`);

        // 3. Répondre immédiatement — le crédit se fait via le webhook ci-dessous
        res.json({
            success: true, pending: true, referenceId,
            message: `📱 Confirmez le paiement de ${numAmount.toLocaleString('fr-FR')} XAF sur votre téléphone MTN !`
        });
        // ────────────────────────────────────────────────────────
    } catch (err) {
        console.error('[MTN] Deposit error:', err);
        res.status(500).json({ success: false, message: `Erreur MTN: ${err.message}` });
    }
});

// ── MTN — WEBHOOK ──────────────────────────────────────────────
// MTN appelle automatiquement cette URL quand l'utilisateur confirme
// ou refuse le paiement.
//
// ✏️  À configurer dans momodeveloper.mtn.com → ton app → Callback URL :
//     https://TON-SERVICE.onrender.com/api/payment/mtn/callback
//     (et aussi dans la variable MTN_CALLBACK_URL dans Render)
//
app.post('/api/payment/mtn/callback', async (req, res) => {
    try {
        const { referenceId, status, financialTransactionId } = req.body;
        console.log(`[MTN Callback] ref:${referenceId} status:${status}`);

        // Toujours répondre 200 d'abord — MTN retente si on ne répond pas
        res.status(200).json({ received: true });

        if (!referenceId) return;

        // Double vérification du statut auprès de MTN (sécurité)
        let finalStatus = status;
        try {
            const check = await mtnCheckStatus(referenceId);
            finalStatus = check.status;
        } catch (e) {
            console.warn('[MTN Callback] Impossible de vérifier statut:', e.message);
        }

        if (finalStatus === 'SUCCESSFUL') {
            const pending = await db.query(
                'SELECT * FROM pending_payments WHERE reference_id = $1 AND paid = FALSE',
                [referenceId]
            );
            if (pending.length > 0) {
                const { user_id, amount } = pending[0];
                // Anti-double-crédit : marquer payé AVANT de créditer
                await db.query(
                    'UPDATE pending_payments SET paid = TRUE, paid_at = CURRENT_TIMESTAMP WHERE reference_id = $1',
                    [referenceId]
                );
                await db.updateBalance(user_id, parseInt(amount));
                await db.query(
                    `UPDATE transactions SET description = $1 WHERE reference = $2`,
                    [`✅ Dépôt MTN confirmé — ${parseInt(amount).toLocaleString('fr-FR')} XAF`, referenceId]
                );
                console.log(`[MTN Callback] ✅ Crédité — user:${user_id} +${amount} XAF txn:${financialTransactionId}`);
            }
        } else if (finalStatus === 'FAILED') {
            await db.query('DELETE FROM pending_payments WHERE reference_id = $1', [referenceId]);
            await db.query(
                `UPDATE transactions SET description = $1 WHERE reference = $2`,
                [`❌ Dépôt MTN échoué — paiement refusé ou expiré`, referenceId]
            );
            console.log(`[MTN Callback] ❌ Échoué — ref:${referenceId}`);
        }
    } catch (err) {
        console.error('[MTN Callback] Erreur:', err);
    }
});

// ── MTN — VÉRIFICATION MANUELLE ───────────────────────────────
// L'utilisateur peut vérifier si son paiement est passé sans attendre le webhook.
app.get('/api/payment/mtn/status/:referenceId', authMiddleware, async (req, res) => {
    try {
        if (!mtnIsConfigured())
            return res.json({ success: true, status: 'SIMULATED' });
        const data = await mtnCheckStatus(req.params.referenceId);
        res.json({ success: true, status: data.status, data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// PAIEMENTS — ORANGE MONEY (DÉPÔT)
// ================================================================
// Flux : différent de MTN — Orange utilise une page web dédiée.
// → Le backend crée une session de paiement → obtient une payment_url
// → Le frontend redirige l'utilisateur vers cette URL
// → L'utilisateur entre son PIN sur la page Orange
// → Orange appelle le webhook de confirmation
// → Le webhook crédite le solde.

app.post('/api/payment/orange/deposit', authMiddleware, async (req, res) => {
    try {
        const { amount, phone } = req.body;
        const numAmount = parseInt(amount);

        if (!numAmount || numAmount < 1000)
            return res.status(400).json({ success: false, message: 'Montant minimum: 1 000 XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Orange invalide (min 9 chiffres)' });

        // ── MODE SIMULATION ────────────────────────────────────
        if (!orangeIsConfigured()) {
            console.warn('[Orange] ⚠️  Clés non configurées — simulation active');
            await db.updateBalance(req.userId, numAmount);
            await db.addTransaction(req.userId, 'deposit', numAmount, {
                operator: 'orange', phone,
                description: `[SIMULATION] Dépôt Orange ${numAmount} XAF — ajouter ORANGE_CLIENT_ID dans Render`
            });
            const p = await db.getPortfolio(req.userId);
            return res.json({ success: true, simulated: true, message: `✅ [TEST] ${numAmount.toLocaleString('fr-FR')} XAF déposés (simulation Orange)`, newBalance: parseInt(p.balance) });
        }
        // ────────────────────────────────────────────────────────

        // ── VRAI PAIEMENT ORANGE ────────────────────────────────
        const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2,4).toUpperCase();

        await db.addTransaction(req.userId, 'deposit', numAmount, {
            operator: 'orange', phone, reference: orderId,
            description: `⏳ Dépôt Orange en attente — ${numAmount} XAF`
        });
        await db.query(
            `INSERT INTO pending_payments (reference_id, user_id, amount, operator, created_at)
             VALUES ($1, $2, $3, 'orange', CURRENT_TIMESTAMP) ON CONFLICT (reference_id) DO NOTHING`,
            [orderId, req.userId, numAmount]
        );

        const { paymentUrl } = await orangeCreatePayment({ amount: numAmount, phone, orderId, userId: req.userId });
        console.log(`[Orange] Session créée — orderId:${orderId} user:${req.userId} ${numAmount} XAF`);

        // Orange nécessite une redirection → on renvoie l'URL au frontend
        res.json({
            success: true, pending: true, orderId, paymentUrl,
            message: `🟠 Redirection vers Orange Money pour ${numAmount.toLocaleString('fr-FR')} XAF`
        });
        // ────────────────────────────────────────────────────────
    } catch (err) {
        console.error('[Orange] Deposit error:', err);
        res.status(500).json({ success: false, message: `Erreur Orange: ${err.message}` });
    }
});

// ── ORANGE — WEBHOOK ────────────────────────────────────────────
// Orange appelle automatiquement cette URL après confirmation/refus.
//
// ✏️  À configurer dans developer.orange.com → ton app → notif_url :
//     https://TON-SERVICE.onrender.com/api/payment/orange/callback
//     (et aussi dans ORANGE_NOTIF_URL dans Render)
//
app.post('/api/payment/orange/callback', async (req, res) => {
    try {
        const { order_id, status, txnid, message: msg } = req.body;
        console.log(`[Orange Callback] orderId:${order_id} status:${status}`);

        res.status(200).json({ received: true }); // Toujours 200 en premier

        if (!order_id) return;

        if (status === 'SUCCESS' || status === 'SUCCESSFULL') {
            const pending = await db.query(
                'SELECT * FROM pending_payments WHERE reference_id = $1 AND paid = FALSE',
                [order_id]
            );
            if (pending.length > 0) {
                const { user_id, amount } = pending[0];
                await db.query(
                    'UPDATE pending_payments SET paid = TRUE, paid_at = CURRENT_TIMESTAMP WHERE reference_id = $1',
                    [order_id]
                );
                await db.updateBalance(user_id, parseInt(amount));
                await db.query(
                    `UPDATE transactions SET description = $1 WHERE reference = $2`,
                    [`✅ Dépôt Orange confirmé — ${parseInt(amount).toLocaleString('fr-FR')} XAF`, order_id]
                );
                console.log(`[Orange Callback] ✅ Crédité — user:${user_id} +${amount} XAF txn:${txnid}`);
            }
        } else {
            await db.query('DELETE FROM pending_payments WHERE reference_id = $1', [order_id]);
            await db.query(
                `UPDATE transactions SET description = $1 WHERE reference = $2`,
                [`❌ Dépôt Orange échoué — ${msg || 'paiement refusé'}`, order_id]
            );
            console.log(`[Orange Callback] ❌ Échoué — orderId:${order_id}`);
        }
    } catch (err) {
        console.error('[Orange Callback] Erreur:', err);
    }
});

// ── ROUTE GÉNÉRIQUE (compatibilité frontend) ───────────────────
// L'ancien frontend appelle /api/payment/deposit avec operator dans le body.
app.post('/api/payment/deposit', authMiddleware, (req, res) => {
    const op = (req.body.operator || 'mtn').toLowerCase();
    if (op === 'orange') return app._router.handle(
        Object.assign(req, { url: '/api/payment/orange/deposit', path: '/api/payment/orange/deposit' }), res, () => {}
    );
    return app._router.handle(
        Object.assign(req, { url: '/api/payment/mtn/deposit', path: '/api/payment/mtn/deposit' }), res, () => {}
    );
});

// ================================================================
// PAIEMENTS — RETRAIT (1 par jour · minimum 1 500 XAF · frais 1%)
// ================================================================
// Règle métier : le retrait n'est autorisé que si l'utilisateur
// possède au moins un investissement actif (machine achetée).
// Cela garantit que seuls les vrais investisseurs peuvent retirer.
// ================================================================
app.post('/api/payment/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, phone, operator } = req.body;
        const numAmount = parseInt(amount);

        if (!numAmount || numAmount < 1500)
            return res.status(400).json({ success: false, message: 'Montant minimum de retrait : 1 500 XAF' });
        if (!phone || String(phone).replace(/\s/g,'').length < 9)
            return res.status(400).json({ success: false, message: 'Numéro Mobile Money invalide' });

        // ── VÉRIFICATION INVESTISSEMENT ACTIF ──────────────────
        // L'utilisateur doit posséder au moins une machine active
        // pour pouvoir effectuer un retrait.
        const activeInvestments = await db.query(
            `SELECT id FROM investments WHERE user_id = $1 AND status = 'active' LIMIT 1`,
            [req.userId]
        );
        if (activeInvestments.length === 0) {
            return res.status(403).json({
                success: false,
                message: '⛔ Retrait impossible. Vous devez d\'abord acheter une machine (investissement actif) avant de pouvoir retirer vos gains.'
            });
        }
        // ────────────────────────────────────────────────────────

        const alreadyWithdrawn = await db.query(
            `SELECT id FROM transactions WHERE user_id = $1 AND type = 'withdrawal' AND created_at::date = CURRENT_DATE`,
            [req.userId]
        );
        if (alreadyWithdrawn.length > 0)
            return res.status(400).json({ success: false, message: '⛔ Un seul retrait autorisé par jour. Revenez demain.' });

        const portfolio = await db.getPortfolio(req.userId);
        if (!portfolio || parseInt(portfolio.balance) < numAmount)
            return res.status(400).json({ success: false, message: 'Solde insuffisant' });

        const fee       = Math.round(numAmount * 0.01);
        const netAmount = numAmount - fee;

        await db.updateBalance(req.userId, numAmount, 'subtract');
        await db.addTransaction(req.userId, 'withdrawal', numAmount, {
            fee, netAmount, operator: operator || 'mtn', phone,
            description: `Retrait via ${(operator || 'mtn').toUpperCase()} Money — ${netAmount.toLocaleString('fr-FR')} XAF nets`
        });

        res.json({
            success: true,
            message: `✅ ${netAmount.toLocaleString('fr-FR')} XAF en cours d'envoi (frais: ${fee} XAF)`,
            netAmount, fee, newBalance: parseInt(portfolio.balance) - numAmount
        });
    } catch (err) {
        console.error('Withdraw error:', err);
        res.status(500).json({ success: false, message: 'Erreur lors du retrait' });
    }
});

// ================================================================
// BONUS JOURNALIER (100 XAF / jour, réclamation manuelle)
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
        const level1    = await db.query('SELECT id, name, email FROM users WHERE referred_by = $1', [req.userId]);
        const l1Ids     = level1.map(u => u.id);
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
            success: true, referralCode: user?.referral_code,
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
                (SELECT COUNT(*) FROM users)::int                             AS "totalUsers",
                (SELECT COUNT(*) FROM investments WHERE status='active')::int AS "totalInvestments",
                (SELECT COUNT(*) FROM transactions)::int                      AS "totalTransactions",
                (SELECT COALESCE(SUM(balance),0) FROM portfolios)::bigint     AS "totalBalance"
        `);
        res.json({
            success: true, users,
            portfolios: portfolios.map(p => ({
                userId: p.user_id, balance: parseInt(p.balance||0),
                totalInvested: parseInt(p.total_invested||0),
                referralEarnings: parseInt(p.referral_earnings||0),
                totalGains: parseInt(p.total_gains||0)
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
            success: true, status: 'online',
            users:   parseInt(r[0].cnt),
            mtn:     mtnIsConfigured()    ? 'actif'      : 'simulation',
            orange:  orangeIsConfigured() ? 'actif'      : 'simulation',
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ success: false, status: 'db_error', message: err.message });
    }
});

// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ================================================================
// CRONS AUTOMATIQUES
// ================================================================
function startKeepalive() {
    const SELF_URL = process.env.RENDER_EXTERNAL_URL
        ? `${process.env.RENDER_EXTERNAL_URL}/api/health`
        : `http://localhost:${PORT}/api/health`;
    setInterval(() => {
        try {
            const http = SELF_URL.startsWith('https') ? require('https') : require('http');
            http.get(SELF_URL, r => console.log(`[Keepalive] ${r.statusCode} — ${new Date().toLocaleTimeString('fr-FR')}`))
                .on('error', e => console.warn('[Keepalive] Ping failed:', e.message));
        } catch (e) { console.warn('[Keepalive] Error:', e.message); }
    }, 14 * 60 * 1000);
    console.log('✅ [Keepalive] Ping toutes les 14 minutes');
}

function startDailyGainsCron() {
    async function distributeAllUsersGains() {
        console.log('[Gains CRON] ⏰ Distribution journalière démarrée...');
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
        return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()+1, 0, 0, 30)) - now;
    }
    const delay = msUntilMidnightUTC();
    console.log(`✅ [Gains CRON] Prochaine distribution dans ${Math.round(delay/1000/60)} min (minuit UTC)`);
    setTimeout(() => {
        distributeAllUsersGains();
        setInterval(distributeAllUsersGains, 24 * 60 * 60 * 1000);
    }, delay);
}

function startCleanupCron() {
    setInterval(async () => {
        try {
            await db.query("DELETE FROM transactions WHERE created_at < NOW() - INTERVAL '365 days'");
            await db.query("DELETE FROM pending_payments WHERE paid = FALSE AND created_at < NOW() - INTERVAL '24 hours'");
        } catch (e) { /* silencieux */ }
    }, 24 * 60 * 60 * 1000);
}

// ================================================================
// COMPTES PAR DÉFAUT
// ================================================================
async function createDefaultAccounts() {
    const admin = await db.getUserByEmail('admin@nextera.com');
    if (!admin) {
        const id = 'user_admin', hash = await bcrypt.hash('admin123', 10);
        await db.query('INSERT INTO users (id,name,email,phone,password,is_admin,referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id,'Administrateur','admin@nextera.com','699999999',hash,true,'NEXT-ADMIN001']);
        await db.query('INSERT INTO portfolios (user_id,balance,total_invested,referral_earnings,total_gains) VALUES ($1,500000,0,0,0) ON CONFLICT (user_id) DO NOTHING', [id]);
        console.log('✅ Compte admin: admin@nextera.com / admin123');
    }
    const test = await db.getUserByEmail('test@nextera.com');
    if (!test) {
        const id = 'user_test', hash = await bcrypt.hash('test123', 10);
        await db.query('INSERT INTO users (id,name,email,phone,password,is_admin,referral_code) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
            [id,'Jean Dupont','test@nextera.com','690000000',hash,false,'NEXT-TEST001']);
        await db.query('INSERT INTO portfolios (user_id,balance,total_invested,referral_earnings,total_gains) VALUES ($1,25000,0,0,0) ON CONFLICT (user_id) DO NOTHING', [id]);
        console.log('✅ Compte test: test@nextera.com / test123');
    }
}

// ================================================================
// DÉMARRAGE
// ================================================================
app.listen(PORT, async () => {
    const connected = await db.testConnection();
    if (!connected) { console.error('❌ PostgreSQL inaccessible. Vérifier DATABASE_URL dans Render.'); process.exit(1); }
    await db.initTables();
    await createDefaultAccounts();
    startKeepalive();
    startDailyGainsCron();
    startCleanupCron();

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🌿 NextEra — Port ${String(PORT).padEnd(42)}║
║  📊 Health   : /api/health                                   ║
║  🔑 Admin    : admin@nextera.com / admin123                  ║
║  🧪 Test     : test@nextera.com  / test123                   ║
║  🎁 Bonus    : 1 000 XAF offerts à chaque inscription        ║
║                                                              ║
║  MTN MoMo   : ${mtnIsConfigured()    ? '✅ ACTIF (argent réel)              ' : '⚠️  SIMULATION (MTN_PRIMARY_KEY manquant)  '}║
║  Orange     : ${orangeIsConfigured() ? '✅ ACTIF (argent réel)              ' : '⚠️  SIMULATION (ORANGE_CLIENT_ID manquant) '}║
╚══════════════════════════════════════════════════════════════╝`);
});
