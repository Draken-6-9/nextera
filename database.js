// database.js — PostgreSQL (Render)
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000
});

async function testConnection() {
    try {
        const client = await pool.connect();
        await client.query('SELECT 1');
        client.release();
        console.log('✅ PostgreSQL connecté avec succès !');
        return true;
    } catch (error) {
        console.error('❌ Erreur de connexion PostgreSQL:', error.message);
        return false;
    }
}

// ============================================================
// COUCHE REQUÊTE — convertit MySQL → PostgreSQL automatiquement
// ============================================================
async function query(sql, params = []) {
    try {
        let pgSql = sql;
        let paramIndex = 1;
        pgSql = pgSql.replace(/\?/g, () => `$${paramIndex++}`);
        pgSql = pgSql.replace(/CURDATE\(\)/g, 'CURRENT_DATE');
        pgSql = pgSql.replace(/NOW\(\)/g, 'CURRENT_TIMESTAMP');
        // MySQL "active" string comparison
        pgSql = pgSql.replace(/"active"/g, `'active'`);

        const result = await pool.query(pgSql, params);
        return result.rows;
    } catch (error) {
        console.error('SQL Error:', error.message);
        console.error('Query:', sql);
        console.error('Params:', params);
        throw error;
    }
}

// ============================================================
// UTILISATEURS
// ============================================================
async function getUserByEmail(email) {
    const rows = await query('SELECT * FROM users WHERE email = $1', [email]);
    return rows[0] || null;
}

async function getUserById(userId) {
    const rows = await query('SELECT * FROM users WHERE id = $1', [userId]);
    return rows[0] || null;
}

async function createUser(user) {
    const { id, name, email, phone, password, referralCode, referredBy } = user;
    await query(
        'INSERT INTO users (id, name, email, phone, password, referral_code, referred_by) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [id, name, email, phone, password, referralCode, referredBy || null]
    );
    await query(
        'INSERT INTO portfolios (user_id, balance, total_invested, referral_earnings, total_gains) VALUES ($1, 0, 0, 0, 0)',
        [id]
    );
    return { id, name, email, phone, referralCode };
}

// ============================================================
// PORTEFEUILLES
// ============================================================
async function getPortfolio(userId) {
    const rows = await query('SELECT * FROM portfolios WHERE user_id = $1', [userId]);
    return rows[0] || null;
}

async function updateBalance(userId, amount, operation = 'add') {
    if (operation === 'add') {
        await query('UPDATE portfolios SET balance = balance + $1 WHERE user_id = $2', [amount, userId]);
    } else {
        await query('UPDATE portfolios SET balance = balance - $1 WHERE user_id = $2', [amount, userId]);
    }
}

// ============================================================
// TRANSACTIONS
// ============================================================
async function addTransaction(userId, type, amount, options = {}) {
    const { fee = 0, netAmount = null, operator = null, phone = null, description = null, reference = null } = options;
    const id = 'tx_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
    await query(
        `INSERT INTO transactions (id, user_id, type, amount, fee, net_amount, operator, phone, description, reference, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)`,
        [id, userId, type, amount, fee, netAmount, operator, phone, description, reference]
    );
    return id;
}

// ============================================================
// MACHINES
// ============================================================
async function getMachines() {
    return await query('SELECT * FROM machines WHERE is_active = true ORDER BY price ASC');
}

// ============================================================
// INVESTISSEMENTS
// ============================================================
async function getUserInvestments(userId) {
    return await query(
        "SELECT * FROM investments WHERE user_id = $1 AND status = 'active' ORDER BY created_at DESC",
        [userId]
    );
}

async function createInvestment(investment) {
    const { id, userId, machineId, machineName, machineIcon, amount, dailyYield } = investment;
    await query(
        "INSERT INTO investments (id, user_id, machine_id, machine_name, machine_icon, amount, daily_yield, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', CURRENT_TIMESTAMP)",
        [id, userId, machineId, machineName, machineIcon, amount, dailyYield]
    );
    return investment;
}

// ============================================================
// BONUS JOURNALIER
// ============================================================
async function hasClaimedBonusToday(userId) {
    const rows = await query(
        'SELECT * FROM daily_bonus WHERE user_id = $1 AND last_claim_date = CURRENT_DATE',
        [userId]
    );
    return rows.length > 0;
}

async function claimBonus(userId, amount) {
    await query(
        'INSERT INTO daily_bonus (user_id, last_claim_date) VALUES ($1, CURRENT_DATE) ON CONFLICT (user_id) DO UPDATE SET last_claim_date = CURRENT_DATE',
        [userId]
    );
    await updateBalance(userId, amount);
    await addTransaction(userId, 'bonus', amount, { description: 'Bonus journalier 100 XAF' });
}

// ============================================================
// GAINS JOURNALIERS
// ============================================================
async function applyDailyGains(userId) {
    const investments = await getUserInvestments(userId);
    let totalGain = 0;

    for (const inv of investments) {
        const rows = await query(
            'SELECT id FROM investments WHERE id = $1 AND (last_gain_date IS NULL OR last_gain_date != CURRENT_DATE)',
            [inv.id]
        );

        if (rows.length > 0) {
            const gain = Math.round(inv.amount * (inv.daily_yield / 100));
            totalGain += gain;
            await query(
                'UPDATE investments SET last_gain_date = CURRENT_DATE, total_gains_received = COALESCE(total_gains_received, 0) + $1 WHERE id = $2',
                [gain, inv.id]
            );
        }
    }

    if (totalGain > 0) {
        await updateBalance(userId, totalGain);
        await addTransaction(userId, 'gain', totalGain, { description: `Gains journaliers (${totalGain} XAF)` });
        await query('UPDATE portfolios SET total_gains = COALESCE(total_gains, 0) + $1 WHERE user_id = $2', [totalGain, userId]);
    }

    return totalGain;
}

// ============================================================
// INIT DES TABLES (auto au démarrage)
// ============================================================
async function initTables() {
    // Users
    await query(`
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(60) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            phone VARCHAR(20) NOT NULL,
            password VARCHAR(255) NOT NULL,
            referral_code VARCHAR(30) UNIQUE,
            referred_by VARCHAR(60),
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Portfolios
    await query(`
        CREATE TABLE IF NOT EXISTS portfolios (
            user_id VARCHAR(60) PRIMARY KEY,
            balance BIGINT DEFAULT 0,
            total_invested BIGINT DEFAULT 0,
            referral_earnings BIGINT DEFAULT 0,
            total_gains BIGINT DEFAULT 0
        )
    `);

    // Transactions
    await query(`
        CREATE TABLE IF NOT EXISTS transactions (
            id VARCHAR(60) PRIMARY KEY,
            user_id VARCHAR(60) NOT NULL,
            type VARCHAR(20) NOT NULL,
            amount BIGINT NOT NULL,
            fee BIGINT DEFAULT 0,
            net_amount BIGINT,
            operator VARCHAR(20),
            phone VARCHAR(20),
            description TEXT,
            reference VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Investments
    await query(`
        CREATE TABLE IF NOT EXISTS investments (
            id VARCHAR(60) PRIMARY KEY,
            user_id VARCHAR(60) NOT NULL,
            machine_id VARCHAR(20) NOT NULL,
            machine_name VARCHAR(100) NOT NULL,
            machine_icon VARCHAR(10),
            amount BIGINT NOT NULL,
            daily_yield INTEGER DEFAULT 20,
            status VARCHAR(20) DEFAULT 'active',
            last_gain_date DATE,
            total_gains_received BIGINT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Daily Bonus
    await query(`
        CREATE TABLE IF NOT EXISTS daily_bonus (
            user_id VARCHAR(60) PRIMARY KEY,
            last_claim_date DATE
        )
    `);

    // Machines
    await query(`
        CREATE TABLE IF NOT EXISTS machines (
            id VARCHAR(20) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            icon VARCHAR(10) DEFAULT '⚡',
            price BIGINT NOT NULL,
            daily_yield INTEGER DEFAULT 20,
            description TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            filled INTEGER DEFAULT 0
        )
    `);

    // Insérer les machines par défaut si vides
    const existing = await query('SELECT COUNT(*) as cnt FROM machines');
    if (parseInt(existing[0].cnt) === 0) {
        const defaultMachines = [
            ['m1', 'Machine Éco+',     '⚡',  5000,  20, '1 000 XAF/jour'],
            ['m2', 'Machine Pro',      '🔋', 10000,  20, '2 000 XAF/jour'],
            ['m3', 'Machine Business', '💎', 20000,  20, '4 000 XAF/jour'],
            ['m4', 'Machine Elite',    '👑', 50000,  20, '10 000 XAF/jour'],
            ['m5', 'Machine Ultimate', '🚀',100000,  20, '20 000 XAF/jour']
        ];
        for (const [id, name, icon, price, daily_yield, description] of defaultMachines) {
            await query(
                'INSERT INTO machines (id, name, icon, price, daily_yield, description) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING',
                [id, name, icon, price, daily_yield, description]
            );
        }
        console.log('✅ Machines par défaut insérées');
    }

    // Table pending_payments
    // Stocke les paiements en attente entre l'initiation et la confirmation webhook.
    // Empêche le double-crédit si le webhook est appelé deux fois par MTN/Orange.
    await query(`
        CREATE TABLE IF NOT EXISTS pending_payments (
            reference_id VARCHAR(100) PRIMARY KEY,
            user_id      VARCHAR(60)  NOT NULL,
            amount       BIGINT       NOT NULL,
            operator     VARCHAR(20)  DEFAULT 'mtn',
            paid         BOOLEAN      DEFAULT FALSE,
            paid_at      TIMESTAMP,
            created_at   TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
        )
    `);
    console.log('✅ Toutes les tables sont prêtes (PostgreSQL)');
}

module.exports = {
    pool,
    testConnection,
    initTables,
    query,
    getUserByEmail,
    getUserById,
    getPortfolio,
    createUser,
    updateBalance,
    addTransaction,
    getMachines,
    getUserInvestments,
    createInvestment,
    hasClaimedBonusToday,
    claimBonus,
    applyDailyGains
};
