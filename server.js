// ========================================
// BACKEND API - MIKROTIK VPN SAAS
// Node.js + Express + PostgreSQL
// ========================================

// package.json
/*
{
  "name": "mikrotik-vpn-api",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node server.js",
    "dev": "node --watch server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "axios": "^1.6.5"
  }
}
*/

// .env (À CRÉER sur Render.com)
/*
DATABASE_URL=postgresql://postgres:[PASSWORD]@[HOST]:5432/postgres
JWT_SECRET=votre_secret_jwt_ultra_secure_ici
TAILSCALE_API_KEY=votre_cle_api_tailscale
STRIPE_SECRET_KEY=votre_cle_stripe_secrete
PORT=3000
NODE_ENV=production
*/

// ========================================
// server.js - SERVEUR PRINCIPAL
// ========================================

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import axios from 'axios';

dotenv.config();

const app = express();
const { Pool } = pg;

// Configuration base de données
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middlewares de sécurité
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // 100 requêtes max
});
app.use('/api/', limiter);

// ========================================
// MIDDLEWARE D'AUTHENTIFICATION
// ========================================

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Token manquant' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const client = await pool.query(
      'SELECT id, email, forfait FROM clients WHERE id = $1',
      [decoded.userId]
    );

    if (client.rows.length === 0) {
      return res.status(401).json({ error: 'Utilisateur non trouvé' });
    }

    req.user = client.rows[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// ========================================
// ROUTES AUTHENTIFICATION
// ========================================

// Inscription
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, nom, prenom, entreprise } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    // Vérifier si l'email existe
    const existing = await pool.query(
      'SELECT id FROM clients WHERE email = $1',
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email déjà utilisé' });
    }

    // Hash du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Créer le client
    const result = await pool.query(
      `INSERT INTO clients (email, password_hash, nom, prenom, entreprise, forfait)
       VALUES ($1, $2, $3, $4, $5, 'basic')
       RETURNING id, email, nom, prenom, forfait, created_at`,
      [email, hashedPassword, nom, prenom, entreprise]
    );

    const newClient = result.rows[0];

    // Créer organisation Tailscale
    try {
      const tailscaleOrg = await createTailscaleOrg(email);
      await pool.query(
        'UPDATE clients SET tailscale_org_id = $1 WHERE id = $2',
        [tailscaleOrg.id, newClient.id]
      );
    } catch (error) {
      console.error('Erreur Tailscale:', error);
    }

    // Générer token JWT
    const token = jwt.sign(
      { userId: newClient.id },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      message: 'Compte créé avec succès',
      token,
      user: {
        id: newClient.id,
        email: newClient.email,
        nom: newClient.nom,
        prenom: newClient.prenom,
        forfait: newClient.forfait
      }
    });

  } catch (error) {
    console.error('Erreur inscription:', error);
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT id, email, password_hash, nom, prenom, forfait FROM clients WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const client = result.rows[0];
    const validPassword = await bcrypt.compare(password, client.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const token = jwt.sign(
      { userId: client.id },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: client.id,
        email: client.email,
        nom: client.nom,
        prenom: client.prenom,
        forfait: client.forfait
      }
    });

  } catch (error) {
    console.error('Erreur connexion:', error);
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

// ========================================
// ROUTES ROUTEURS MIKROTIK
// ========================================

// Liste des routeurs du client
app.get('/api/routeurs', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, nom, description, modele, version_routeros, 
              ip_locale, ip_publique, tailscale_ip, statut, 
              last_ping, created_at
       FROM routeurs 
       WHERE client_id = $1 
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({ routeurs: result.rows });

  } catch (error) {
    console.error('Erreur liste routeurs:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des routeurs' });
  }
});

// Ajouter un routeur
app.post('/api/routeurs', authMiddleware, async (req, res) => {
  try {
    const { nom, description, modele, ip_locale } = req.body;

    // Vérifier limite selon forfait
    const count = await pool.query(
      'SELECT COUNT(*) FROM routeurs WHERE client_id = $1',
      [req.user.id]
    );

    const limits = { basic: 1, pro: 3, business: 999 };
    const limit = limits[req.user.forfait] || 1;

    if (parseInt(count.rows[0].count) >= limit) {
      return res.status(403).json({ 
        error: `Limite de ${limit} routeur(s) atteinte pour votre forfait ${req.user.forfait}` 
      });
    }

    // Créer le routeur
    const result = await pool.query(
      `INSERT INTO routeurs (client_id, nom, description, modele, ip_locale)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [req.user.id, nom, description, modele, ip_locale]
    );

    // Log activité
    await pool.query(
      `INSERT INTO logs_activite (client_id, routeur_id, type, message)
       VALUES ($1, $2, 'configuration', 'Nouveau routeur ajouté')`,
      [req.user.id, result.rows[0].id]
    );

    res.status(201).json({
      message: 'Routeur ajouté avec succès',
      routeur: result.rows[0]
    });

  } catch (error) {
    console.error('Erreur ajout routeur:', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout du routeur' });
  }
});

// Supprimer un routeur
app.delete('/api/routeurs/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Vérifier que le routeur appartient au client
    const check = await pool.query(
      'SELECT id FROM routeurs WHERE id = $1 AND client_id = $2',
      [id, req.user.id]
    );

    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Routeur non trouvé' });
    }

    await pool.query('DELETE FROM routeurs WHERE id = $1', [id]);

    res.json({ message: 'Routeur supprimé avec succès' });

  } catch (error) {
    console.error('Erreur suppression routeur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression' });
  }
});

// ========================================
// ROUTES DASHBOARD & STATISTIQUES
// ========================================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  try {
    const [routeurs, logs] = await Promise.all([
      pool.query(
        `SELECT COUNT(*) as total,
                COUNT(CASE WHEN statut = 'online' THEN 1 END) as online,
                COUNT(CASE WHEN statut = 'offline' THEN 1 END) as offline
         FROM routeurs WHERE client_id = $1`,
        [req.user.id]
      ),
      pool.query(
        `SELECT type, COUNT(*) as count
         FROM logs_activite 
         WHERE client_id = $1 
         AND created_at > NOW() - INTERVAL '7 days'
         GROUP BY type`,
        [req.user.id]
      )
    ]);

    res.json({
      routeurs: {
        total: parseInt(routeurs.rows[0].total),
        online: parseInt(routeurs.rows[0].online),
        offline: parseInt(routeurs.rows[0].offline)
      },
      activites: logs.rows
    });

  } catch (error) {
    console.error('Erreur stats:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des stats' });
  }
});

// ========================================
// INTÉGRATION TAILSCALE
// ========================================

async function createTailscaleOrg(email) {
  try {
    const response = await axios.post(
      'https://api.tailscale.com/api/v2/tailnet',
      { name: email.split('@')[0] },
      {
        headers: {
          'Authorization': `Bearer ${process.env.TAILSCALE_API_KEY}`
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Erreur création org Tailscale:', error.response?.data);
    throw error;
  }
}

// ========================================
// WEBHOOK STRIPE (pour paiements)
// ========================================

app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    // TODO: Valider signature Stripe
    const event = req.body;

    switch (event.type) {
      case 'payment_intent.succeeded':
        // Enregistrer le paiement
        await pool.query(
          `INSERT INTO paiements (client_id, montant, stripe_payment_intent_id, statut)
           VALUES ($1, $2, $3, 'succeeded')`,
          [event.data.object.metadata.client_id, event.data.object.amount / 100, event.data.object.id]
        );
        break;

      case 'customer.subscription.deleted':
        // Désactiver l'abonnement
        await pool.query(
          `UPDATE clients SET statut = 'suspendu' 
           WHERE stripe_customer_id = $1`,
          [event.data.object.customer]
        );
        break;
    }

    res.json({ received: true });

  } catch (error) {
    console.error('Erreur webhook Stripe:', error);
    res.status(500).json({ error: 'Erreur webhook' });
  }
});

// ========================================
// ROUTE SANTÉ (Health Check)
// ========================================

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      database: 'connected'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      database: 'disconnected' 
    });
  }
});

// ========================================
// DÉMARRAGE SERVEUR
// ========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ API MikroTik VPN démarrée sur le port ${PORT}`);
  console.log(`📊 Base de données: ${process.env.DATABASE_URL ? 'Connectée' : 'Non configurée'}`);
  console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Configuré' : '⚠️ NON CONFIGURÉ'}`);
  console.log(`🌐 Tailscale: ${process.env.TAILSCALE_API_KEY ? 'Configuré' : '⚠️ NON CONFIGURÉ'}`);
});