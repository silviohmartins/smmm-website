require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const axios = require('axios');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Configuração do Pool de Conexão com o Postgres
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Middlewares
app.use(express.urlencoded({ extended: true })); // Para ler dados de formulários
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } // Usar 'true' em produção com HTTPS
}));

// Middleware para proteger rotas
const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/admin/login');
    }
    next();
};

// --- Rotas ---

// Rota para a página de login (GET)
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Rota para processar o login (POST)
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM administrators WHERE username = $1', [username]);
        const user = result.rows[0];

        if (user && await bcrypt.compare(password, user.password_hash)) {
            req.session.userId = user.id; // Login bem-sucedido
            res.redirect('/admin');
        } else {
            res.send('Usuário ou senha inválidos.'); // Falha no login
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor');
    }
});

// Rota principal da área de admin (protegida)
app.get('/admin', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Rota de Logout
app.post('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/admin');
        }
        res.clearCookie('connect.sid');
        res.redirect('/admin/login');
    });
});

// --- API para interagir com o n8n ---

// Rota para ativar/desativar workflow (protegida)
app.post('/api/n8n/workflows/:id/toggle', requireLogin, async (req, res) => {
    const { id } = req.params;
    const { active } = req.body; // 'active' deve ser true ou false

    try {
        const url = `${process.env.N8N_WEBHOOK_BASE_URL}/${id}/${active ? 'activate' : 'deactivate'}`;
        await axios.post(url, {}, {
            headers: { 'Authorization': process.env.N8N_API_KEY }
        });
        res.json({ success: true, message: `Workflow ${id} foi ${active ? 'ativado' : 'desativado'}.` });
    } catch (error) {
        console.error('Erro ao comunicar com n8n:', error.response?.data || error.message);
        res.status(500).json({ success: false, message: 'Falha ao comunicar com a API do n8n.' });
    }
});

app.listen(port, () => {
    console.log(`Servidor de admin rodando na porta ${port}`);
});