const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const sesiones = new Map();
const seccionesPermitidas = new Set(['productos', 'clientes', 'usuarios']);
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const getTiDBAuthHeader = () => {
    const credentials = `${process.env.TIDB_PUBLIC_KEY}:${process.env.TIDB_PRIVATE_KEY}`;
    return `Basic ${Buffer.from(credentials).toString('base64')}`;
};

const fetchTiDB = async (endpointTiDB, method = 'GET', body = null) => {
    const url = `${process.env.TIDB_ENDPOINT_URL}/${endpointTiDB}`;
    console.log("URL de TiDB solicitada:", url, "Método:", method);
    
    const options = {
        method,
        headers: {
            'Authorization': getTiDBAuthHeader(),
            'Content-Type': 'application/json'
        }
    };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(url, options);
    
    if (!response.ok) {
        const errorText = await response.text(); 
        console.error("ERROR HTTP:", errorText);
        throw new Error(`Error HTTP: ${errorText}`);
    }
    
    const json = await response.json();
    
    if (json.data && json.data.result && json.data.result.code && json.data.result.code !== 200) {
        console.error("ERROR SQL TiDB:", json.data.result.message);
        throw new Error(json.data.result.message);
    }

    return json;
};

const normalizarRol = rol => String(rol || '').trim().toLowerCase();

const autenticar = (req, res, next) => {
    if (req.path === '/login') return next();

    const token = req.get('Authorization')?.replace(/^Bearer\s+/i, '');
    const usuario = token ? sesiones.get(token) : null;
    if (!usuario) {
        return res.status(401).json({ error: 'Sesión no válida o expirada' });
    }

    req.usuario = usuario;
    next();
};

const autorizarSeccion = (req, res, next) => {
    const seccion = req.params.seccion;
    if (!seccionesPermitidas.has(seccion)) {
        return res.status(404).json({ error: 'Endpoint no válido' });
    }

    const rol = normalizarRol(req.usuario.rol);
    const esLectura = req.method === 'GET';
    const puedeLeer = ['auditor', 'capturista', 'admin', 'administrador'].includes(rol);
    const puedeModificar = ['capturista', 'admin', 'administrador'].includes(rol);

    if ((esLectura && !puedeLeer) || (!esLectura && !puedeModificar)) {
        return res.status(403).json({ error: 'No tienes permisos para esta operación' });
    }

    next();
};

app.use('/api', autenticar);

app.get('/api/:seccion', autorizarSeccion, async (req, res) => {
    try {
        const tidbEndpoint = req.params.seccion;

        const data = await fetchTiDB(`${tidbEndpoint}`);
        res.json(data.data.rows || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const normalizarNombre = valor => String(valor || '')
            .normalize('NFKC')
            .replace(/\s+/g, ' ')
            .trim()
            .toLocaleLowerCase('es-MX');
        const nombre = normalizarNombre(req.body.nombre);
        const contrasena = String(req.body.contrasena || '');

        if (!nombre || !contrasena) {
            return res.status(400).json({ error: 'Nombre y contraseña son obligatorios' });
        }

        const data = await fetchTiDB('usuarios');
        const usuario = (data.data.rows || []).find(row =>
            normalizarNombre(row.nombre) === nombre &&
            String(row.contrasena || '') === contrasena
        );

        if (!usuario) {
            return res.status(401).json({ error: 'Nombre o contraseña incorrectos' });
        }

        const token = crypto.randomUUID();
        sesiones.set(token, {
            id_usuario: usuario.id_usuario,
            nombre: usuario.nombre,
            rol: usuario.rol
        });

        res.json({
            token,
            id_usuario: usuario.id_usuario,
            nombre: usuario.nombre,
            rol: usuario.rol
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/:seccion', autorizarSeccion, async (req, res) => {
    try {
        const tidbEndpoint = req.params.seccion;
        const data = await fetchTiDB(`${tidbEndpoint}`, 'POST', req.body);
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/:seccion/:id', autorizarSeccion, async (req, res) => {
    try {
        const tidbEndpoint = req.params.seccion;
        let idName = 'id_' + tidbEndpoint.slice(0, -1);
        req.body[idName] = Number(req.params.id);

        console.log('[PUT] Datos recibidos desde el navegador:', {
            url: `/api/${tidbEndpoint}/${req.params.id}`,
            body: req.body
        });
        
        const data = await fetchTiDB(`${tidbEndpoint}`, 'PUT', req.body);
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/:seccion/:id', autorizarSeccion, async (req, res) => {
    try {
        const tidbEndpoint = req.params.seccion;
        let idName = 'id_' + tidbEndpoint.slice(0, -1);

        console.log('[DELETE] Datos recibidos desde el navegador:', {
            url: `/api/${tidbEndpoint}/${req.params.id}`,
            filtro: `${idName}=${req.params.id}`
        });
        
        const data = await fetchTiDB(`${tidbEndpoint}?${idName}=${encodeURIComponent(req.params.id)}`, 'DELETE');
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`App corriendo en http://localhost:${PORT}`);
    });
}

module.exports = app;