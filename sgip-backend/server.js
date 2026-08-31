const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { enable } = require('express/lib/application');
const QRCode = require('qrcode');
const PDFDocument = require('pdfkit');
require('dotenv').config();

const app = express();
app.use(cors()); // pour que ton front puisse parler au back
app.use(express.json());

// Middleware : vérifie qu'un token JWT valide est fourni (header Authorization: Bearer <token>)
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token manquant.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Token invalide ou expiré.' });
    }
    req.user = decoded; // { id, matricule, role }
    next();
  });
}

// Middleware : à utiliser après verifyToken, bloque si le rôle n'est pas Admin
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'Admin') {
    return res.status(403).json({ success: false, message: 'Accès réservé aux administrateurs.' });
  }
  next();
}


const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    instanceName: process.env.DB_INSTANCE,
    encrypt: false, trustServerCertificate: true
  }
};

const poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(pool => {
    console.log('Connecté à SQL Server (sa) ✅');
    return pool;
  })
  .catch(err => console.error('❌ Échec de connexion SQL Server:', err));

// Route Register
app.post('/api/register', async (req, res) => {
  // On récupère "nom" envoyé par le formulaire HTML
  const { nom, email, mot_de_passe } = req.body;

  try {
    const pool = await sql.connect(dbConfig);

    // 1. Vérifier si l'email existe déjà
    const checkEmail = await pool.request()
      .input('email', sql.NVarChar, email)
      .query('SELECT Id FROM Utilisateurs WHERE Email = @email');

    if (checkEmail.recordset.length > 0) {
      return res.status(400).json({ success: false, message: 'Cet email est déjà utilisé !' });
    }

    // 2. Génération d'un matricule automatique (ex: USR4829)
    const matricule = 'USR' + Math.floor(1000 + Math.random() * 9000);

    // 3. Découper "Nom complet" (ex: "Cezar SANTINI" -> Nom: "SANTINI", Prénom: "Cezar")
    const partiesNom = (nom || 'Utilisateur').trim().split(' ');
    const prenomVal = partiesNom[0];
    const nomVal = partiesNom.slice(1).join(' ') || prenomVal;

    // 4. Insertion dans la table Utilisateurs
    await pool.request()
      .input('matricule', sql.NVarChar, matricule)
      .input('nom', sql.NVarChar, nomVal)
      .input('prenom', sql.NVarChar, prenomVal)
      .input('email', sql.NVarChar, email)
      .input('mot_de_passe', sql.NVarChar, mot_de_passe)
      .query(`
        INSERT INTO Utilisateurs (Matricule, Nom, Prenom, Email, MotDePasse, Role)
        VALUES (@matricule, @nom, @prenom, @email, @mot_de_passe, 'USER')
      `);

    res.json({ success: true, message: 'Inscription réussie !', matricule });
  } catch (err) {
    console.error("Erreur détaillée Inscription :", err);
    res.status(500).json({ success: false, message: 'Erreur lors de l\'inscription.' });
  }
});

// 2. ROUTE LOGIN UNIFIÉE (ADMIN + UTILISATEUR)
app.post('/api/login', async (req, res) => {
  const { email, mot_de_passe } = req.body;

  try {
    const pool = await sql.connect(dbConfig);

    // Recherche de l'utilisateur (Admin ou User normal)
    const result = await pool.request()
      .input('email', sql.NVarChar, email)
      .input('mot_de_passe', sql.NVarChar, mot_de_passe)
      .query(`
        SELECT Id, Matricule, Nom, Prenom, Email, Role 
        FROM Utilisateurs 
        WHERE Email = @email AND MotDePasse = @mot_de_passe AND EstActif = 1
      `);

    if (result.recordset.length > 0) {
      const user = result.recordset[0];

      // On retourne les infos de l'utilisateur ainsi que son Rôle et son Matricule !
      res.json({
        success: true,
        user: {
          id: user.Id,
          matricule: user.Matricule,
          nom: user.Nom,
          prenom: user.Prenom,
          email: user.Email,
          role: user.Role
        }
      });
    } else {
      res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
    }
  } catch (err) {
    console.error("Erreur Connexion :", err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    // Vérification des données
    if (!email || !newPassword) {
      return res.status(400).json({
        message: "L'email et le nouveau mot de passe sont obligatoires."
      });
    }

    // Connexion à SQL Server
    const pool = await sql.connect(dbConfig);

    // Vérifier si l'utilisateur existe
    const utilisateur = await pool.request()
      .input("Email", sql.NVarChar(150), email)
      .query(`
                SELECT Id
                FROM Utilisateurs
                WHERE Email = @Email
            `);

    if (utilisateur.recordset.length === 0) {
      return res.status(404).json({
        message: "Aucun utilisateur ne possède cet email."
      });
    }

    // Modifier le mot de passe
    await pool.request()
      .input("Email", sql.NVarChar(150), email)
      .input("MotDePasse", sql.NVarChar(255), newPassword)
      .query(`
                UPDATE Utilisateurs
                SET MotDePasse = @MotDePasse
                WHERE Email = @Email
            `);

    res.status(200).json({
      message: "Mot de passe réinitialisé avec succès."
    });

  } catch (error) {
    console.error("Erreur réinitialisation :", error);

    res.status(500).json({
      message: "Une erreur est survenue lors de la réinitialisation."
    });
  }
});

// Route : Création d'une nouvelle session de présence
app.post('/api/sessions/create', async (req, res) => {
  const { titre, responsable } = req.body;

  if (!titre) {
    return res.status(400).json({ success: false, message: 'Le titre est obligatoire.' });
  }

  try {
    const pool = await sql.connect(dbConfig);

    // 2. Créer directement la nouvelle session active
    const result = await pool.request()
      .input('titre', sql.NVarChar, titre)
      .input('responsable', sql.NVarChar, responsable || 'Admin')
      .query(`
        INSERT INTO Sessions (Titre, Responsable, EstActive)
        VALUES (@titre, @responsable, 1);
        SELECT SCOPE_IDENTITY() AS Id;
      `);

    res.json({
      success: true,
      message: 'Nouvelle session active créée avec succès',
      sessionId: result.recordset[0].Id
    });

  } catch (err) {
    console.error("❌ ERREUR CREATION SESSION :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// Route : Fermer une session spécifique
app.post('/api/sessions/close', async (req, res) => {
  const { sessionId } = req.body;

  try {
    const pool = await sql.connect(dbConfig);
    await pool.request()
      .input('id', sql.Int, sessionId)
      .query(`UPDATE Sessions SET EstActive = 0 WHERE Id = @id`);

    res.json({ success: true, message: 'Session fermée avec succès' });
  } catch (err) {
    console.error("❌ ERREUR FERMETURE SESSION :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// Route : Récupérer les 5 dernières sessions
app.get('/api/sessions/recent', async (req, res) => {

  try {

    const pool = await sql.connect(dbConfig);

    const result = await pool.request().query(`
      SELECT
        s.Id,
        s.Titre,
        s.Responsable,
        s.DateCreation,
        s.EstActive,
        s.EstArchivee,

        COUNT(DISTINCT p.UserId) AS Participants

      FROM Sessions s

      LEFT JOIN Presences p
        ON p.SessionId = s.Id

      WHERE ISNULL(s.EstArchivee, 0) = 0

      GROUP BY
        s.Id,
        s.Titre,
        s.Responsable,
        s.DateCreation,
        s.EstActive,
        s.EstArchivee

      ORDER BY
        s.DateCreation DESC
    `);

    res.json({
      success: true,
      sessions: result.recordset
    });

  } catch (err) {

    console.error(
      "❌ Erreur récupération sessions :",
      err
    );

    res.status(500).json({
      success: false,
      message: err.message
    });
  }

});
app.get('/api/admin/statistics', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);

    let { dateDebut, dateFin } = req.query;

    if (!dateDebut) {
      dateDebut = new Date().toISOString().slice(0, 10);
    }

    if (!dateFin) {
      dateFin = dateDebut;
    }

    // =====================================================
    // PARTICIPANTS ATTENDUS
    // Une ligne = un utilisateur inscrit à une session
    // =====================================================

    const participantsResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT COUNT(*) AS totalParticipants
        FROM SessionParticipants sp
        INNER JOIN Sessions s
          ON s.Id = sp.SessionId
        INNER JOIN Utilisateurs u
          ON u.Id = sp.UserId
        WHERE CAST(s.DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
          AND (u.Role IS NULL OR u.Role <> 'Admin')
      `);

    const totalParticipants =
      participantsResult.recordset[0].totalParticipants || 0;


    // =====================================================
    // SESSIONS
    // =====================================================

    const sessionsResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT COUNT(*) AS totalSessions
        FROM Sessions
        WHERE CAST(DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
      `);

    const totalSessions =
      sessionsResult.recordset[0].totalSessions || 0;


    // =====================================================
    // PRÉSENCES
    // =====================================================

    const presenceResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT
          COUNT(*) AS totalPresences,

          SUM(
            CASE
              WHEN UPPER(ISNULL(Statut, 'PRESENT')) = 'RETARD'
              THEN 1
              ELSE 0
            END
          ) AS totalRetards

        FROM Presences p
        INNER JOIN Sessions s
          ON s.Id = p.SessionId

        WHERE CAST(s.DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
      `);

    const totalPresences =
      presenceResult.recordset[0].totalPresences || 0;

    const totalRetards =
      presenceResult.recordset[0].totalRetards || 0;


    // =====================================================
    // ABSENCES
    // =====================================================

    const absences = Math.max(
      0,
      totalParticipants - totalPresences
    );


    // =====================================================
    // TAUX DE PRÉSENCE
    // =====================================================

    const presenceRate =
      totalParticipants > 0
        ? Math.round(
            (totalPresences / totalParticipants) * 100
          )
        : 0;


    // =====================================================
    // PRÉSENTS AUJOURD'HUI
    // =====================================================

    const todayResult = await pool.request().query(`
      SELECT COUNT(*) AS presentsToday
      FROM Presences
      WHERE CAST([Timestamp] AS DATE)
            = CAST(GETDATE() AS DATE)
    `);

    const presentsToday =
      todayResult.recordset[0].presentsToday || 0;


    // =====================================================
    // SESSIONS ACTIVES
    // =====================================================

    const activeResult = await pool.request().query(`
      SELECT COUNT(*) AS activeSessions
      FROM Sessions
      WHERE EstActive = 1
    `);

    const activeSessions =
      activeResult.recordset[0].activeSessions || 0;


    // =====================================================
    // RÉPONSE
    // =====================================================

    res.json({
      success: true,

      period: {
        dateDebut,
        dateFin
      },

      stats: {
        totalUsers: totalParticipants,
        totalSessions,
        totalPresences,
        usersPresent: totalPresences,
        totalRetards,
        absences,
        presenceRate,
        presentsToday,
        activeSessions
      }
    });

  } catch (err) {

    console.error(
      '❌ Erreur statistiques :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});
// Route : Enregistrer une présence via le scan d'un QR code
// Route : Consulter la session actuellement active (utilisée par la page de scan)
app.get('/api/sessions/active', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request().query(`
      SELECT TOP 1 Id, Titre FROM Sessions WHERE EstActive = 1 ORDER BY DateCreation DESC
    `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'Aucune session active.' });
    }

    res.json({ success: true, id: result.recordset[0].Id, titre: result.recordset[0].Titre });
  } catch (err) {
    console.error("❌ Erreur session active :", err.message);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});
// Route : Enregistrer une présence via le scan d'un QR code
app.post('/api/presences/scan', async (req, res) => {
  const { matricule } = req.body;

  if (!matricule) {
    return res.status(400).json({
      success: false,
      message: 'Matricule requis.'
    });
  }

  try {
    const pool = await sql.connect(dbConfig);

    // =====================================================
    // 1. Récupérer la session active la plus récente
    // =====================================================

    const activeSession = await pool.request().query(`
      SELECT TOP 1
        Id,
        Titre
      FROM Sessions
      WHERE EstActive = 1
      ORDER BY DateCreation DESC
    `);

    if (activeSession.recordset.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Aucune session active en cours.'
      });
    }

    const sessionId = activeSession.recordset[0].Id;
    const sessionTitre = activeSession.recordset[0].Titre;

    // =====================================================
    // 2. Vérifier que l'utilisateur existe
    // =====================================================

    const userResult = await pool.request()
      .input('matricule', sql.NVarChar(50), matricule)
      .query(`
        SELECT
          Id,
          Nom,
          Prenom
        FROM Utilisateurs
        WHERE Matricule = @matricule
          AND (EstActif = 1 OR EstActif IS NULL)
      `);

    if (userResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé.'
      });
    }

    const user = userResult.recordset[0];

    // =====================================================
    // 3. Vérifier si l'utilisateur est déjà présent
    //    dans une session encore active
    // =====================================================

    const activePresence = await pool.request()
      .input('userId', sql.UniqueIdentifier, user.Id)
      .query(`
        SELECT TOP 1
          p.Id,
          p.SessionId,
          s.Titre
        FROM Presences p
        INNER JOIN Sessions s
          ON s.Id = p.SessionId
        WHERE p.UserId = @userId
          AND s.EstActive = 1
        ORDER BY p.Timestamp DESC
      `);

    if (activePresence.recordset.length > 0) {

      const ancienneSession =
        activePresence.recordset[0];

      return res.status(400).json({
        success: false,
        message:
          `Vous êtes déjà présent dans la session ` +
          `"${ancienneSession.Titre}". ` +
          `Vous ne pouvez pas pointer dans une autre session ` +
          `tant que celle-ci est active.`
      });
    }

    // =====================================================
    // 4. Sécurité supplémentaire :
    //    vérifier le doublon dans cette session
    // =====================================================

    const existingPresence = await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .input('userId', sql.UniqueIdentifier, user.Id)
      .query(`
        SELECT Id
        FROM Presences
        WHERE SessionId = @sessionId
          AND UserId = @userId
      `);

    if (existingPresence.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Présence déjà enregistrée pour cette session.'
      });
    }

    // =====================================================
    // 5. Enregistrer la présence
    // =====================================================

    await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .input('userId', sql.UniqueIdentifier, user.Id)
      .input('matricule', sql.NVarChar(50), matricule)
      .input('statut', sql.NVarChar(20), 'PRESENT')
      .query(`
        INSERT INTO Presences
        (
          Id,
          SessionId,
          UserId,
          Matricule,
          Timestamp,
          Statut,
          SourceApp,
          Synchro,
          DateSync
        )
        VALUES
        (
          NEWID(),
          @sessionId,
          @userId,
          @matricule,
          GETDATE(),
          @statut,
          'Scan',
          1,
          SYSDATETIME()
        )
      `);

    // =====================================================
    // 6. Réponse
    // =====================================================

    res.json({
      success: true,
      message:
        `Présence enregistrée avec succès pour ` +
        `${user.Prenom || ''} ${user.Nom || matricule}`,
      sessionId: sessionId,
      session: sessionTitre
    });

  } catch (err) {

    console.error(
      '❌ Erreur validation présence :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: 'Erreur lors de l\'enregistrement.'
    });
  }
});
// =====================================================
// INSCRIRE UN UTILISATEUR À UNE SESSION
// =====================================================
app.post('/api/sessions/:sessionId/participer', async (req, res) => {
  const { sessionId } = req.params;
  const { userId } = req.body;

  if (!sessionId || !userId) {
    return res.status(400).json({
      success: false,
      message: 'Session et utilisateur requis.'
    });
  }

  try {
    const pool = await sql.connect(dbConfig);

    // 1. Vérifier que la session existe
    const sessionResult = await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .query(`
        SELECT Id, Titre, EstActive
        FROM Sessions
        WHERE Id = @sessionId
      `);

    if (sessionResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Session introuvable.'
      });
    }

    const session = sessionResult.recordset[0];

    // 2. Vérifier que l'utilisateur existe
    const userResult = await pool.request()
      .input('userId', sql.UniqueIdentifier, userId)
      .query(`
        SELECT Id, Matricule, Nom, Prenom
        FROM Utilisateurs
        WHERE Id = @userId
    `);

    if (userResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur introuvable.'
      });
    }

    // 3. Vérifier si l'utilisateur est déjà inscrit
    const inscriptionResult = await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .input('userId', sql.UniqueIdentifier, userId)
      .query(`
        SELECT Id
        FROM SessionParticipants
        WHERE SessionId = @sessionId
          AND UserId = @userId
      `);

    if (inscriptionResult.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Vous êtes déjà inscrit à cette session.'
      });
    }

    // 4. Vérifier si l'utilisateur est déjà
    //    dans une autre session active
    const activePresenceResult = await pool.request()
      .input('userId', sql.UniqueIdentifier, userId)
      .query(`
        SELECT TOP 1
          p.SessionId,
          s.Titre
        FROM Presences p
        INNER JOIN Sessions s
          ON s.Id = p.SessionId
        WHERE p.UserId = @userId
          AND s.EstActive = 1
        ORDER BY p.Timestamp DESC
      `);

    if (activePresenceResult.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message:
          `Vous êtes déjà présent dans la session "${activePresenceResult.recordset[0].Titre}".`
      });
    }

    // 5. Inscrire l'utilisateur
    await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .input('userId', sql.UniqueIdentifier, userId)
      .query(`
        INSERT INTO SessionParticipants
        (
          SessionId,
          UserId,
          DateInscription
        )
        VALUES
        (
          @sessionId,
          @userId,
          SYSDATETIME()
        )
      `);

    res.json({
      success: true,
      message: `Inscription réussie à la session "${session.Titre}".`
    });

  } catch (err) {

    console.error(
      '❌ Erreur inscription session :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de l’inscription.'
    });
  }
});
// Route pour les presences avec un check in
app.post('/api/presences/checkin', async (req, res) => {
  const { sessionId, matricule } = req.body;

  if (!sessionId || !matricule) {
    return res.status(400).json({
      success: false,
      message: 'sessionId et matricule sont requis.'
    });
  }

  try {
    const pool = await sql.connect(dbConfig);

    // =====================================================
    // 1. Vérifier que la session existe et est active
    // =====================================================

    const sessionResult = await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .query(`
        SELECT
          Id,
          Titre,
          EstActive
        FROM Sessions
        WHERE Id = @sessionId
      `);

    if (sessionResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Session introuvable.'
      });
    }

    const session = sessionResult.recordset[0];

    if (session.EstActive !== true) {
      return res.status(400).json({
        success: false,
        message: 'Cette session n\'est plus active.'
      });
    }

    // =====================================================
    // 2. Vérifier que l'utilisateur existe
    // =====================================================

    const userResult = await pool.request()
      .input('matricule', sql.NVarChar(50), matricule)
      .query(`
        SELECT
          Id,
          Nom,
          Prenom
        FROM Utilisateurs
        WHERE Matricule = @matricule
          AND (EstActif = 1 OR EstActif IS NULL)
      `);

    if (userResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Matricule inconnu.'
      });
    }

    const user = userResult.recordset[0];

    // =====================================================
    // 3. Vérifier si l'utilisateur est déjà présent
    //    dans une session active
    // =====================================================

    const activePresence = await pool.request()
      .input('userId', sql.UniqueIdentifier, user.Id)
      .query(`
        SELECT TOP 1
          p.Id,
          p.SessionId,
          s.Titre
        FROM Presences p
        INNER JOIN Sessions s
          ON s.Id = p.SessionId
        WHERE p.UserId = @userId
          AND s.EstActive = 1
        ORDER BY p.Timestamp DESC
      `);

    if (activePresence.recordset.length > 0) {

      const ancienneSession =
        activePresence.recordset[0];

      // Si c'est exactement la même session
      if (ancienneSession.SessionId === sessionId) {
        return res.status(400).json({
          success: false,
          message:
            'Présence déjà enregistrée pour cette session.'
        });
      }

      // Si c'est une autre session active
      return res.status(400).json({
        success: false,
        message:
          `Vous êtes déjà présent dans la session ` +
          `"${ancienneSession.Titre}". ` +
          `Vous ne pouvez pas pointer dans une autre session ` +
          `tant que celle-ci est active.`
      });
    }

    // =====================================================
    // 4. Vérification supplémentaire du doublon
    // =====================================================

    const existingPresence = await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .input('userId', sql.UniqueIdentifier, user.Id)
      .query(`
        SELECT Id
        FROM Presences
        WHERE SessionId = @sessionId
          AND UserId = @userId
      `);

    if (existingPresence.recordset.length > 0) {
      return res.status(400).json({
        success: false,
        message:
          'Présence déjà enregistrée pour cette session.'
      });
    }

    // =====================================================
    // 5. Enregistrer la présence
    // =====================================================

    await pool.request()
      .input('sessionId', sql.Int, sessionId)
      .input('userId', sql.UniqueIdentifier, user.Id)
      .input('matricule', sql.NVarChar(50), matricule)
      .input('statut', sql.NVarChar(20), 'PRESENT')
      .query(`
        INSERT INTO Presences
        (
          Id,
          SessionId,
          UserId,
          Matricule,
          Timestamp,
          Statut,
          SourceApp,
          Synchro,
          DateSync
        )
        VALUES
        (
          NEWID(),
          @sessionId,
          @userId,
          @matricule,
          GETDATE(),
          @statut,
          'Checkin',
          1,
          SYSDATETIME()
        )
      `);

    // =====================================================
    // 6. Réponse
    // =====================================================

    res.json({
      success: true,
      message:
        `Présence enregistrée pour ` +
        `${user.Prenom || ''} ${user.Nom || matricule}`,
      sessionId: sessionId,
      session: session.Titre
    });

  } catch (err) {

    console.error(
      '❌ Erreur check-in :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: 'Erreur lors de l\'enregistrement.'
    });
  }
});
app.delete('/api/sessions/:id', async (req, res) => {

  const { id } = req.params;

  try {

    const pool = await sql.connect(dbConfig);

    const sessionResult = await pool.request()
      .input('id', sql.Int, id)
      .query(`
        SELECT Id, Titre, EstActive, EstArchivee
        FROM Sessions
        WHERE Id = @id
      `);

    if (sessionResult.recordset.length === 0) {

      return res.status(404).json({
        success: false,
        message: 'Session introuvable.'
      });

    }

    const session = sessionResult.recordset[0];

    if (
      session.EstActive === true ||
      session.EstActive === 1
    ) {

      return res.status(400).json({
        success: false,
        message:
          'Impossible d’archiver une session encore active. ' +
          'Fermez-la d’abord.'
      });

    }

    await pool.request()
      .input('id', sql.Int, id)
      .query(`
        UPDATE Sessions
        SET EstArchivee = 1
        WHERE Id = @id
      `);

    res.json({
      success: true,
      message: 'Session archivée avec succès.'
    });

  } catch (err) {

    console.error(
      '❌ ERREUR ARCHIVAGE SESSION :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: err.message
    });

  }

});
// =====================================================
// GÉNÉRER LES INFORMATIONS D'UN BADGE UTILISATEUR
// =====================================================

app.get('/api/admin/users/:userId/badge', async (req, res) => {

  try {

    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'ID utilisateur requis.'
      });
    }

    const pool = await sql.connect(dbConfig);

    const result = await pool.request()
      .input(
        'userId',
        sql.UniqueIdentifier,
        userId
      )
      .query(`
        SELECT
          Id,
          Matricule,
          Nom,
          Prenom,
          Email,
          Role,
          EstActif
        FROM Utilisateurs
        WHERE Id = @userId
      `);

    if (result.recordset.length === 0) {

      return res.status(404).json({
        success: false,
        message: 'Utilisateur introuvable.'
      });

    }

    const user = result.recordset[0];

    // -------------------------------------------------
    // DONNÉES DU QR CODE PERMANENT
    // -------------------------------------------------

    const qrData = JSON.stringify({
      matricule: user.Matricule,
      nom: user.Nom,
      prenom: user.Prenom
    });

    res.json({

      success: true,

      user: {
        id: user.Id,
        matricule: user.Matricule,
        nom: user.Nom,
        prenom: user.Prenom,
        email: user.Email,
        role: user.Role,
        estActif: user.EstActif
      },

      qrData: qrData

    });

  } catch (err) {

    console.error(
      '❌ ERREUR GÉNÉRATION BADGE :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: err.message
    });

  }

});
// Route ADMIN UNIQUEMENT : générer/ressortir le badge QR de n'importe quel utilisateur
app.get('/api/admin/badges/:matricule', verifyToken, requireAdmin, async (req, res) => {
  const { matricule } = req.params;

  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request()
      .input('matricule', sql.NVarChar(50), matricule)
      .query('SELECT Matricule, Nom, Prenom FROM Utilisateurs WHERE Matricule = @matricule');

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: 'Utilisateur non trouvé.' });
    }

    const user = result.recordset[0];
    const qrData = JSON.stringify({
      matricule: user.Matricule,
      nom: user.Nom,
      prenom: user.Prenom
    });

    // Retourne directement l'image PNG (utilisable dans une balise <img src="/api/users/USR1234/qrcode">)
    res.setHeader('Content-Type', 'image/png');
    QRCode.toFileStream(res, qrData, { width: 300, margin: 2 });

  } catch (err) {
    console.error("❌ Erreur génération QR code :", err.message);
    res.status(500).json({ success: false, message: 'Erreur lors de la génération du QR code.' });
  }
});
//route pour les presences du jour
app.get('/api/admin/presences/today', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request().query(`
  SELECT u.Id, u.Matricule, u.Nom, u.Prenom, p.Timestamp, s.Titre AS SessionTitre
  FROM Utilisateurs u
  OUTER APPLY (
    SELECT TOP 1 Timestamp, SessionId
    FROM Presences
    WHERE Presences.UserId = u.Id
      AND CAST(Timestamp AS DATE) = CAST(GETDATE() AS DATE)
    ORDER BY Timestamp DESC
  ) p
  LEFT JOIN Sessions s ON s.Id = p.SessionId
  WHERE u.Role IS NULL OR u.Role != 'Admin'
  ORDER BY u.Nom, u.Prenom
`);

    const utilisateurs = result.recordset.map(row => ({
      Matricule: row.Matricule,
      Nom: row.Nom,
      Prenom: row.Prenom,
      Timestamp: row.Timestamp,
      Statut: row.Timestamp ? 'Présent' : 'Absent',
      Session: row.SessionTitre || null
    }));
    const total = utilisateurs.length;
    const presents = utilisateurs.filter(u => u.Statut === 'Présent').length;

    res.json({
      success: true,
      total,
      presents,
      absents: total - presents,
      utilisateurs
    });
  } catch (err) {
    console.error("❌ Erreur présences du jour :", err.message);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

//Route pour les statistiques
//app.get('/api/admin/statistics', async (req, res) => {
//try {
//const pool = await sql.connect(dbConfig);

// 1. Total Utilisateurs
//const usersCount = await pool.request().query(
//`SELECT COUNT(*) AS total FROM Utilisateurs WHERE Role != 'Admin'`
//);

// 2. Présents aujourd'hui
//  const todayPresents = await pool.request().query(`
//  SELECT COUNT(DISTINCT UserId) AS total 
//FROM Presences 
//WHERE CAST(TimeStamp AS DATE) = CAST(GETDATE() AS DATE)
//`);

// 3. Sessions actives (Requête propre sans 'true')
//const activeSessionsQuery = await pool.request().query(`
//SELECT COUNT(*) AS actives FROM Sessions WHERE EstActive = 1
//`);

// 4. Total des sessions
//const totalSessionsQuery = await pool.request().query(
//`SELECT COUNT(*) AS total FROM Sessions`
//);

//const totalUsers = usersCount.recordset[0].total || 0;
//const presentsCount = todayPresents.recordset[0].total || 0;
//const activeSessionsCount = activeSessionsQuery.recordset[0].actives || 0;
//const totalSessionsCount = totalSessionsQuery.recordset[0].total || 0;

//const rate = totalUsers > 0 ? Math.round((presentsCount / totalUsers) * 100) : 0;

//    res.json({
//    success: true,
//  stats: {
//  totalUsers: totalUsers,
//presentsToday: presentsCount,
// presenceRate: rate,
//totalSessions: totalSessionsCount,
//activeSessions: activeSessionsCount
// }
//});

//} catch (err) {
//console.error("❌ ERREUR STATS SQL :", err.message);
//res.status(500).json({ success: false, message: err.message });
//}
//});
// ============================================================
// RAPPORTS & STATISTIQUES ADMIN
// ============================================================

app.get('/api/admin/statistics', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);

    let { dateDebut, dateFin } = req.query;

    // Par défaut : aujourd'hui
    if (!dateDebut) {
      dateDebut = new Date().toISOString().slice(0, 10);
    }

    if (!dateFin) {
      dateFin = dateDebut;
    }

    // =====================================================
    // 1. PARTICIPATIONS ATTENDUES
    // =====================================================
    // Une ligne dans SessionParticipants =
    // un utilisateur inscrit à une session.
    //
    // On ne compte donc PLUS :
    // utilisateurs × sessions
    // =====================================================

    const participantsResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT COUNT(*) AS totalParticipants
        FROM SessionParticipants sp
        INNER JOIN Sessions s
          ON s.Id = sp.SessionId
        INNER JOIN Utilisateurs u
          ON u.Id = sp.UserId
        WHERE CAST(s.DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
          AND (u.Role IS NULL OR u.Role != 'Admin')
      `);

    const totalParticipants =
      participantsResult.recordset[0].totalParticipants || 0;


    // =====================================================
    // 2. NOMBRE DE SESSIONS
    // =====================================================

    const sessionsResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT COUNT(*) AS totalSessions
        FROM Sessions
        WHERE CAST(DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
      `);

    const totalSessions =
      sessionsResult.recordset[0].totalSessions || 0;


    // =====================================================
    // 3. PRÉSENCES
    // =====================================================

    const presenceResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT
          COUNT(*) AS totalPresences,

          SUM(
            CASE
              WHEN UPPER(ISNULL(Statut, 'PRESENT')) = 'RETARD'
              THEN 1
              ELSE 0
            END
          ) AS totalRetards

        FROM Presences

        WHERE CAST([Timestamp] AS DATE)
              BETWEEN @dateDebut AND @dateFin
      `);

    const totalPresences =
      presenceResult.recordset[0].totalPresences || 0;

    const totalRetards =
      presenceResult.recordset[0].totalRetards || 0;


    // =====================================================
    // 4. ABSENCES
    // =====================================================

    const absences = Math.max(
      0,
      totalParticipants - totalPresences
    );


    // =====================================================
    // 5. TAUX DE PRÉSENCE
    // =====================================================

    const presenceRate =
      totalParticipants > 0
        ? Math.round(
            (totalPresences / totalParticipants) * 100
          )
        : 0;


    // =====================================================
    // 6. PRÉSENTS AUJOURD'HUI
    // =====================================================

    const todayResult = await pool.request().query(`
      SELECT COUNT(*) AS presentsToday
      FROM Presences
      WHERE CAST([Timestamp] AS DATE)
            = CAST(GETDATE() AS DATE)
    `);

    const presentsToday =
      todayResult.recordset[0].presentsToday || 0;


    // =====================================================
    // 7. SESSIONS ACTIVES
    // =====================================================

    const activeResult = await pool.request().query(`
      SELECT COUNT(*) AS activeSessions
      FROM Sessions
      WHERE EstActive = 1
    `);

    const activeSessions =
      activeResult.recordset[0].activeSessions || 0;


    // =====================================================
    // 8. RÉPONSE
    // =====================================================

    res.json({
      success: true,

      period: {
        dateDebut,
        dateFin
      },

      stats: {

        // Conservé sous ce nom pour ne pas casser
        // ton JavaScript existant.
        totalUsers: totalParticipants,

        totalSessions,

        totalPresences,

        usersPresent: totalPresences,

        totalRetards,

        absences,

        presenceRate,

        presentsToday,

        activeSessions

      }
    });

  } catch (err) {

    console.error(
      '❌ Erreur statistiques :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});
// ============================================================
// ÉVOLUTION MENSUELLE
// ============================================================

app.get('/api/admin/statistics/monthly', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);

    const result = await pool.request().query(`
      SELECT
        YEAR([Timestamp]) AS Annee,
        MONTH([Timestamp]) AS Mois,
        COUNT(*) AS Presences
      FROM Presences
      GROUP BY
        YEAR([Timestamp]),
        MONTH([Timestamp])
      ORDER BY
        YEAR([Timestamp]),
        MONTH([Timestamp])
    `);

    const mois = [
      'Jan',
      'Fév',
      'Mar',
      'Avr',
      'Mai',
      'Juin',
      'Juil',
      'Août',
      'Sep',
      'Oct',
      'Nov',
      'Déc'
    ];

    const data = result.recordset.map(row => ({
      mois: mois[row.Mois - 1],
      annee: row.Annee,
      presences: row.Presences
    }));

    res.json({
      success: true,
      data
    });

  } catch (err) {
    console.error(
      '❌ ERREUR GRAPHIQUE :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});
// ============================================================
// EXPORT PDF
// ============================================================

app.get('/api/admin/export-pdf', async (req, res) => {
  try {

    const pool = await sql.connect(dbConfig);

    let { dateDebut, dateFin } = req.query;

    // =====================================================
    // DATES PAR DÉFAUT
    // =====================================================

    if (!dateDebut) {
      dateDebut = new Date().toISOString().slice(0, 10);
    }

    if (!dateFin) {
      dateFin = dateDebut;
    }


    // =====================================================
    // 1. NOMBRE DE PARTICIPANTS ATTENDUS
    // =====================================================
    // Une inscription dans SessionParticipants
    // correspond à une participation attendue.
    //
    // On ne fait PLUS :
    // totalUsers × totalSessions
    // =====================================================

    const participantsResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT COUNT(*) AS totalParticipants
        FROM SessionParticipants sp

        INNER JOIN Sessions s
          ON s.Id = sp.SessionId

        INNER JOIN Utilisateurs u
          ON u.Id = sp.UserId

        WHERE CAST(s.DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin

          AND (
            u.Role IS NULL
            OR u.Role != 'Admin'
          )
      `);

    const totalParticipants =
      participantsResult.recordset[0].totalParticipants || 0;


    // =====================================================
    // 2. NOMBRE DE SESSIONS
    // =====================================================

    const sessionsResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT COUNT(*) AS totalSessions
        FROM Sessions
        WHERE CAST(DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
      `);

    const totalSessions =
      sessionsResult.recordset[0].totalSessions || 0;


    // =====================================================
    // 3. PRÉSENCES ET RETARDS
    // =====================================================
    // On relie les présences aux sessions concernées.
    // =====================================================

    const presenceResult = await pool.request()
      .input('dateDebut', sql.Date, dateDebut)
      .input('dateFin', sql.Date, dateFin)
      .query(`
        SELECT
          COUNT(*) AS totalPresences,

          SUM(
            CASE
              WHEN UPPER(ISNULL(p.Statut, 'PRESENT')) = 'RETARD'
              THEN 1
              ELSE 0
            END
          ) AS totalRetards

        FROM Presences p

        INNER JOIN Sessions s
          ON s.Id = p.SessionId

        WHERE CAST(s.DateCreation AS DATE)
              BETWEEN @dateDebut AND @dateFin
      `);

    const totalPresences =
      presenceResult.recordset[0].totalPresences || 0;

    const totalRetards =
      presenceResult.recordset[0].totalRetards || 0;


    // =====================================================
    // 4. CALCUL DES ABSENCES
    // =====================================================

    const absences = Math.max(
      0,
      totalParticipants - totalPresences
    );


    // =====================================================
    // 5. CALCUL DU TAUX DE PRÉSENCE
    // =====================================================

    const taux =
      totalParticipants > 0
        ? Math.round(
            (totalPresences / totalParticipants) * 100
          )
        : 0;


    // =====================================================
    // 6. ENREGISTRER LE RAPPORT DANS LA TABLE Rapports
    // =====================================================

    const reportResult = await pool.request()
      .input(
        'nomRapport',
        sql.NVarChar(150),
        `Rapport du ${dateDebut} au ${dateFin}`
      )
      .input(
        'type',
        sql.NVarChar(50),
        'PDF'
      )
      .input(
        'dateDebut',
        sql.Date,
        dateDebut
      )
      .input(
        'dateFin',
        sql.Date,
        dateFin
      )
      .query(`
        INSERT INTO Rapports
        (
          NomRapport,
          Type,
          DateDebut,
          DateFin,
          DateGeneration,
          Statut
        )

        OUTPUT INSERTED.Id

        VALUES
        (
          @nomRapport,
          @type,
          @dateDebut,
          @dateFin,
          SYSDATETIME(),
          'Terminé'
        )
      `);

    const reportId =
      reportResult.recordset[0].Id;


    // =====================================================
    // 7. CRÉATION DU PDF
    // =====================================================

    const doc = new PDFDocument({
      margin: 50
    });


    // =====================================================
    // 8. EN-TÊTES HTTP
    // =====================================================

    res.setHeader(
      'Content-Type',
      'application/pdf'
    );

    res.setHeader(
      'Content-Disposition',
      `attachment; filename="rapport_${dateDebut}_${dateFin}.pdf"`
    );


    doc.pipe(res);


    // =====================================================
    // 9. TITRE
    // =====================================================

    doc
      .fontSize(22)
      .text(
        'SGIP - Rapport de présence',
        {
          align: 'center'
        }
      );

    doc.moveDown();


    // =====================================================
    // 10. PÉRIODE
    // =====================================================

    doc
      .fontSize(12)
      .text(
        `Période : ${dateDebut} au ${dateFin}`
      );

    doc.moveDown();


    // =====================================================
    // 11. STATISTIQUES
    // =====================================================

    doc
      .fontSize(15)
      .text('Statistiques');

    doc.moveDown();


    doc
      .fontSize(12)

      .text(
        `Participations prévues : ${totalParticipants}`
      )

      .text(
        `Sessions : ${totalSessions}`
      )

      .text(
        `Présences : ${totalPresences}`
      )

      .text(
        `Retards : ${totalRetards}`
      )

      .text(
        `Absences : ${absences}`
      )

      .text(
        `Taux de présence : ${taux}%`
      );


    doc.moveDown();


    // =====================================================
    // 12. DATE DE GÉNÉRATION
    // =====================================================

    doc
      .fontSize(10)
      .text(
        `Rapport généré le ${new Date().toLocaleString('fr-FR')}`
      );


    // =====================================================
    // 13. TERMINER LE PDF
    // =====================================================

    doc.end();


  } catch (err) {

    console.error(
      '❌ ERREUR EXPORT PDF :',
      err.message
    );

    // Évite d'essayer d'envoyer du JSON
    // si le PDF a déjà commencé à être envoyé.
    if (!res.headersSent) {

      res.status(500).json({
        success: false,
        message: err.message
      });

    }

  }
});
// Route : Récupérer tous les utilisateurs avec la colonne EstActif
app.get('/api/users/all', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request().query(`
      SELECT 
        u.Id, 
        u.Nom, 
        u.Prenom, 
        u.Email, 
        u.EstActif,
        MAX(p.[Timestamp]) AS DernierePresence
      FROM Utilisateurs u
      LEFT JOIN Presences p ON u.Id = p.UserId
      WHERE u.Role IS NULL OR u.Role != 'Admin'
      GROUP BY u.Id, u.Nom, u.Prenom, u.Email, u.EstActif
      ORDER BY u.Nom ASC
    `);

    res.json({ success: true, users: result.recordset });
  } catch (err) {
    console.error("❌ ERREUR UTILISATEURS :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// Route : Supprimer un utilisateur
app.delete('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const pool = await sql.connect(dbConfig);

    // 1. Supprimer les présences associées (UserId est un GUID/VarChar)
    await pool.request()
      .input('userId', sql.VarChar, id)
      .query('DELETE FROM Presences WHERE UserId = @userId');

    // 2. Supprimer l'utilisateur (Id est un GUID/VarChar)
    await pool.request()
      .input('id', sql.VarChar, id)
      .query('DELETE FROM Utilisateurs WHERE Id = @id');

    res.json({ success: true, message: "Utilisateur supprimé avec succès." });
  } catch (err) {
    console.error("❌ ERREUR SUPPRESSION :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// Route : Modifier un utilisateur
app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { nom, prenom, email, estActif } = req.body;

    const pool = await sql.connect(dbConfig);
    await pool.request()
      .input('id', sql.VarChar, id)
      .input('nom', sql.NVarChar, nom)
      .input('prenom', sql.NVarChar, prenom)
      .input('email', sql.NVarChar, email)
      .input('estActif', sql.Bit, estActif ? 1 : 0)
      .query(`
        UPDATE Utilisateurs 
        SET Nom = @nom, Prenom = @prenom, Email = @email, EstActif = @estActif 
        WHERE Id = @id
      `);

    res.json({ success: true, message: "Utilisateur mis à jour avec succès." });
  } catch (err) {
    console.error("❌ ERREUR MODIFICATION :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
//route pour ajouter un utilisateur
app.post('/api/users/add', async (req, res) => {
  try {
    const { matricule, nom, prenom, email, estActif } = req.body;
    const defaultPassword = '123456'; // Mot de passe temporaire
    const pool = await sql.connect(dbConfig);

    await pool.request()
      .input('matricule', sql.VarChar, matricule || '')
      .input('nom', sql.VarChar, nom || '')
      .input('prenom', sql.VarChar, prenom || '')
      .input('email', sql.VarChar, email || '')
      .input('motDePasse', sql.VarChar, defaultPassword)
      .input('estActif', sql.Bit, estActif ? 1 : 0)
      .query(`
        INSERT INTO Utilisateurs (Id, Matricule, Nom, Prenom, Email, MotDePasse, EstActif)
        VALUES (NEWID(), @matricule, @nom, @prenom, @email, @motDePasse, @estActif)
      `);

    res.json({ success: true, message: "Utilisateur ajouté avec succès." });
  } catch (err) {
    console.error("❌ ERREUR AJOUT :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/sessions/add', async (req, res) => {
  const { matricule, timestamp } = req.body;

  try {
    const pool = await poolPromise;

    // 1. Vérifier que le matricule existe
    let userResult = await pool.request()
      .input('matricule', sql.NVarChar(50), matricule)
      .query('SELECT Id FROM dbo.Utilisateurs WHERE LTRIM(RTRIM(Matricule)) = LTRIM(RTRIM(@matricule))');

    if (userResult.recordset.length === 0) {
      console.log(`⚠️ Matricule introuvable : ${matricule}`);
      return res.status(400).json({ error: "Matricule inconnu." });
    }
    let userId = userResult.recordset[0].Id;

    // 2. NOUVEAU : Récupérer la session activée depuis le WEB
    let sessionResult = await pool.request()
      .query('SELECT TOP 1 Id FROM dbo.Sessions WHERE EstActive = 1 ORDER BY DateCreation DESC');

    if (sessionResult.recordset.length === 0) {
      console.log(`⚠️ Aucune session active`);
      return res.status(400).json({ error: "Aucune session active. Activez une session depuis le WEB." });
    }
    let sessionId = sessionResult.recordset[0].Id;
    console.log(`✅ Session active trouvée : ${sessionId}`);

    // 3. Insertion AVEC le SessionId
    await pool.request()
      .input('userId', sql.UniqueIdentifier, userId)
      .input('matricule', sql.NVarChar(50), matricule)
      .input('timestamp', sql.DateTime2, timestamp || new Date())
      .input('statut', sql.NVarChar(20), 'Present')
      .input('sourceApp', sql.NVarChar(20), 'Desktop')
      .input('sessionId', sql.Int, sessionId)
      .query(`
                INSERT INTO dbo.Presences (Id, UserId, Matricule, Timestamp, Statut, SourceApp, Synchro, DateSync, SessionId) 
                VALUES (NEWID(), @userId, @matricule, @timestamp, @statut, @sourceApp, 1, SYSDATETIME(), @sessionId)
            `);

    console.log(`✅ Pointage inséré pour : ${matricule} dans session ${sessionId}`);
    return res.status(200).json({ message: "Pointage enregistré !", sessionId: sessionId });

  } catch (err) {
    console.error("❌ ERREUR BDD :", err.message);
    return res.status(500).json({ error: err.message });
  }
});
// Route : présences des 7 derniers jours (pour le graphique)
app.get('/api/admin/presences/last7days', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request().query(`
      SELECT CAST(Timestamp AS DATE) AS Jour, COUNT(DISTINCT UserId) AS Total
      FROM Presences
      WHERE Timestamp >= DATEADD(DAY, -6, CAST(GETDATE() AS DATE))
      GROUP BY CAST(Timestamp AS DATE)
      ORDER BY Jour
    `);
    res.json({ success: true, jours: result.recordset });
  } catch (err) {
    console.error("❌ Erreur presences 7 jours :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// Route : présences regroupées par session (pour le graphique)
app.get('/api/admin/presences/by-session', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request().query(`
      SELECT s.Titre, COUNT(p.Id) AS Total
      FROM Sessions s
      LEFT JOIN Presences p ON p.SessionId = s.Id
      GROUP BY s.Titre
      ORDER BY Total DESC
    `);
    res.json({ success: true, sessions: result.recordset });
  } catch (err) {
    console.error("❌ Erreur presences par session :", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// 2. Route pour la synchronisation hors-ligne
app.post('/api/sessions/sync', async (req, res) => {
  const { sessions } = req.body;

  try {
    let pool = await sql.connect();

    for (let session of sessions) {
      // Récupération de l'UserId
      let userResult = await pool.request()
        .input('matricule', sql.NVarChar(50), session.matricule)
        .query('SELECT Id FROM dbo.Utilisateurs WHERE Matricule = @matricule');

      let userId = userResult.recordset.length > 0 ? userResult.recordset[0].Id : null;

      await pool.request()
        .input('userId', sql.UniqueIdentifier, userId)
        .input('matricule', sql.NVarChar(50), session.matricule)
        .input('timestamp', sql.DateTime2, session.timestamp)
        .input('statut', sql.NVarChar(20), 'Present')
        .input('sourceApp', sql.NVarChar(20), 'Desktop')
        .query(`
                    INSERT INTO dbo.Presences (Id, UserId, Matricule, Timestamp, Statut, SourceApp, Synchro, DateSync) 
                    VALUES (NEWID(), @userId, @matricule, @timestamp, @statut, @sourceApp, 1, SYSDATETIME())
                `);
    }

    return res.status(200).json({ message: "Synchronisation réussie !" });
  } catch (err) {
    console.error("Erreur de synchronisation BDD:", err);
    return res.status(500).json({ error: "Erreur lors de la synchronisation" });
  }
});

// TABLEAU DE PRESENCE - PRESENCES DU DESKTOP WPF
app.get('/api/admin/presences/today', async (req, res) => {
  try {
    const pool = await poolPromise;

    const result = await pool.request().query(`
             SELECT
                 u.Id,
                 u.Matricule,
                 u.Nom,
                 u.Prenom,
                 p.Timestamp,
                 CASE
                     WHEN p.Id IS NULL THEN 'Absent'
                     ELSE 'Présent'
                 END AS Statut
             FROM dbo.Utilisateurs u
             LEFT JOIN dbo.Presences p
                 ON u.Id = p.UserId
                 AND CAST(p.Timestamp AS DATE) = CAST(GETDATE() AS DATE)
                 AND p.SourceApp = 'Desktop'
             WHERE u.Role IS NULL OR u.Role <> 'Admin'
             ORDER BY u.Nom, u.Prenom
         `);

    const utilisateurs = result.recordset;

    const presents = utilisateurs.filter(
      x => x.Statut === 'Présent'
    ).length;

    const absents = utilisateurs.filter(
      x => x.Statut === 'Absent'
    ).length;

    res.json({
      success: true,
      total: utilisateurs.length,
      presents,
      absents,
      utilisateurs
    });

  } catch (error) {
    console.error('Erreur présences :', error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});
//test api
//app.get('/test-api', (req, res) => {
// res.json ({
//  success:true,
//  message: "Mon serveur fonctionne"
//  });
// });
// Récupérer l'historique des présences d'un utilisateur par son matricule
app.get('/api/presences/:matricule', async (req, res) => {
  const { matricule } = req.params;

  try {
    const pool = await poolPromise;
    const result = await pool.request()
      .input('matricule', sql.NVarChar(50), matricule)
      .query(`
                SELECT Timestamp, Statut, SourceApp 
                FROM dbo.Presences 
                WHERE LTRIM(RTRIM(Matricule)) = LTRIM(RTRIM(@matricule))
                ORDER BY Timestamp DESC
            `);

    return res.status(200).json(result.recordset);
  } catch (err) {
    console.error("❌ Erreur récupération présences :", err.message);
    return res.status(500).json({ error: "Erreur lors de la récupération des données" });
  }
});
// ============================================================
// RAPPORTS GÉNÉRÉS
// ============================================================

app.get('/api/admin/reports', async (req, res) => {
  try {

    const pool = await sql.connect(dbConfig);

    const result = await pool.request().query(`
      SELECT
        Id,
        NomRapport,
        Type,
        DateDebut,
        DateFin,
        DateGeneration,
        Statut
      FROM Rapports
      ORDER BY DateGeneration DESC
    `);

    res.json({
      success: true,
      reports: result.recordset
    });

  } catch (err) {

    console.error(
      '❌ Erreur récupération rapports :',
      err.message
    );

    res.status(500).json({
      success: false,
      message: err.message
    });

  }
});
app.listen(process.env.PORT, () => console.log(`Serveur lancé sur http://localhost:${process.env.PORT}`));