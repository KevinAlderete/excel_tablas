const express = require("express");
const { google } = require("googleapis");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const ExcelJS = require("exceljs");
const XLSX = require("xlsx");
require("dotenv").config();
const session = require("express-session");

const app = express();
const PORT = 3000;

// Ruta al archivo de credenciales
// Escribir el archivo temporalmente
const tempCredentialsPath = path.join(__dirname, "tmp-credentials.json");
fs.writeFileSync(
  tempCredentialsPath,
  process.env.GOOGLE_APPLICATION_CREDENTIALS
);

// Leer las credenciales
const credentials = JSON.parse(fs.readFileSync(tempCredentialsPath, "utf8"));

// Autenticación
const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ["https://www.googleapis.com/auth/spreadsheets"],
});

const spreadsheetId = "12XREUejy7VS2lGGaQA0keBcbYxquxB-nUS8s4qHha1w";

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: "secret_key",
    resave: false,
    saveUninitialized: true,
  })
);

// Sirve los archivos estáticos (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// Ruta para la página de inicio
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Ruta para el Dashboard
app.get("/dashboard", verifyToken, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Ruta para el Dashboard del administrador
app.get("/users", verifyToken, (req, res) => {
  // Verificar que el usuario sea el administrador
  //console.log(req.user);
  if (req.user.role !== "Administrador") {
    return res.redirect("/dashboard");
    //return res.status(403).json({ error: "No autorizado" });
  }

  // Enviar el archivo HTML del Dashboard
  res.sendFile(path.join(__dirname, "public", "users.html"));
});

// Ruta para obtener la lista de nombres de hojas
app.get("/users/sheets", verifyToken, async (req, res) => {
  try {
    // Verificar que el usuario sea el administrador
    if (req.user.role !== "Administrador") {
      return res.status(403).json({ error: "No autorizado" });
    }

    // Cliente de Google Sheets
    const sheets = google.sheets({ version: "v4", auth });

    // Obtener propiedades de la hoja de cálculo
    const response = await sheets.spreadsheets.get({ spreadsheetId });

    // Extraer y limpiar nombres de las hojas
    const sheetNames = response.data.sheets.map(
      (sheet) => sheet.properties.title //.trim()
    );

    // Devolver nombres de las hojas
    res.json({ sheets: sheetNames });
  } catch (error) {
    console.error("Error al obtener nombres de las hojas:", error);
    res.status(500).json({ error: "No se pudieron obtener las hojas." });
  }
});

// Ruta para obtener la lista de nombres de hojas
app.get("/users/data", verifyToken, async (req, res) => {
  try {
    // Verificar que el usuario sea el administrador
    if (req.user.role !== "Administrador") {
      return res.status(403).json({ error: "No autorizado" });
    }

    // Obtener los datos de la hoja de usuarios
    const userData = await getSheetData("Usuarios");

    // Enviar los datos al frontend
    res.json(userData);
  } catch (error) {
    console.error("Error al obtener los usuarios:", error);
    res.status(500).json({ error: "No se pudieron obtener los usuarios." });
  }
});

// Función para obtener datos desde Google Sheets
async function getSheetData(sheetName) {
  const client = await auth.getClient();
  const sheets = google.sheets({ version: "v4", auth: client });

  const response = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: sheetName,
  });

  return response.data.values;
}

// Función para obtener los usuarios
async function getUsers() {
  const client = await auth.getClient();
  const sheets = google.sheets({ version: "v4", auth: client });

  const response = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: "Usuarios!A2:F", // Suponiendo que la fila 1 contiene los encabezados
  });

  return response.data.values;
}

// Ruta para el login
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;

  try {
    const users = await getUsers();
    const user = users.find((u) => u[2] === userId); // Busca el userId
    const af = "funciona";
    const isPasswordValid = await bcrypt.compare(password, user[3]);
    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user[3]);
      if (isPasswordValid) {
        // Crear un token JWT
        const token = jwt.sign(
          { userId: user[2], sheet: user[4], role: user[5] },
          "secret_key",
          { expiresIn: "1h" }
        );
        req.session.token = token; // Guardar token en la sesión
        return res.json({ message: "Login exitoso", token });
      }
    }
    res.status(400).json({
      error: `Credenciales incorrectas.`,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al realizar el login" });
  }
});

// Middleware para verificar la autenticación
function verifyToken(req, res, next) {
  const token = req.session.token; // Obtenemos el token de la sesión
  if (!token) {
    // Si no hay token, redirigir al inicio (login)
    return res.redirect("/");
  }

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) {
      // Si el token es inválido, redirigir al inicio
      return res.redirect("/");
    }
    req.user = decoded; // Asigna los datos decodificados del token al objeto `req.user`
    next(); // Continúa con la siguiente función middleware
  });
}

// En la ruta '/data', usa el nombre de la hoja
app.get("/data", verifyToken, async (req, res) => {
  try {
    const usuarios = await getSheetData("Usuarios");
    const usuarioActual = usuarios.find(
      (usuario) => usuario[2] === req.user.userId
    );

    if (!usuarioActual) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const nombreHoja = usuarioActual[4];
    if (!nombreHoja) {
      return res
        .status(400)
        .json({ error: "No se encontró un nombre de hoja para este usuario" });
    }

    const data = await getSheetData(nombreHoja);

    res.json({
      hoja: nombreHoja,
      datos: data, // Enviar todos los datos sin paginar
    });
  } catch (error) {
    console.error("Error al cargar datos:", error);
    res.status(500).json({ error: "Error al cargar los datos" });
  }
});

// Ruta para crear usuarios (solo administradores)
app.post("/users", verifyToken, async (req, res) => {
  const { name, lastName, userId, password, sheet, rol } = req.body;

  if (!req.user || req.user.role !== "Administrador") {
    return res.status(403).json({ error: "No autorizado" });
  }

  try {
    const client = await auth.getClient();
    const sheets = google.sheets({ version: "v4", auth: client });

    // Leer los datos actuales de la hoja de usuarios
    const readResponse = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: "Usuarios!C2:C",
    });

    const existingUserIds = readResponse.data.values
      ? readResponse.data.values.flat() // Asegurarse de que sea un array plano
      : [];

    // Validar si el userId ya existe
    if (existingUserIds.includes(userId)) {
      return res.status(400).json({ error: "El usuario ya existe" });
    }

    // Si no existe, procedemos a crear el usuario
    const hashedPassword = await bcrypt.hash(password, 10);

    const writeResponse = await sheets.spreadsheets.values.append({
      spreadsheetId,
      range: "Usuarios!A2:F",
      valueInputOption: "RAW",
      resource: {
        values: [[name, lastName, userId, hashedPassword, sheet, rol]],
      },
    });

    res.json({ message: "Usuario creado correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al crear el usuario" });
  }
});

// Función para obtener el `sheetId` de una hoja específica
async function getSheetId(sheetName) {
  const client = await auth.getClient();
  const sheets = google.sheets({ version: "v4", auth: client });

  // Obtener las propiedades de todas las hojas
  const response = await sheets.spreadsheets.get({
    spreadsheetId,
    fields: "sheets.properties", // Pedir todas las propiedades
  });
  //
  // Buscar la hoja por su título
  const sheet = response.data.sheets.find(
    (sheet) => sheet.properties.title === sheetName
  );

  if (!sheet) {
    throw new Error(`No se encontró la hoja con título "${sheetName}".`);
  }

  return sheet.properties.sheetId;
}

// Función para eliminar un usuario de Google Sheets
async function deleteUserFromSheet(userId) {
  try {
    const client = await auth.getClient();
    const sheets = google.sheets({ version: "v4", auth: client });

    // Obtener el ID de la hoja "Usuarios"
    const sheetId = await getSheetId("Usuarios");

    // Obtener los datos de la hoja
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: "Usuarios!A2:F",
    });

    const rows = response.data.values;

    if (!rows || rows.length === 0) {
      throw new Error("No hay datos en la hoja.");
    }

    // Buscar el índice de la fila que contiene el userId
    const rowIndex = rows.findIndex((row) => row[2] === userId);

    if (rowIndex === -1) {
      throw new Error("Usuario no encontrado.");
    }

    // Eliminar la fila
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId,
      requestBody: {
        requests: [
          {
            deleteDimension: {
              range: {
                sheetId, // Usar el sheetId obtenido
                dimension: "ROWS",
                startIndex: rowIndex + 1, // Ajustar según el rango "A2:E"
                endIndex: rowIndex + 2,
              },
            },
          },
        ],
      },
    });

    return "Usuario eliminado correctamente.";
  } catch (error) {
    console.error("Error al eliminar el usuario:", error);
    throw error;
  }
}

// Ruta para eliminar usuarios
app.delete("/users/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;

  if (!req.user || req.user.role !== "Administrador") {
    return res.status(403).json({ error: "No autorizado" });
  }

  try {
    const result = await deleteUserFromSheet(userId);
    res.json({ message: result });
  } catch (error) {
    res.status(500).json({ error: "Error al eliminar el usuario." });
  }
});

// Ruta para obtener los datos del usuario
app.get("/users/:userId", verifyToken, async (req, res) => {
  const { userId: paramUserId } = req.params;

  if (!req.user || req.user.role !== "Administrador") {
    return res.status(403).json({ error: "No autorizado" });
  }
  //console.log(paramUserId);

  try {
    const client = await auth.getClient();
    const sheets = google.sheets({ version: "v4", auth: client });

    // Obtener los datos del usuario
    const readResponse = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: "Usuarios!A2:F",
    });

    const data = readResponse.data.values;
    const user = data.find((row) => row[2] == paramUserId);
    //console.log(user, data);

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // Devolver los datos del usuario
    res.json({
      user: {
        name: user[0],
        lastName: user[1],
        userId: user[2],
        sheet: user[4],
        rol: user[5],
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al obtener los datos del usuario" });
  }
});

app.put("/users/:userId", verifyToken, async (req, res) => {
  //console.log("Datos recibidos:", req.body); // Verifica los datos que se reciben

  const { name, lastName, userId, password, sheet, rol } = req.body;
  const { userId: paramUserId } = req.params;

  if (!req.user || req.user.role !== "Administrador") {
    return res.status(403).json({ error: "No autorizado" });
  }

  try {
    const client = await auth.getClient();
    const sheets = google.sheets({ version: "v4", auth: client });

    const readResponse = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: "Usuarios!A2:F",
    });

    const data = readResponse.data.values;
    const userIndex = data.findIndex((row) => row[2] === paramUserId);

    if (userIndex === -1) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const hashedPassword = password
      ? await bcrypt.hash(password, 10)
      : data[userIndex][3];

    const writeResponse = await sheets.spreadsheets.values.update({
      spreadsheetId,
      range: `Usuarios!A${userIndex + 2}:F${userIndex + 2}`,
      valueInputOption: "RAW",
      resource: {
        values: [[name, lastName, userId, hashedPassword, sheet, rol]],
      },
    });

    res.json({ message: "Usuario actualizado correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al actualizar el usuario" });
  }
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
