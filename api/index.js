require(`dotenv`).config();
const express = require("express");
const cors = require("cors");
const pool = require("./db");
const app = express();
const { SECRET_KEY, authenticateToken } = require("./auth");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 3000;

const corsOption = {
  origin: ["http://localhost:5173"],
  optionSuccessStatus: 200,
};

app.use(cors(corsOption));

app.use(express.json());

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userQuery =
      "SELECT id, email, password, created_at FROM users WHERE id = $1";
    const result = await pool.query(userQuery, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "ユーザーが見つかりません" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "サーバーエラーが発生しました" });
  }
});

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, password, created_at",
      [email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.status(201).json({
      token: `Bearer ${token}`,
      user: {
        id: user.id,
        email: user.email,
        password: user.password,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "エラーが発生しました" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "エラーが発生しました" });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: "エラーが発生しました" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.status(200).json({
      token: `Bearer ${token}`,
      user: {
        id: user.id,
        email: user.email,
        password: user.password,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "エラーが発生しました" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} .env: ${process.env.NODE_ENV}`);
});

app.get("/", (req, res) => {
  res.send("Hello world");
});

app.get("/users", authenticateToken, async (req, res) => {
  const { user } = req;

  const result = await pool.query("SELECT * FROM users WHERE email = $1", [
    user.email,
  ]);
  res.json(result.rows[0]);
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  await pool.query(
    "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
    [email, hashedPassword]
  );

  res.send("User registered");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);

  if (result.rows.length === 0) {
    return res.status(404).json({ error: "Wrong credential" });
  }
  const user = result.rows[0];
  const isPasswodValid = await bcrypt.compare(password, user.password);

  if (!isPasswodValid) {
    return res.status(400).json({ error: "Wrong credential" });
  }

  const token = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "1h" });

  res.cookie("authToken", token, {
    httpOnly: true,
    secure: true,
    maxAge: 3600000,
  });

  res.json({ token });
});
