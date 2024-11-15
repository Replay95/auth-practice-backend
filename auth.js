const jwt = require("jsonwebtoken");
const SECRET_KEY = "PVjFnc3W3VamtX2AVoA38fugQNlEkJ5Plx6amq7MVR0=";

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "トークンが必要です" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "無効なトークンです" });
    req.user = user;
    next();
  });
}

module.exports = {
  authenticateToken,
  SECRET_KEY,
};
