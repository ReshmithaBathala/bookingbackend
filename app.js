const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
app.use(
  cors({
    origin: "http://localhost:3001", // frontend URL
  })
);
app.use(bodyParser.json());
require("dotenv").config();

const PORT = 3000;
const SECRET_KEY = "reshmitha_secret_key";
const ADMIN_API_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwidXNlcm5hbWUiOiJyZXNobWl0aGEiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MjI3OTQ4NDUsImV4cCI6MTcyMjc5ODQ0NX0.GBvT3r1Z1yzqD0OSRGLNJOZsVcGfITPKaxWSk7vT8f8";

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to database");
});

// Helper functions
const generateToken = (user) => jwt.sign(user, SECRET_KEY, { expiresIn: "1h" });

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Extract the token
  if (!token) return res.sendStatus(401); // Unauthorized if no token

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden if token is invalid
    req.user = user;
    next();
  });
};

// Middleware to check admin API key
const checkAdminApiKey = (req, res, next) => {
  const apiKey = req.headers["api-key"];
  if (apiKey !== ADMIN_API_KEY) return res.sendStatus(403);
  next();
};

// Routes
app.post("/register", (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  db.query(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    [username, hashedPassword, role],
    (err) => {
      if (err) throw err;
      res.send({ message: "User registered successfully" });
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err) throw err;

      if (
        results.length === 0 ||
        !bcrypt.compareSync(password, results[0].password)
      ) {
        return res.sendStatus(401);
      }

      const user = {
        id: results[0].id,
        username: results[0].username,
        role: results[0].role,
      };
      const token = generateToken(user);

      res.send({ token, role: user.role });
    }
  );
});

app.post("/trains", checkAdminApiKey, (req, res) => {
  const { train_name, source, destination, total_seats } = req.body;

  db.query(
    "INSERT INTO trains (train_name, source, destination, total_seats, available_seats) VALUES (?, ?, ?, ?, ?)",
    [train_name, source, destination, total_seats, total_seats],
    (err) => {
      if (err) {
        console.error("Error inserting train:", err);
        return res.sendStatus(500);
      }
      res.send({ message: "Train added successfully" });
    }
  );
});

app.get("/trains", authenticateToken, (req, res) => {
  const { source, destination } = req.query;

  let query = "SELECT * FROM trains";
  let queryParams = [];

  if (source && destination) {
    query += " WHERE source = ? AND destination = ?";
    queryParams = [source, destination];
  }

  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error("Error fetching trains:", err);
      return res.status(500).send("Server error");
    }
    res.send(results);
  });
});

app.put("/trains/:id", checkAdminApiKey, (req, res) => {
  const { id } = req.params;
  const { total_seats } = req.body;

  db.query(
    "UPDATE trains SET total_seats = ? WHERE id = ?",
    [total_seats, id],
    (err, results) => {
      if (err) {
        console.error("Error updating train seats:", err);
        return res.sendStatus(500);
      }

      if (results.affectedRows === 0) {
        return res.sendStatus(404); // Not Found if no rows affected
      }

      res.send({ message: "Seats updated successfully" });
    }
  );
});

app.post("/book", authenticateToken, (req, res) => {
  const { train_id } = req.body;
  const userId = req.user.id;
  const currentDate = new Date();

  db.query(
    "SELECT available_seats FROM trains WHERE id = ?",
    [train_id],
    (err, results) => {
      if (err) {
        console.error("Error querying available seats:", err);
        return res.sendStatus(500); // Internal server error
      }

      // Check if the query returned any results
      if (results.length === 0) {
        return res.sendStatus(404); // Not Found
      }

      const availableSeats = results[0].available_seats;

      // Ensure availableSeats is defined and greater than 0
      if (availableSeats === undefined || availableSeats <= 0) {
        return res.sendStatus(400); // Bad Request
      }

      db.query(
        "UPDATE trains SET available_seats = available_seats - 1 WHERE id = ?",
        [train_id],
        (err) => {
          if (err) {
            console.error("Error updating available seats:", err);
            return res.sendStatus(500); // Internal server error
          }

          db.query(
            "INSERT INTO bookings (user_id, train_id) VALUES (?, ?)",
            [train_id, userId],
            (err) => {
              if (err) {
                console.error("Error inserting booking:", err);
                return res.sendStatus(500); // Internal server error
              }
              res.send({ message: "Booking successful" });
            }
          );
        }
      );
    }
  );
});

app.get("/bookings", authenticateToken, (req, res) => {
  db.query(
    "SELECT * FROM bookings WHERE user_id = ?",
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error("Error fetching bookings:", err);
        return res.sendStatus(500);
      }

      res.send(results);
    }
  );
});

app.get("/bookings/:id", authenticateToken, (req, res) => {
  const bookingId = req.params.id;

  db.query(
    "SELECT * FROM bookings WHERE id = ? AND user_id = ?",
    [bookingId, req.user.id],
    (err, results) => {
      if (err) {
        console.error("Error fetching booking details:", err);
        return res.sendStatus(500);
      }

      if (results.length === 0) {
        return res.sendStatus(404); // Booking not found
      }

      res.send(results[0]);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
