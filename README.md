# EcoLink Backend

EcoLink is a Node.js + Express + MongoDB backend application following an MVC architecture.

## Tech Stack

- Node.js
- Express
- MongoDB with Mongoose

## Project Structure

```text
src/
  config/
    db.js
  controllers/
  middlewares/
    errorHandler.js
  models/
  routes/
    index.js
  utils/
app.js
server.js
```

## Getting Started

1. Install dependencies:

```bash
npm install
```

2. Create a `.env` file based on `.env.example` and set your `MONGODB_URI` and `PORT` if needed.

3. Run the development server:

```bash
npm run dev
```

The server will start on `http://localhost:3000` by default.

## MongoDB Connection

The MongoDB connection is handled via Mongoose in `src/config/db.js`. The connection string is read from the `MONGODB_URI` environment variable or defaults to `mongodb://localhost:27017/ecolink`.

