import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import routes from './routes/index.js';
import { globalErrorHandler } from './utils/error/index.js';

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api', routes);

app.use((req, res, next) => {
  next(new Error('Not Found', { cause: 404 }));
});

app.use(globalErrorHandler);

export default app;
