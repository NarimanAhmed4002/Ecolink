import express from 'express';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as reviewsController from './reviews.controller.js';
import { validateCreateReview } from './reviews.validation.js';

const router = express.Router();

router.get('/', reviewsController.list);
router.post('/', isAuthenticated, validateRequest(validateCreateReview), reviewsController.create);

export default router;

