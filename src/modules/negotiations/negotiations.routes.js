import express from 'express';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as negotiationsController from './negotiations.controller.js';
import { validateCreateNegotiation } from './negotiations.validation.js';

const router = express.Router();

router.use(isAuthenticated);

router.post('/', validateRequest(validateCreateNegotiation), negotiationsController.create);
router.get('/me', negotiationsController.listMine);
router.get('/:id', negotiationsController.getOne);

export default router;

