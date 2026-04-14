import express from 'express';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as ordersController from './orders.controller.js';
import { validateCreateOrder } from './orders.validation.js';

const router = express.Router();

router.use(isAuthenticated);

router.post('/', validateRequest(validateCreateOrder), ordersController.create);
router.get('/me', ordersController.listMine);
router.get('/:id', ordersController.getOne);

export default router;

