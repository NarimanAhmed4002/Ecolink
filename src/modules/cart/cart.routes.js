import express from 'express';
import * as cartController from './cart.controller.js';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import { validateAddCartItem, validateUpdateCartItem } from './cart.validation.js';

const router = express.Router();

router.use(isAuthenticated);

router.get('/', cartController.getCart);
router.post('/items', validateRequest(validateAddCartItem), cartController.addItem);
router.patch('/items/:wasteId', validateRequest(validateUpdateCartItem), cartController.updateItem);
router.delete('/items/:wasteId', cartController.removeItem);

export default router;
