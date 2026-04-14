import express from 'express';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as wasteController from './waste.controller.js';
import { validateCreateWaste, validateUpdateWaste } from './waste.validation.js';

const router = express.Router();

router.get('/', wasteController.list);
router.get('/:id', wasteController.getOne);

router.post('/', isAuthenticated, validateRequest(validateCreateWaste), wasteController.create);
router.patch('/:id', isAuthenticated, validateRequest(validateUpdateWaste), wasteController.update);
router.delete('/:id', isAuthenticated, wasteController.remove);

export default router;

