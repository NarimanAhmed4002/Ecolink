import express from 'express';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as userController from './user.controller.js';
import { validateUpdateProfile, validateChangePassword } from './user.validation.js';

const router = express.Router();

router.use(isAuthenticated);

router.get('/profile', userController.getProfile);
router.patch('/profile', validateRequest(validateUpdateProfile), userController.updateProfile);
router.patch('/change-password', validateRequest(validateChangePassword), userController.changePassword);

export default router;
//E:\ECO LINK\ecolink-backend\src\modules\user\user.routes.js