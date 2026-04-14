import express from 'express';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as authController from './auth.controller.js';
import { validateRegister, validateLogin, validateRefreshToken } from './auth.validation.js';

const router = express.Router();

router.post('/register', validateRequest(validateRegister), authController.register);
router.post('/login', validateRequest(validateLogin), authController.login);
router.post('/refresh-token', validateRequest(validateRefreshToken), authController.refreshToken);
router.post('/logout', authController.logout);

export default router;
//E:\ECO LINK\ecolink-backend\src\modules\auth\auth.routes.js