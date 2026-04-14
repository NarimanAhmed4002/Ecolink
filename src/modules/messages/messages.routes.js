import express from 'express';
import { isAuthenticated } from '../../middleware/auth.middleware.js';
import { validateRequest } from '../../middleware/validation.middleware.js';
import * as messagesController from './messages.controller.js';
import { validateSendMessage } from './messages.validation.js';

const router = express.Router();

router.use(isAuthenticated);

router.get('/', messagesController.list);
router.post('/', validateRequest(validateSendMessage), messagesController.send);

export default router;

