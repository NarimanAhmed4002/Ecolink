import express from 'express';
import authRoutes from '../modules/auth/auth.routes.js';
import userRoutes from '../modules/user/user.routes.js';
import wasteRoutes from '../modules/waste/waste.routes.js';
import ordersRoutes from '../modules/orders/orders.routes.js';
import negotiationsRoutes from '../modules/negotiations/negotiations.routes.js';
import messagesRoutes from '../modules/messages/messages.routes.js';
import cartRoutes from '../modules/cart/cart.routes.js';
import reviewsRoutes from '../modules/reviews/reviews.routes.js';

const router = express.Router();

router.get('/health', (req, res) => {
  res.json({ success: true, message: 'EcoLink API is running' });
});

router.use('/auth', authRoutes);
router.use('/user', userRoutes);
router.use('/waste', wasteRoutes);
router.use('/orders', ordersRoutes);
router.use('/negotiations', negotiationsRoutes);
router.use('/messages', messagesRoutes);
router.use('/cart', cartRoutes);
router.use('/reviews', reviewsRoutes);

export default router;
