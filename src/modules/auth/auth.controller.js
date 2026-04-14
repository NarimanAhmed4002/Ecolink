import { asyncHandler } from '../../utils/error/index.js';
import * as authService from './auth.service.js';

export const register = asyncHandler(async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;
  if(!firstName || !lastName || !email || !password){
    return res.status(400).json({ success:false, message:"All fields are required" });
  }
  const result = await authService.register(firstName, lastName, email, password);
  res.status(201).json({ success: true, data: result });
});

export const login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;
  const result = await authService.login(email, password);
  res.status(200).json({ success: true, data: result });
});

export const refreshToken = asyncHandler(async (req, res, next) => {
  const refreshToken = req.body?.refreshToken || req.headers?.refreshtoken;
  const result = await authService.refreshTokens(refreshToken);
  res.status(200).json({ success: true, data: result });
});

export const logout = asyncHandler(async (req, res, next) => {
  const refreshToken = req.body?.refreshToken || req.headers?.refreshtoken;
  await authService.logout(refreshToken);
  res.status(200).json({ success: true, message: 'Logged out successfully' });
});
//E:\ECO LINK\ecolink-backend\src\modules\auth\auth.controller.js