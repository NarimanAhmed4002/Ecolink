const validateRegister = (body) => {
  const { firstName, lastName, email, password } = body || {};
  if (!firstName || !firstName.trim()) return 'First name is required';
  if (!lastName || !lastName.trim()) return 'Last name is required';
  if (!email || !email.trim()) return 'Email is required';
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return 'Invalid email format';
  if (!password) return 'Password is required';
  if (password.length < 6) return 'Password must be at least 6 characters';
  return null;
};

const validateLogin = (body) => {
  const { email, password } = body || {};
  if (!email || !email.trim()) return 'Email is required';
  if (!password) return 'Password is required';
  return null;
};

const validateRefreshToken = (body, req) => {
  const refreshToken = body?.refreshToken || req?.headers?.refreshtoken;
  if (!refreshToken) return 'Refresh token is required';
  return null;
};

export { validateRegister, validateLogin, validateRefreshToken };
//E:\ECO LINK\ecolink-backend\src\modules\auth\auth.validation.js