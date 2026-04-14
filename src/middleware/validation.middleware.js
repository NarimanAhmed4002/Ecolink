/**
 * Validates req body/session using a schema validator.
 * Expects validator to throw or call next(error) on failure.
 * @param {Function} validator - (req, res, next) => {} or schema-based validator
 */
export const validate = (validator) => {
  return (req, res, next) => {
    try {
      const result = validator(req.body || req.query || req.params);
      if (result && result.error) {
        return res.status(400).json({
          success: false,
          message: result.error.details?.[0]?.message || 'Validation failed',
        });
      }
      if (result && result.value) {
        req.validated = result.value;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Generic middleware that runs a validation function and passes errors to next()
 * Use with modules that export validateRegister, validateLogin, etc.
 */
export const validateRequest = (validateFn) => {
  return (req, res, next) => {
    try {
      const error = validateFn(req.body || req.params, req);
      if (error) {
        return res.status(400).json({ success: false, message: error });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
};
