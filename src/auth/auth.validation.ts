// auth.validation.ts
import Joi from 'joi';
//TODO: add strong validation
export const LoginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
});

export const TokenSchema = Joi.object({
  refreshToken: Joi.string().required(),
});
