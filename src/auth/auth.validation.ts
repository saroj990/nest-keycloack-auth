// auth.validation.ts
import * as Joi from 'joi';
//TODO: add strong validation
export const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
});
