// filepath: c:\Users\Administrator\chat\backend\schemas.js
const Joi = require('joi');

const groupSchema = Joi.object({
  name: Joi.string().required(),
  description: Joi.string().optional(),
  members: Joi.array().items(Joi.string()).optional(),
});

module.exports = {
  groupSchema,
};