import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  APP_PORT: number;
  NATS_SERVERS: string[];
  JWT_SECRET: string;
}

const evnsSchema = joi
  .object({
    APP_PORT: joi.number().required(),
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    JWT_SECRET: joi.string().required(),
  })
  .unknown(true);

const { error, value } = evnsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
});

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.APP_PORT,
  nats_servers: envVars.NATS_SERVERS,
  jwtSecret: envVars.JWT_SECRET,
};
