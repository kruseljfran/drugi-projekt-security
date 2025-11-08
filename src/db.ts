import { Pool } from "pg";
import dotenv from "dotenv";
dotenv.config();

const connectionString = process.env.DATABASE_URL || "postgresql://postgres:postgres@localhost:5432/drugi-projekt-security";

const isProduction = process.env.NODE_ENV === "production";

const useSsl =
  isProduction ||
  (process.env.DATABASE_URL ? process.env.DATABASE_URL.indexOf("render.com") !== -1 : false);

export const pool = new Pool({
  connectionString,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});