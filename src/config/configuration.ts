export default () => ({
  port: parseInt(process.env.PORT || '3000', 10),
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/my-app',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  },
  mailtrap: {
    from: process.env.MAIL_FROM || 'noreply@gmail.com',
    host: process.env.MAIL_HOST || 'sandbox.smtp.mailtrap.io',
    port: process.env.MAIL_PORT || '2525',
    user: process.env.MAIL_USERNAME || 'xyz',
    pass: process.env.MAIL_PASSWORD || 'xyz',
  },
  frontend: {
    url: process.env.FRONTEND_URL || 'http://localhost:3000',
  },
  postgres: {
    host: process.env.POSTGRES_HOST || 'localhost',
    port: process.env.POSTGRES_PORT || '5432',
    username: process.env.POSTGRES_USERNAME || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'mysecurepassword',
    database: process.env.POSTGRES_DATABASE || 'my_database',
  },
});
