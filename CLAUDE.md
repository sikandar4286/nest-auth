# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build & Development
- `npm run build` - Build the application using NestJS
- `npm run build:swc` - Build using SWC (faster TypeScript compilation)
- `npm run start` - Start the application
- `npm run start:dev` - Start in development mode with file watching
- `npm run start:dev:swc` - Start development mode with SWC for faster compilation
- `npm run start:prod` - Start in production mode

### Code Quality
- `npm run lint` - Run ESLint with auto-fix
- `npm run format` - Format code using Prettier
- `npm run test` - Run unit tests
- `npm run test:watch` - Run tests in watch mode
- `npm run test:cov` - Run tests with coverage
- `npm run test:e2e` - Run end-to-end tests

### Database (DES Module - PostgreSQL)
- `npm run migration:g:des` - Generate new migration (requires {migrationName} parameter)
- `npm run migration:run:des` - Run pending migrations
- `npm run migration:revert:des` - Revert last migration
- `npm run seed:des` - Run database seeders

## Architecture Overview

This is a NestJS application with a hybrid architecture supporting both MongoDB and PostgreSQL databases:

### Dual Database Setup
- **Main Application**: Uses MongoDB with Mongoose for traditional auth/roles functionality
- **DES Module**: Uses PostgreSQL with TypeORM for a more sophisticated RBAC system

### Key Modules
1. **AuthModule** (`src/auth/`) - MongoDB-based authentication with JWT
2. **RolesModule** (`src/roles/`) - MongoDB-based role management
3. **DesModule** (`src/des/`) - PostgreSQL-based system with:
   - Advanced RBAC (Role-Based Access Control)
   - Redis caching integration
   - Separate migration system
   - Comprehensive user/role/permission entities

### Database Configuration
- MongoDB connection configured in `AppModule`
- PostgreSQL connection configured in `DesModule` only
- TypeORM migrations are disabled in non-production (`synchronize: false`, `migrationsRun: true` in production)
- Separate data source configuration in `src/des/data-source.ts` for migrations

### Security & Guards
- JWT-based authentication with refresh tokens
- Custom authentication guards in both MongoDB (`src/guards/`) and PostgreSQL (`src/des/guards/`) systems
- Permission-based authorization decorators
- Global validation pipes with whitelist enabled

### Caching
- Redis integration configured in DES module using `@keyv/redis`
- 30-second TTL default for cached data

### Key Patterns
- DTOs for request/response validation using class-validator
- Global response interceptor for consistent API responses
- CORS enabled for `http://localhost:5179`
- Environment-based configuration using `@nestjs/config`

## Development Notes

### Working with DES Module
- DES module has its own TypeORM setup separate from the main app
- Use the specific migration commands for DES module database changes
- Seeds are available for initial data setup
- Redis must be running locally on port 6379 for caching

### Testing
- Unit tests use Jest with TypeScript support
- E2E tests have separate configuration
- Coverage reports generated in `../coverage` directory

### Environment Setup
- Requires `.env` file with database configurations for both MongoDB and PostgreSQL
- CORS configured for React frontend on port 5179