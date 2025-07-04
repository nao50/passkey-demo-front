# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Start development server**: `npm start` or `ng serve` (runs on http://localhost:4200)
- **Build for production**: `npm run build` or `ng build`
- **Build for development with watch**: `npm run watch` or `ng build --watch --configuration development`
- **Run tests**: `npm test` or `ng test` (uses Karma + Jasmine)
- **Generate components**: `ng generate component component-name`

## Architecture

This is an Angular 20 application using the latest Angular features:

- **Configuration**: Uses standalone application configuration (app.config.ts) with zoneless change detection
- **Routing**: Centralized routing configuration in app.routes.ts (currently empty)
- **Build System**: Uses Angular's new application builder (@angular/build:application)
- **Testing**: Karma + Jasmine test runner configured
- **Styling**: Global styles in src/styles.css, component-specific styles supported

## Key Files

- `src/app/app.config.ts` - Main application configuration with providers
- `src/app/app.routes.ts` - Routing configuration
- `src/main.ts` - Application bootstrap
- `angular.json` - Angular CLI workspace configuration
- `tsconfig.app.json` - TypeScript configuration for the app
- `tsconfig.spec.json` - TypeScript configuration for tests

## Development Notes

- Uses npm as package manager
- Prettier is configured with Angular parser for HTML files
- Bundle size limits: 500kB warning, 1MB error for initial bundle
- Component style limits: 4kB warning, 8kB error
- Source maps enabled in development builds