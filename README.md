# CipherBank Frontend

Enterprise-grade web application for bank statement processing and financial data management. Built with React and modern web technologies to provide a secure, performant interface for The PayTrix CipherBank platform.

## Overview

CipherBank Frontend is a production-ready React application that provides the user interface for bank statement parsing, financial data visualization, and secure document management. The application integrates with the CipherBank backend API through JWT-based authentication and implements industry-standard security practices.

## Technology Stack

### Core Framework
- **React** 19.2.0 - Modern component-based UI library
- **React DOM** 19.2.0 - DOM-specific methods for React
- **React Scripts** 5.0.1 - Build tooling and development server

### Styling & UI
- **Tailwind CSS** 3.4.18 - Utility-first CSS framework
- **PostCSS** 8.5.6 - CSS processing and transformation
- **Autoprefixer** 10.4.22 - Automatic vendor prefix management
- **Lucide React** 0.555.0 - Icon library for modern UI components

### Testing
- **Testing Library** (React, DOM, Jest DOM, User Event) - Comprehensive testing utilities
- **Web Vitals** 2.1.4 - Performance monitoring and metrics

## Prerequisites

Before running this project, ensure you have the following installed:

- **Node.js** 20.x or higher
- **npm** 9.x or higher
- Access to the CipherBank backend API
- Valid API credentials and environment configuration

## Getting Started

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd cipherbank-frontend
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
Create a `.env` file in the project root with the following configuration:
```env
REACT_APP_API_URL=<backend-api-url>
```

Note: Replace `<backend-api-url>` with your CipherBank backend API endpoint.

### Development Server

Start the development server with hot-reload:
```bash
npm start
```

The application will be available at `http://localhost:3000`. The development server provides:
- Hot module replacement (HMR)
- Real-time error reporting
- Automatic browser refresh on file changes

### Production Build

Create an optimized production build:
```bash
npm run build
```

The build process will:
- Minify and bundle all JavaScript and CSS
- Optimize assets for production deployment
- Generate source maps (configurable)
- Output files to the `build/` directory

Build artifacts are optimized for best performance with code splitting, tree shaking, and asset compression.

### Testing

Run the test suite:
```bash
npm test
```

Tests run in interactive watch mode by default. Press `a` to run all tests or `q` to quit.

For CI/CD environments:
```bash
CI=true npm test
```

## Project Structure

```
cipherbank-frontend/
├── public/              # Static assets and HTML template
│   ├── index.html      # Application entry point
│   ├── manifest.json   # PWA configuration
│   └── favicon.ico     # Application icon
├── src/                # Application source code
│   ├── components/     # Reusable React components
│   ├── services/       # API integration and business logic
│   ├── utils/          # Helper functions and utilities
│   ├── App.js          # Root application component
│   └── index.js        # Application entry point
├── .github/            # GitHub workflows and CI/CD
│   └── workflows/      # Automated deployment pipelines
├── package.json        # Dependencies and scripts
├── tailwind.config.js  # Tailwind CSS configuration
└── README.md          # Project documentation
```

## Available Scripts

### `npm start`
Runs the development server on port 3000 with hot-reload enabled.

### `npm run build`
Creates an optimized production build in the `build/` directory.

### `npm test`
Launches the test runner in interactive watch mode.

### `npm run eject`
**Warning:** This is a one-way operation. Ejects from Create React App to expose all configuration files.

## Deployment

### Automated Deployment

The project uses GitHub Actions for automated blue-green deployments. Deployments are triggered automatically when code is pushed to the `release` branch.

The deployment pipeline includes:
- Automated dependency installation
- Production build generation
- Zero-downtime deployment strategy
- Health checks and verification
- Automated rollback on failure

### Manual Deployment

For manual deployments:

1. Build the production application:
```bash
npm run build
```

2. Deploy the contents of the `build/` directory to your web server

3. Ensure your web server is configured for single-page application (SPA) routing:
   - All routes should serve `index.html`
   - Static assets should be cached appropriately
   - Proper MIME types should be configured

### Environment Configuration

Production deployments require proper environment variable configuration:

```env
# API Configuration
REACT_APP_API_URL=<production-api-url>

# Build Configuration (optional)
GENERATE_SOURCEMAP=false
CI=false
```

## Integration with Backend

### API Communication

The frontend communicates with the CipherBank backend API through RESTful endpoints. All requests include:

- **Authentication**: JWT token in Authorization header
- **Content Type**: JSON for request/response bodies
- **Error Handling**: Standardized error response format

### Authentication Flow

1. User submits credentials via login form
2. Frontend sends POST request to `/api/auth/login`
3. Backend validates credentials and returns JWT token
4. Frontend stores token securely
5. All subsequent API requests include token in Authorization header
6. Token automatically refreshes before expiration

### Security Considerations

- JWT tokens are stored securely
- Sensitive data is never logged or exposed
- HTTPS is enforced for all API communication
- CORS is properly configured for production domains

## Browser Support

Production builds are optimized for:
- Modern browsers (>0.2% market share)
- No support for Internet Explorer
- Automatic polyfills for required features

Development builds target:
- Latest Chrome version
- Latest Firefox version
- Latest Safari version

## Performance Optimization

The application implements several performance optimizations:

- **Code Splitting**: Dynamic imports for route-based code splitting
- **Asset Optimization**: Minified JavaScript and CSS bundles
- **Tree Shaking**: Removal of unused code
- **Lazy Loading**: Components loaded on demand
- **Caching**: Appropriate cache headers for static assets
- **Bundle Analysis**: Regular monitoring of bundle sizes

## Development Guidelines

### Code Style

- Follow React best practices and hooks guidelines
- Use functional components with hooks over class components
- Implement proper prop validation
- Maintain consistent code formatting

### Component Development

- Keep components small and focused
- Implement proper error boundaries
- Use meaningful component and variable names
- Document complex logic with comments

### State Management

- Use React hooks for local component state
- Implement context for shared application state
- Avoid prop drilling through multiple component levels

### API Integration

- Centralize API calls in service modules
- Implement proper error handling
- Use loading states for async operations
- Handle network failures gracefully

## Troubleshooting

### Build Failures

If the build fails:
1. Clear node_modules and package-lock.json
2. Run `npm install` to reinstall dependencies
3. Check Node.js version compatibility
4. Review build error messages for specific issues

### Development Server Issues

If the development server fails to start:
1. Ensure port 3000 is available
2. Check for conflicting processes
3. Clear browser cache and restart server
4. Verify environment variables are properly configured

### API Connection Issues

If API requests fail:
1. Verify backend API is running and accessible
2. Check REACT_APP_API_URL environment variable
3. Ensure CORS is properly configured on backend
4. Verify JWT token is valid and not expired

## Contributing

### Internal Development Process

1. Create a feature branch from `main`
2. Implement changes following code guidelines
3. Write/update tests for new functionality
4. Submit pull request with detailed description
5. Address code review feedback
6. Merge to `main` after approval
7. Deploy to staging for QA verification
8. Promote to `release` branch for production deployment

### Code Review Requirements

- All code must pass linting checks
- Test coverage must be maintained
- Performance impact must be considered
- Security implications must be reviewed
- Documentation must be updated

## License

Copyright 2024 The PayTrix. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software, via any medium, is strictly prohibited.

## Support

For internal support and questions:
- Contact the development team through internal communication channels
- Review project documentation and API specifications
- Check deployment logs for production issues
- Escalate critical issues to project managers

## Acknowledgments

Built and maintained by The PayTrix development team.

---

**The PayTrix** - Enterprise Financial Solutions