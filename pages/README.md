# Pahlevan GitHub Pages

This directory contains the GitHub Pages website for the Pahlevan project.

## Structure

```
pages/
├── index.html           # Main landing page
├── docs.html           # Documentation portal
├── charts.html         # Helm charts listing
├── assets/             # Static assets
│   ├── css/           # Stylesheets
│   ├── js/            # JavaScript
│   └── *.svg          # Icons and images
├── charts/            # Helm repository
│   └── index.yaml     # Chart index
└── README.md          # This file
```

## Features

### 🏠 Landing Page (`index.html`)
- Modern, responsive design
- Interactive terminal demo
- Feature showcase
- Quick installation guides
- Links to documentation and charts

### 📚 Documentation Portal (`docs.html`)
- References existing documentation in `../docs/`
- Organized by categories
- Quick reference section
- Links to GitHub source

### Package Helm Charts (`charts.html`)
- Chart listing and metadata
- Installation instructions
- Configuration examples
- Links to chart source code

## Integration with Repository

The GitHub Pages site integrates with the main repository:

- **Documentation**: Links to markdown files in `docs/`
- **Helm Charts**: References charts in `charts/`
- **Releases**: Automated updates from GitHub releases
- **CI/CD**: Deployed via `.github/workflows/pages.yml`

## Local Development

1. **Serve locally**:
   ```bash
   # Simple HTTP server
   cd pages/
   python3 -m http.server 8000

   # Or with Node.js
   npx http-server -p 8000

   # Or with PHP
   php -S localhost:8000
   ```

2. **Open in browser**:
   ```
   http://localhost:8000
   ```

## Deployment

The site is automatically deployed when:
- Changes are pushed to `main` branch in `pages/`, `docs/`, or `charts/` directories
- A new release is published
- Manually triggered via GitHub Actions

### Deployment Process

1. **Build**: Copy pages content and generate Helm index
2. **Validate**: Basic HTML and link validation
3. **Deploy**: GitHub Pages deployment
4. **Notify**: Slack notification on success

## Customization

### Styling
- Edit `assets/css/main.css` for styling changes
- Uses CSS custom properties for theming
- Mobile-first responsive design

### Content
- **Homepage**: Edit `index.html`
- **Documentation**: Edit `docs.html` or add new pages
- **Charts**: Edit `charts.html`

### Navigation
- Update navigation links in each HTML file
- Consistent header/footer across pages

## Helm Repository

The site serves as a Helm repository at:
- **Repository URL**: `https://obsernetics.github.io/pahlevan/`
- **Chart Index**: `https://obsernetics.github.io/pahlevan/charts/index.yaml`

### Adding Charts
Charts are automatically packaged and indexed from the `charts/` directory in the main repository.

## Performance

- **Lightweight**: Minimal dependencies, optimized assets
- **Fast Loading**: Efficient CSS and JavaScript
- **CDN**: Delivered via GitHub Pages CDN
- **Caching**: Proper cache headers for static assets

## SEO & Accessibility

- **Meta Tags**: Complete OpenGraph and Twitter Card metadata
- **Semantic HTML**: Proper heading structure and landmarks
- **Alt Text**: Images include descriptive alt text
- **Mobile**: Responsive design for all device sizes

## Monitoring

- **GitHub Insights**: Repository traffic and engagement
- **Performance**: Core Web Vitals monitoring
- **Uptime**: GitHub Pages uptime monitoring

## Contributing

1. Fork the repository
2. Make changes to files in `pages/`
3. Test locally
4. Submit a pull request

### Guidelines
- Maintain mobile responsiveness
- Follow existing design patterns
- Update navigation consistently
- Test all links and functionality

## Support

- **Issues**: [GitHub Issues](https://github.com/obsernetics/pahlevan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/obsernetics/pahlevan/discussions)
- **Documentation**: Links to `docs/` directory