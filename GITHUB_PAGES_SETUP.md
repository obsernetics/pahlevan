# GitHub Pages Setup Guide

This guide explains how to enable and use the GitHub Pages integration for the Pahlevan project.

## 🎯 What I've Created

I've integrated a complete GitHub Pages website into your existing repository at `/pages/` that:

✅ **Uses existing documentation** from `docs/` directory
✅ **References existing Helm charts** from `charts/` directory
✅ **Integrates with existing CI/CD** workflows
✅ **Provides professional web presence** at `obsernetics.github.io/pahlevan`
✅ **Serves as Helm repository** for chart distribution

## 📁 Repository Structure

```
/home/reza/development/pahlevan/
├── pages/                    # 🆕 GitHub Pages website
│   ├── index.html           # Landing page
│   ├── docs.html            # Documentation portal
│   ├── charts.html          # Helm charts listing
│   ├── assets/              # CSS, JS, icons
│   │   ├── css/main.css
│   │   ├── js/main.js
│   │   └── pahlevan-icon.svg
│   ├── charts/
│   │   └── index.yaml       # Helm repository index
│   └── README.md
├── docs/                    # ✅ Existing documentation (referenced by pages)
│   ├── quick-start.md
│   ├── architecture.md
│   ├── deployment.md
│   └── ...
├── charts/                  # ✅ Existing Helm charts (referenced by pages)
│   └── pahlevan-operator/
├── .github/workflows/
│   ├── pages.yml           # 🆕 GitHub Pages deployment
│   ├── helm.yml            # ✅ Existing Helm workflow
│   └── release.yml         # ✅ Existing release workflow
└── GITHUB_PAGES_SETUP.md   # 🆕 This guide
```

## 🚀 How to Enable GitHub Pages

### 1. Configure Repository Settings

Go to your repository on GitHub:

```
https://github.com/obsernetics/pahlevan/settings/pages
```

**Configure GitHub Pages:**
- **Source**: Deploy from a branch → `gh-pages` (will be created automatically)
- **OR Source**: GitHub Actions (recommended)
- **Custom domain** (optional): `pahlevan.obsernetics.com`

### 2. Enable Workflows

The workflows are already created. Just commit and push:

```bash
cd /home/reza/development/pahlevan/

# Add all the new pages content
git add pages/
git add .github/workflows/pages.yml
git add GITHUB_PAGES_SETUP.md

# Commit the changes
git commit -m "feat: Add GitHub Pages website with Helm repository

- Add responsive landing page with interactive terminal demo
- Add documentation portal linking to existing docs
- Add Helm charts listing and repository
- Add automated deployment workflow
- Integrate with existing CI/CD pipelines"

# Push to trigger deployment
git push origin main
```

### 3. First Deployment

After pushing, the GitHub Pages workflow will:

1. **Build** the website from `pages/` directory
2. **Generate** Helm repository index from `charts/`
3. **Deploy** to `https://obsernetics.github.io/pahlevan/`
4. **Notify** via Slack (if webhook configured)

## 🔗 Site URLs

Once deployed, your site will be available at:

- **Homepage**: `https://obsernetics.github.io/pahlevan/`
- **Documentation**: `https://obsernetics.github.io/pahlevan/docs.html`
- **Helm Charts**: `https://obsernetics.github.io/pahlevan/charts.html`
- **Helm Repository**: `https://obsernetics.github.io/pahlevan/charts/index.yaml`

## 📦 Helm Repository Usage

Users can now add your Helm repository:

```bash
# Add repository
helm repo add pahlevan https://obsernetics.github.io/pahlevan/

# Update repositories
helm repo update

# Install Pahlevan
helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace
```

## 🔄 How It Integrates

### With Existing Documentation

The website **references** your existing documentation:
- Links point to `https://github.com/obsernetics/pahlevan/blob/main/docs/quick-start.md`
- Maintains single source of truth in `docs/` directory
- No duplication of content

### With Existing Helm Charts

The website **showcases** your existing charts:
- Charts listed from `charts/` directory
- Links to chart source code on GitHub
- Helm repository index generated from actual charts

### With Existing Workflows

The pages workflow **complements** existing workflows:
- Triggers on changes to `pages/`, `docs/`, or `charts/`
- Works with release workflow to update Helm repository
- Notifications integrate with existing Slack setup

## 🛠️ Local Development

Test the website locally:

```bash
cd /home/reza/development/pahlevan/pages/

# Simple HTTP server
python3 -m http.server 8000

# Open browser
open http://localhost:8000
```

## ✏️ Customization

### Update Content

- **Landing page**: Edit `pages/index.html`
- **Documentation**: Update `docs/*.md` files (referenced automatically)
- **Charts**: Update `charts/` directory (indexed automatically)
- **Styling**: Modify `pages/assets/css/main.css`

### Add New Pages

Create new HTML files in `pages/` and update navigation:

```html
<!-- Add to navigation in all pages -->
<a href="new-page.html" class="nav-link">New Page</a>
```

### Custom Domain (Optional)

If you have a custom domain:

1. Add CNAME record: `pahlevan.obsernetics.com → obsernetics.github.io`
2. Uncomment CNAME creation in `pages.yml`:
   ```yaml
   echo "pahlevan.obsernetics.com" > _site/CNAME
   ```

## 📊 Monitoring

Track your site performance:

- **GitHub Insights**: Repository → Insights → Traffic
- **GitHub Actions**: Monitor deployment status
- **Site Access**: Check `obsernetics.github.io/pahlevan`

## 🔧 Troubleshooting

### Deployment Fails

Check GitHub Actions logs:
```
https://github.com/obsernetics/pahlevan/actions
```

### Site Not Updating

1. Check if GitHub Pages is enabled in repository settings
2. Verify workflow permissions (needs `pages: write`)
3. Check if changes were pushed to `main` branch

### Helm Repository Issues

1. Verify charts have valid `Chart.yaml`
2. Check chart packaging in workflow logs
3. Test Helm repository manually:
   ```bash
   helm repo add test https://obsernetics.github.io/pahlevan/
   helm search repo test
   ```

## 🎉 What's Next

Your GitHub Pages site is now ready! Here's what happens automatically:

1. **Documentation updates** → Site reflects changes via links
2. **Chart updates** → Helm repository index updates
3. **Releases** → Chart packages published to repository
4. **Issues/PRs** → Community can easily find documentation

## 📞 Support

If you need help:

- **Workflow issues**: Check GitHub Actions logs
- **Site issues**: Test locally first
- **Content updates**: Edit files in `pages/`, `docs/`, or `charts/`
- **Questions**: GitHub Discussions or Issues

---

**Your professional Pahlevan website is ready! 🚀**

Visit: `https://obsernetics.github.io/pahlevan/` (after first deployment)