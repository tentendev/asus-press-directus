FROM directus/directus:11.13.4

# Switch to root user to allow corepack enable
USER root

# Enable pnpm, which Directus uses internally for its build processes
RUN corepack enable

# Switch back to the non-root 'node' user (best practice)
USER node

# Set the working directory to the app root
WORKDIR /directus

# Copy your entire 'extensions' folder into the container
# Ensure you have a local 'extensions' folder with your source code and package.json files
COPY --chown=node:node ./extensions /directus/extensions

# Navigate into the main application directory and run build for all extensions
# This command iterates through all subdirectories in 'extensions', installs dependencies, and runs the 'build' script
RUN find extensions -mindepth 1 -maxdepth 1 -type d | xargs -P 8 -I {} sh -c 'cd {} && pnpm install && pnpm run build'