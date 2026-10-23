# PC Reports image (ghcr.io/kstans/pc-reports), built by .github/workflows/pc-reports-image.yml.
# The code lives in the image so umbrelOS updates swap it by changing the image tag; umbrelOS does
# not replace files inside an installed app's folder on update.
FROM node:22-alpine
WORKDIR /app
COPY server.mjs ./
COPY lib ./lib
COPY templates ./templates
ENV PORT=8765 DATA_DIR=/data
# The node image's "node" user is uid 1000, which owns the Umbrel app-data folder.
USER node
EXPOSE 8765
CMD ["node", "server.mjs"]
