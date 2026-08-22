FROM node:22-alpine

RUN node -v
RUN npm -v

WORKDIR /app/backend

RUN apk add --update --no-cache autoconf bash libtool automake python3 py3-pip alpine-sdk openssh-keygen yarn nano

RUN yarn global add pm2

ADD docker/ecosystem.config.js /app/backend

# Install packages first so that Docker doesn't run `yarn install` if the packages haven't changed.
# The APDM/ADSP SemApps compatibility patchers must be present before dependency installation so production images
# patch the exact pinned SemApps artifacts and fail closed if their reviewed contracts drift.
# See https://making.close.com/posts/reduce-docker-image-size
ADD backend/package.json /app/backend
ADD backend/yarn.lock /app/backend
ADD backend/scripts/patch-semapps-activitypub-local-delivery.js /app/backend/scripts/patch-semapps-activitypub-local-delivery.js
ADD backend/scripts/patch-semapps-activitypub-local-delivery-phase9.js /app/backend/scripts/patch-semapps-activitypub-local-delivery-phase9.js
ADD backend/scripts/patch-semapps-activitypub-remote-actor-fetch.js /app/backend/scripts/patch-semapps-activitypub-remote-actor-fetch.js
ADD backend/scripts/patch-semapps-crypto-hs2019-verification.js /app/backend/scripts/patch-semapps-crypto-hs2019-verification.js
ADD backend/scripts/patch-semapps-ldp-local-registry-bootstrap.js /app/backend/scripts/patch-semapps-ldp-local-registry-bootstrap.js
ADD backend/scripts/patch-semapps-ldp-special-endpoint-race.js /app/backend/scripts/patch-semapps-ldp-special-endpoint-race.js
ADD backend/scripts/patch-semapps-jsonld-distributed-context-cache.js /app/backend/scripts/patch-semapps-jsonld-distributed-context-cache.js
ADD backend/scripts/patch-semapps-ontologies-distributed-cache.js /app/backend/scripts/patch-semapps-ontologies-distributed-cache.js
ADD backend/scripts/patch-semapps-jsonld-distributed-locality.js /app/backend/scripts/patch-semapps-jsonld-distributed-locality.js
ADD backend/scripts/patch-semapps-ldp-distributed-semantic-locality.js /app/backend/scripts/patch-semapps-ldp-distributed-semantic-locality.js
ADD backend/scripts/patch-semapps-ldp-same-document-fragments.js /app/backend/scripts/patch-semapps-ldp-same-document-fragments.js
RUN yarn install && yarn cache clean

ADD backend /app/backend

EXPOSE 3000

CMD [ "pm2-runtime", "ecosystem.config.js" ]
