FROM node:18-alpine as BUILDER

WORKDIR /usr/src/app

COPY ./packages/common/prisma ./prisma

RUN npm init -y
RUN npm install prisma

CMD ["node_modules/.bin/prisma", "migrate", "deploy"]