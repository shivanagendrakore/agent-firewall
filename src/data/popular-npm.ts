/**
 * Popular npm package names for the typosquat check.
 *
 * Source: seed list, hand-picked from widely used npm packages (the registry's
 * most-depended-upon and most-downloaded names).
 * Date: 2026-10-09.
 * Replace at release with `node scripts/gen-popular.mjs` (top 5,000 targets and
 * 20,000 known by downloads; the final source is still to be chosen).
 */

import { names } from "./names.js";

export const NPM = {
  source: "seed: hand-picked widely used npm packages (regenerate with scripts/gen-popular.mjs)",
  date: "2026-10-09",
  targets: names(`
    react react-dom react-is react-router react-router-dom react-native react-redux react-scripts preact next vue vue-router vuex pinia nuxt svelte angular
    @angular/core @angular/common @angular/cli @vue/cli @nestjs/core @nestjs/common @remix-run/react astro solid-js lit
    lodash lodash.merge lodash.debounce lodash.throttle lodash.get lodash.clonedeep lodash.isequal underscore ramda immutable immer
    express koa fastify hapi restify body-parser cookie-parser cors helmet morgan compression multer busboy formidable express-session
    axios node-fetch cross-fetch isomorphic-fetch got request superagent undici form-data tough-cookie
    chalk commander yargs minimist meow inquirer prompts enquirer ora boxen figlet colors color kleur picocolors ansi-colors cli-table3 listr
    debug semver uuid nanoid shortid moment moment-timezone dayjs date-fns luxon
    typescript ts-node tsx tslib @swc/core @babel/core @babel/preset-env @babel/preset-react @babel/preset-typescript @babel/cli @babel/runtime babel-loader babel-jest
    webpack webpack-cli webpack-dev-server rollup vite esbuild parcel terser uglify-js html-webpack-plugin css-loader style-loader sass-loader postcss-loader ts-loader file-loader url-loader mini-css-extract-plugin
    eslint tslint prettier @typescript-eslint/parser @typescript-eslint/eslint-plugin eslint-plugin-react eslint-plugin-react-hooks eslint-plugin-import eslint-config-prettier eslint-plugin-prettier eslint-config-airbnb stylelint
    jest mocha chai sinon vitest jasmine karma cypress playwright @playwright/test puppeteer supertest nock enzyme @testing-library/react @testing-library/jest-dom
    nodemon dotenv cross-env rimraf mkdirp glob globby fast-glob minimatch micromatch picomatch fs-extra graceful-fs chokidar del make-dir
    async bluebird rxjs eventemitter3 mitt p-limit p-map p-queue p-retry retry
    redux @reduxjs/toolkit redux-thunk redux-saga mobx zustand jotai recoil xstate
    classnames clsx styled-components @emotion/react @emotion/styled tailwindcss postcss autoprefixer sass less stylus bootstrap @mui/material antd
    jquery d3 three chart.js echarts leaflet socket.io socket.io-client ws
    mongoose mongodb mysql mysql2 sqlite3 better-sqlite3 sequelize typeorm prisma @prisma/client knex redis ioredis drizzle-orm
    jsonwebtoken bcrypt bcryptjs passport passport-jwt passport-local validator joi yup zod ajv qs query-string
    execa shelljs cross-spawn which open crypto-js js-yaml yaml xml2js fast-xml-parser cheerio jsdom marked markdown-it highlight.js prismjs
    handlebars ejs pug mustache nunjucks lru-cache node-cache sharp jimp canvas pdfkit archiver jszip adm-zip tar
    concurrently husky lint-staged @commitlint/cli semantic-release lerna nx turbo
    @types/node @types/react @types/react-dom @types/express @types/jest @types/lodash @types/mocha @types/uuid
    @tanstack/react-query swr graphql apollo-server @apollo/client graphql-tag electron expo
    firebase firebase-admin @supabase/supabase-js stripe aws-sdk @aws-sdk/client-s3 googleapis openai @anthropic-ai/sdk langchain @modelcontextprotocol/sdk
    discord.js telegraf twilio nodemailer winston pino bunyan log4js http-proxy-middleware http-proxy serve-static serve http-server live-server browser-sync
    gulp grunt bower yarn pnpm npm node-gyp node-sass core-js regenerator-runtime source-map source-map-support
    inherits safe-buffer readable-stream string_decoder once wrappy inflight brace-expansion balanced-match supports-color has-flag ansi-styles ansi-regex strip-ansi
    color-convert color-name escape-string-regexp signal-exit string-width wrap-ansi cliui camelcase decamelize deepmerge object-assign extend xtend
    kind-of is-number to-regex-range fill-range braces anymatch mime mime-types iconv-lite punycode whatwg-url
    vite-plugin-pwa @vitejs/plugin-react @sveltejs/kit esm dotenv-expand cookie
  `),
  known: names(`
    react-dom-factories reactstrap preact-render-to-string redux-logger
    tslint-config-prettier jsdoc jsdom-global inquire server semver-regex colorette chalk-template
    node-uuid uuid-random server-destroy yaml-js three-stdlib
    vitest-mock-extended jest-cli mocha-junit-reporter nodemon-webpack-plugin
    ajv-formats ajv-keywords zod-to-json-schema joi-browser yup-locales
    cookies cookie-signature execa-wrap open-cli globals globalthis
    lit-html lit-element vue-loader vue-template-compiler svelte-check svelte-preprocess
    tsc tsup tsd tsdx typedoc ts-jest ts-morph swc rome biome @biomejs/biome oxlint
    ws-browser websocket socks socks-proxy-agent proxy-agent https-proxy-agent http-proxy-agent agent-base
    mysql2-promise pg pg-pool pg-promise knex-migrate redis-parser redis-errors
    prisma-client drizzle-kit kysely
    esbuild-register esbuild-wasm rollup-plugin-terser terser-webpack-plugin
    picomatch-browser minimatch-browser micromatch-browser
    debug-log debuglog
    koa-router koa-body koa-static express-validator express-rate-limit
    graphql-request graphql-tools graphql-ws
    eslint-scope eslint-utils eslint-visitor-keys espree esquery esrecurse estraverse esutils
    prettier-plugin-tailwindcss stylelint-config-standard
    recharts
  `),
};
