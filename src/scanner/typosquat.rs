use strsim::levenshtein;

static TOP_PACKAGES: &[&str] = &[
    "lodash", "react", "react-dom", "express", "chalk", "commander", "axios",
    "moment", "webpack", "typescript", "eslint", "prettier", "babel-core",
    "babel-loader", "jest", "mocha", "chai", "sinon", "nodemon", "dotenv",
    "cors", "body-parser", "mongoose", "sequelize", "knex", "pg", "mysql2",
    "redis", "socket.io", "ws", "uuid", "async", "bluebird", "request",
    "superagent", "got", "node-fetch", "cross-fetch", "rxjs", "ramda",
    "underscore", "immer", "zustand", "mobx", "redux", "react-redux",
    "@reduxjs/toolkit", "recoil", "jotai", "valtio", "next", "nuxt", "gatsby",
    "vue", "@vue/cli", "svelte", "angular", "@angular/core", "storybook",
    "tailwindcss", "styled-components", "emotion", "@emotion/react",
    "material-ui", "@mui/material", "antd", "bootstrap", "bulma",
    "rollup", "vite", "parcel", "esbuild", "turbopack", "swc",
    "ts-node", "tsx", "tsup", "tsc-watch", "ts-jest",
    "prettier-plugin-tailwindcss", "eslint-config-prettier",
    "husky", "lint-staged", "commitizen", "semantic-release",
    "lerna", "nx", "turborepo", "pnpm",
    "sharp", "jimp", "canvas", "pdf-lib",
    "date-fns", "dayjs", "luxon",
    "zod", "yup", "joi", "class-validator",
    "winston", "pino", "bunyan", "morgan",
    "passport", "jsonwebtoken", "bcrypt", "bcryptjs",
    "multer", "busboy", "formidable",
    "cheerio", "puppeteer", "playwright", "selenium-webdriver",
    "csv-parse", "papaparse", "xlsx",
    "aws-sdk", "@aws-sdk/client-s3", "firebase", "@google-cloud/storage",
    "stripe", "paypal-rest-sdk",
    "graphql", "apollo-server", "apollo-client", "@apollo/client",
    "prisma", "@prisma/client", "typeorm", "mikro-orm",
    "fastify", "koa", "hapi", "restify", "feathers",
    "pm2", "forever", "cross-env", "concurrently",
    "rimraf", "mkdirp", "glob", "chokidar", "fs-extra", "archiver",
    "mime", "mime-types", "content-type",
    "qs", "querystring", "path-to-regexp", "url-pattern",
    "semver", "node-semver", "check-dependencies",
    "debug", "trace", "source-map-support",
    "colors", "ora", "inquirer", "cli-progress", "boxen", "figlet",
    "yargs", "minimist", "meow", "caporal",
    "lodash-es", "lodash.get", "lodash.set", "lodash.merge",
    "string-width", "strip-ansi", "wrap-ansi",
    "through2", "readable-stream", "concat-stream",
    "tar", "tar-stream", "node-tar", "adm-zip", "jszip",
    "crypto-js", "node-forge", "elliptic", "tweetnacl",
    "xml2js", "fast-xml-parser", "xmlbuilder",
    "toml", "ini", "dotenv-expand",
    "nanoid", "cuid", "shortid",
    "classnames", "clsx",
    "react-router", "react-router-dom", "react-query",
    "@tanstack/react-query", "@tanstack/react-table",
    "react-hook-form", "formik", "final-form",
    "react-spring", "framer-motion", "gsap",
    "d3", "chart.js", "recharts", "highcharts",
    "three", "babylon", "pixi.js",
    "socket.io-client", "ably", "pusher-js",
    "marked", "marked-terminal", "remark", "rehype",
    "prismjs", "highlight.js", "shiki",
    "handlebars", "ejs", "pug", "mustache", "nunjucks",
    "node-cron", "agenda", "bull", "bullmq",
    "nodemailer", "sendgrid", "mailgun-js",
    "twilio", "vonage",
    "openai", "@anthropic-ai/sdk", "cohere-ai",
    "tensorflow", "@tensorflow/tfjs",
    "brain.js", "natural", "compromise",
    "serialize-javascript", "flatted",
    "object-hash", "deep-equal", "fast-deep-equal",
    "p-limit", "p-queue", "p-map", "p-retry",
    "execa", "cross-spawn", "which",
    "portfinder", "detect-port", "http-proxy",
    "compression", "helmet", "csurf", "express-rate-limit",
    "cookie-parser", "express-session",
    "connect-redis", "express-mongo-sanitize",
    "socket.io-adapter", "socket.io-redis",
    "kafka-node", "kafkajs", "amqplib", "nats",
    "grpc", "@grpc/grpc-js", "protobufjs",
    "reflect-metadata", "inversify", "tsyringe",
    "class-transformer", "class-validator",
    "config", "nconf", "convict",
    "prom-client", "hot-shots", "datadog-metrics",
    "dd-trace", "newrelic", "elastic-apm-node",
    "jest-circus", "vitest", "@testing-library/react",
    "@testing-library/jest-dom", "cypress", "playwright",
];

#[derive(Debug)]
pub struct TyposquatResult {
    pub is_suspect: bool,
    pub closest_match: Option<String>,
    pub edit_distance: usize,
}

pub fn check(package_name: &str) -> TyposquatResult {
    let name = package_name.split('@').next().unwrap_or(package_name);

    if TOP_PACKAGES.contains(&name) {
        return TyposquatResult {
            is_suspect: false,
            closest_match: None,
            edit_distance: 0,
        };
    }

    let mut best_distance = usize::MAX;
    let mut best_match: Option<&str> = None;

    for &top in TOP_PACKAGES {
        let dist = levenshtein(name, top);
        if dist < best_distance {
            best_distance = dist;
            best_match = Some(top);
        }
        if best_distance == 1 {
            break;
        }
    }

    let is_suspect = best_distance <= 2;

    TyposquatResult {
        is_suspect,
        closest_match: if is_suspect {
            best_match.map(str::to_string)
        } else {
            None
        },
        edit_distance: best_distance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_lodash_typo() {
        let result = check("1odash");
        assert!(result.is_suspect);
        assert_eq!(result.closest_match.as_deref(), Some("lodash"));
    }

    #[test]
    fn known_package_is_not_suspect() {
        let result = check("lodash");
        assert!(!result.is_suspect);
    }

    #[test]
    fn unrelated_package_is_not_suspect() {
        let result = check("my-very-unique-internal-tool-xyz");
        assert!(!result.is_suspect);
    }

    #[test]
    fn react_typo_detected() {
        let result = check("reect");
        assert!(result.is_suspect);
    }
}
