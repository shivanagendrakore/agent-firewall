/**
 * Popular RubyGems names for the typosquat check.
 *
 * Source: seed list, hand-picked from widely used gems (the most downloaded
 * names).
 * Date: 2026-10-09.
 * Replace at release with `node scripts/gen-popular.mjs` (the final source is
 * still to be chosen).
 */

import { names } from "./names.js";

export const RUBYGEMS = {
  source: "seed: hand-picked widely used gems (regenerate with scripts/gen-popular.mjs)",
  date: "2026-10-09",
  targets: names(`
    rails rake bundler rack rack-test rspec rspec-core rspec-expectations rspec-mocks rspec-support rspec-rails activesupport activerecord actionpack
    actionview activemodel railties actionmailer activejob nokogiri json thor i18n tzinfo concurrent-ruby minitest puma sidekiq devise pry byebug
    rubocop rubocop-rails faraday httparty rest-client aws-sdk-core aws-sdk-s3 mime-types multi_json builder erubi mail capybara selenium-webdriver
    webmock factory_bot factory_bot_rails faker sprockets jquery-rails turbolinks bootsnap listen spring mysql2 sqlite3 redis unicorn sinatra
    jwt bcrypt addressable public_suffix racc rexml zeitwerk crass loofah rails-html-sanitizer nio4r websocket-driver kaminari pundit cancancan
  `),
  known: names(`
    pg oj ffi vcr sass sassc rack-cors rack-attack rspec-its rubocop-ast rubocop-rspec rubocop-performance actiontext actioncable activestorage
    nokogumbo json-schema thor-zsh_completion
  `),
};
