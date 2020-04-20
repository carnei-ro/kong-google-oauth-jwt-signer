package = "kong-google-oauth-jwt-signer"
version = "0.0-3"

source = {
 url    = "git@bitbucket.org:leandro-carneiro/kong-google-oauth-jwt-signer.git",
 branch = "master"
}

description = {
  summary = "generate JWT when a google oauth flow is valid  ",
}

dependencies = {
  "lua ~> 5.1"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.kong-google-oauth-jwt-signer.schema"] = "src/schema.lua",
    ["kong.plugins.kong-google-oauth-jwt-signer.handler"] = "src/handler.lua",
  }
}