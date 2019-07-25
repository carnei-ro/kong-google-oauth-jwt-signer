local private_key_file     = '/etc/kong/private.pem' -- hard coded to be loaded at init_work phase

local BasePlugin = require "kong.plugins.base_plugin"

local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local json                 = require("cjson")
local http                 = require("resty.http")

local openssl_digest       = require "openssl.digest"
local openssl_pkey         = require "openssl.pkey"
local pl                   = require('pl.pretty')
local ngx_log              = ngx.log
local ngx_ERR              = ngx.ERR
local encode_base64        = ngx.encode_base64


local read_file            = require("pl.file").read

local function load_private_key(private_key_file)
    local content, err = read_file(private_key_file)
    if content == nil or err then
        ngx_log(ngx_ERR,   ">>>>>>>>>>> BE CAREFUL: PRIVATE KEYS NOT LOADED CORRECTLY. THIS MAY CAUSE SOME UNEXPECTED 500 RETURNS. <<<<<<<<<<<")
        return nil, tostring(err)
    end
    return content
end

local key = load_private_key(private_key_file)

local plugin = BasePlugin:extend()

function plugin:new()
    plugin.super.new(self, plugin_name)
end

function plugin:access(conf)
    plugin.super.access(self)
   
    local uri_args             = ngx.req.get_uri_args()
    
    local uri                  = uri_args['uri'] or ""
    local scheme               = ngx.var.scheme

    local client_id            = conf['client_id']
    local client_secret        = conf['client_secret']
    local jwt_validity         = conf['jwt_validity']
    local secure_cookies       = conf['secure_cookies']
    local http_only_cookies    = conf['http_only_cookies']
    local issuer               = conf['issuer'] or plugin_name
    local cb_uri               = conf['callback_uri'] or "/_oauth"
    local cb_server_name       = ngx.req.get_headers()["Host"]
    local cb_scheme            = ngx.var.callback_scheme or scheme
    local cb_url               = cb_scheme .. "://" .. cb_server_name .. cb_uri
    local redirect_url         = cb_scheme .. "://" .. cb_server_name .. ngx.var.request_uri
    local initial_redirect_url = cb_url .. "?uri=" .. uri

    local function sign(claims, key)
        local c = encode_base64(json.encode(claims)):gsub("==$", ""):gsub("=$", "")
        local data = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.' .. c
        return data .. "." .. encode_base64(openssl_pkey.new(key):sign(openssl_digest.new("sha512"):update(data))):gsub("+", "-"):gsub("/", "_"):gsub("==$", ""):gsub("=$", "")
    end

    local function redirect_to_auth()
        -- google seems to accept space separated domain list in the login_hint, so use this undocumented feature.
        return ngx.redirect("https://accounts.google.com/o/oauth2/auth?" .. ngx.encode_args({
            client_id     = client_id,
            scope         = "email",
            response_type = "code",
            redirect_uri  = cb_url,
            state         = redirect_url
        }))
        end

    local function request_access_token(code)
        local request = http.new()

        request:set_timeout(3000)

        local res, err = request:request_uri("https://accounts.google.com/o/oauth2/token", {
            method = "POST",
            body = ngx.encode_args({
            code          = code,
            client_id     = client_id,
            client_secret = client_secret,
            redirect_uri  = cb_url,
            grant_type    = "authorization_code",
            }),
            headers = {
            ["Content-type"] = "application/x-www-form-urlencoded"
            },
            ssl_verify = false,
        })
        if not res then
            return nil, (err or "auth token request failed: " .. (err or "unknown reason"))
        end

        if res.status ~= 200 then
            return nil, "received " .. res.status .. " from https://accounts.google.com/o/oauth2/token: " .. res.body
        end

        return json.decode(res.body)
    end

    local function request_profile(token)
        local request = http.new()

        request:set_timeout(3000)

        local res, err = request:request_uri("https://www.googleapis.com/oauth2/v2/userinfo", {
            headers = {
            ["Authorization"] = "Bearer " .. token,
            },
            ssl_verify = false,
        })
        if not res then
            return nil, "auth info request failed: " .. (err or "unknown reason")
        end

        if res.status ~= 200 then
            return nil, "received " .. res.status .. " from https://www.googleapis.com/oauth2/v2/userinfo"
        end

        return json.decode(res.body)
    end

    local function authorize()
        if redirect_url ~= (cb_url .. "?uri=" .. uri) then
            if uri_args["error"] then
                ngx_log(ngx_ERR, "received " .. uri_args["error"] .. " from https://accounts.google.com/o/oauth2/auth")
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local token, token_err = request_access_token(uri_args["code"])
            if not token then
                ngx_log(ngx_ERR, "got error during access token request: " .. token_err)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local profile, profile_err = request_profile(token["access_token"])
            if not profile then
                ngx_log(ngx_ERR, "got error during profile request: " .. profile_err)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local claims={}
            claims["sub"] = profile["email"]
            claims["iss"] = issuer
            claims["iat"] = ngx.time()
            claims["exp"] = ngx.time() + jwt_validity
            claims["user"] = profile["email"]:match("([^@]+)@.+")
            claims["domain"] = profile["email"]:match("[^@]+@(.+)")
            claims["verified_email"] = profile["verified_email"]
            claims["picture"] = profile["picture"]

            local jwt = sign(claims,key)

            local expires      = ngx.time() + jwt_validity
            local cookie_tail  = ";version=1;path=/;Max-Age=" .. expires
            if secure_cookies then
                cookie_tail = cookie_tail .. ";secure"
            end
            if http_only_cookies then
                cookie_tail = cookie_tail .. ";httponly"
            end

            ngx.header["Set-Cookie"] = {
                "jwt=" .. jwt .. cookie_tail
            }
           
            local m, err = ngx.re.match(uri_args["state"], "uri=(?<uri>.+)")

            if m then
                return ngx.redirect(m["uri"])
            else
                return ngx.exit(ngx.BAD_REQUEST)
            end
        end

        redirect_to_auth()
    end

    authorize()


end

plugin.PRIORITY = 1000
plugin.VERSION = "0.0-1"

return plugin