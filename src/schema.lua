return {
    fields = {
        client_id = { type = "string", default = "012345678910-1a23b4c5dfg6hij78k9101lmn12opq3r.apps.googleusercontent.com", required = true },
        client_secret = { type = "string", default = "ABC-dEfghijkLmnOPqr_rst-", required = true },
        jwt_validity = { type = "number", default = 86400, required = true },
        cookie_name = { type = "string", default = 'oauth_jwt', required = true },
        secure_cookies = { type = "boolean", default = true, required = true },
        http_only_cookies = { type = "boolean", default = true, required = true },
        issuer = { type = "string", default = 'Kong', required = false },
        callback_uri = { type = "string", default = "/_oauth", required = false },
        callback_scheme = { type = "string", default = nil, required = false },
        private_key_id = { type = "string", default = "00000000-0000-0000-0000-000000000000", required = true },
        ssl_verify = {type = "boolean", default=true, required=true}
    }
}
