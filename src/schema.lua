return {
    fields = {
        client_id = { type = "string", default = "012345678910-1a23b4c5dfg6hij78k9101lmn12opq3r.apps.googleusercontent.com", required = true },
        client_secret = { type = "string", default = "ABC-dEfghijkLmnOPqr_rst-", required = true },
        jwt_validity = { type = "number", default = 86400, required = true },
        secure_cookies = { type = "boolean", default =false, required = true },
        http_only_cookies = { type = "boolean", default = false, required = true },
        issuer = { type = "string", default = nil, required = false },
        cb_uri = { type = "string", default = "/_oauth", required = false },
    }
}
