local private_keys_file     = '/etc/kong/private_keys.json' -- hard coded to be loaded at init_work phase

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
local ngx_b64              = require("ngx.base64")

local read_file            = require("pl.file").read

local function load_private_keys(private_keys_file)
  local content, err = read_file(private_keys_file)
  if content == nil or err then
      ngx_log(ngx_ERR, "Could not read file contents. ", err)
      return nil, tostring(err)
  end

  local pkeys = json.decode(content)
  if not pkeys then
    ngx_log(ngx_ERR, "Could not get 'keys' object from " .. private_keys_file )
    return nil, "Could not get 'keys' object from " .. private_keys_file
  end

  local private_keys={}
  for k,v in pairs(pkeys) do
    private_keys[k]=ngx_b64.decode_base64url(v)
  end

  return private_keys
end
  
local private_keys, err_pk = load_private_keys(private_keys_file)
if err_pk then
  ngx_log(ngx_ERR,   ">>>>>>>>>>> BE CAREFUL: PRIVATE KEYS NOT LOADED CORRECTLY. THIS MAY CAUSE SOME UNEXPECTED 500 RETURNS. <<<<<<<<<<<")
end


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
    local cookie_name          = conf['cookie_name']
    local secure_cookies       = conf['secure_cookies']
    local http_only_cookies    = conf['http_only_cookies']
    local issuer               = conf['issuer'] or plugin_name
    local cb_uri               = conf['callback_uri'] or "/_oauth"
    local private_key_id       = conf['private_key_id']
    local ssl_verify           = conf['ssl_verify']
    local cb_scheme            = conf['callback_scheme'] or scheme
    local key                  = private_keys[private_key_id]
    local cb_server_name       = ngx.req.get_headers()["Host"]
    local cb_url               = cb_scheme .. "://" .. cb_server_name .. cb_uri
    local redirect_url         = cb_scheme .. "://" .. cb_server_name .. ngx.var.request_uri
    local initial_redirect_url = cb_url .. "?uri=" .. uri

    local function sign(claims, key, private_key_id)
        local headers={}
        headers['alg']='RS512'
        headers['typ']='JWT'
        headers['kid']=private_key_id
        h=encode_base64(json.encode(headers)):gsub("==$", ""):gsub("=$", "")
        local c = encode_base64(json.encode(claims)):gsub("==$", ""):gsub("=$", "")
        local data = h .. '.' .. c
        return data .. "." .. encode_base64(openssl_pkey.new(key):sign(openssl_digest.new("sha512"):update(data))):gsub("+", "-"):gsub("/", "_"):gsub("==$", ""):gsub("=$", "")
    end

    local function redirect_to_auth()
        return ngx.redirect("https://accounts.zoho.com/oauth/v2/auth?" .. ngx.encode_args({
            client_id     = client_id,
            scope         = "Aaaserver.profile.read",
            access_type   = "offline",
            redirect_uri  = cb_url,
            state         = redirect_url,
            response_type = "code"
        }))
    end

    local function request_access_token(code)
        local request = http.new()

        request:set_timeout(3000)

        local uri = "https://accounts.zoho.com/oauth/v2/token?" .. ngx.encode_args({
            code          = code,
            grant_type    = "authorization_code",
            client_id     = client_id,
            client_secret = client_secret,
            redirect_uri  = cb_url,
            scope         = "Aaaserver.profile.read",
        })
      
        local res, err = request:request_uri(uri , {
            method = "POST",
            headers = {
                ["Content-type"] = "application/x-www-form-urlencoded"
            },
            ssl_verify = ssl_verify,
        })
        if not res then
            return nil, (err or "auth token request failed: " .. (err or "unknown reason"))
        end

        if res.status ~= 200 then
            return nil, "received " .. res.status .. " from https://accounts.zoho.com/oauth/v2/auth: " .. res.body
        end

        return json.decode(res.body)
    end

    local function request_profile(token)
        local request = http.new()

        request:set_timeout(3000)

        local res, err = request:request_uri("https://accounts.zoho.com/oauth/user/info", {
            headers = {
              ["Authorization"] = "Zoho-oauthtoken " .. token,
            },
            ssl_verify = true,
        })
        if not res then
            return nil, "auth info request failed: " .. (err or "unknown reason")
        end

        if res.status ~= 200 then
            return nil, "received " .. res.status .. " from https://accounts.zoho.com/oauth/user/info"
        end

        return json.decode(res.body)
    end

    local function authorize()
        if redirect_url ~= (cb_url .. "?uri=" .. uri) then
            if uri_args["error"] then
                ngx_log(ngx_ERR, "received " .. uri_args["error"])
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local token, token_err = request_access_token(uri_args["code"])
            if not token then
                ngx_log(ngx_ERR, "got error during access token request: " .. token_err)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            -- local write = require('pl.pretty').write
            -- ngx_log(ngx_ERR, "\nToken: " .. write(token))

            local profile, profile_err = request_profile(token["access_token"])
            if not profile then
                ngx_log(ngx_ERR, "got error during profile request: " .. profile_err)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            -- ngx_log(ngx_ERR, "\nProfile: " .. write(profile))

            local claims={}

            claims["provider"] = 'zoho'
            claims["sub"] = profile["Email"]
            claims["display_name"] = profile["Display_Name"]
            claims["user"] = profile["Email"]:match("([^@]+)@.+")
            claims["domain"] = profile["Email"]:match("[^@]+@(.+)")
            claims["name"] = profile["First_Name"]
            claims["surname"] = profile["Last_Name"]
            claims["iss"] = issuer
            claims["iat"] = ngx.time()
            claims["exp"] = ngx.time() + jwt_validity

            local jwt = sign(claims,key,private_key_id)

            local expires      = ngx.time() + jwt_validity
            local cookie_tail  = ";version=1;path=/;Max-Age=" .. expires
            if secure_cookies then
                cookie_tail = cookie_tail .. ";secure"
            end
            if http_only_cookies then
                cookie_tail = cookie_tail .. ";httponly"
            end

            ngx.header["Set-Cookie"] = {
              cookie_name .. "=" .. jwt .. cookie_tail
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
