require 'rubygems'
require 'rack'

private_key = "secret"

simple_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, "Smart app: Success!\n"] }

config = {
  :mauth_baseurl => 'http://mauth-sandbox.imedidata.net',

  # NB: private_key and app_uuid enable local authentication.
  # They'll only work if the app_uuid can request private keys in MAuth.
  # Authentication won't work if they're provided and the app doesn't have permission in MAuth to request private keys
  :private_key => %{-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDdRAQhVoJhu2vxDB7vOKf8Ul7NDXuyTgqJ8yKaX5pVBvqQqxow
xC8KI8CXfFs3a49u/5g4OT8EO5nznnb3h6o+5fmveh0tHRSLeD/6kOhxHL9awZ3J
7+Fe5U/H+IiXkLO+9k9PIqeYI/CbeoE0D14519cGcoj2miT98B/NB9mCSwIDAQAB
AoGAM9Fd9kDAQAsYeFcSV4u5K4pO0U67DULhjPT3wZdqGUeNHpwzggAv0/wTemaR
JiV2bdRF3cTqUR90Km2OBuIqqCjHIswvSrMoBXRZ+fZvjRBB9V4yf9XFldDQ1hOC
3wepFwo97o1Pypcx6ZxVyZzy0w89ixGljRE+hIj+OApYtYECQQD0n7fV4uGKvakk
CnD1RkpWDGi+Oc1r2vXTdRLynQYoek3vnUTFGBM+MkpbmvvBZ3lGIEEFVQ7L8TcL
vhHanG8xAkEA5443GjfpdEVCmRKJzR0OSybxNcP1+QavJrFtOlhpIirrIfedbSI8
QfC+Kx5ubz/PJWtXJ2eROX40lgIKB2WCOwJAWehF8ceUa6CvhL6Nq6gs9BlVeezW
sjhkt1ZFI4RQ2hmxgUrFFsd1cxuatrZspzW3ne2G2EXdzVkXiSpPd5CdUQJBAL8I
gUVMI3odOdh3huCFvCkcM5wb025jqVTOxEKCdhoONnaLhoFm4Te1me6Q6KM3jXpd
mEWWGCXKjS/E9ukrQckCQB9C90w0Qzg4/9r8E6jTWwQqrlWACjaSR9/jb2zTDWEZ
+dpB68jwzWYOc8EkHKA9UblB2cgDL3/1H55Ol0xnAc8=
-----END RSA PRIVATE KEY-----
},
  :app_uuid => '550e8400-e29b-41d4-a716-446655440000'
}

$: << 'lib'
require 'rack/mauth'

require 'ruby-debug'

use Medidata::MAuthMiddleware, config
run simple_app

