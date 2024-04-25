
def "http auth digest" [--username(-u): string, --password(-p): string, url: string]:  {
	def gen_ha1 [
	    --user(-u): string	# Docs
	    --realm(-r): string	# Docs
	    --password(-r): string	# Docs
	] {
		[$user, $realm, $password]| str join ':' | hash md5 
	}
	def gen_ha2 [
	    --method(-m): string	# Docs
	    --uri(-u): string	# Docs
	] {
		[$method, $uri]| str join ':' | hash md5 
	}
	def gen_response [
		--ha1: string
		--nonce: string
		--nc: string
		--cnonce: string
		--qop: string
		--ha2: string
	] {
		[$ha1,$nonce,$nc,$cnonce,$qop,$ha2]| str join ':' | hash md5 
	}
	let resp = http get --full -e $url
	let auth_req_h = $resp.headers.response | transpose --header-row --as-record | get www-authenticate 
	let auth_v = $auth_req_h | parse -r 'Digest realm="(?<realm>[^"]+).+ qop="(?<qop>[^"]+)".+ nonce="(?<nonce>[^"]+)' | get 0
	let realm = $auth_v.realm
	let method = "GET"
	let qop = $auth_v.qop
	let uri = $url | url parse | get path
	let ha1 = gen_ha1 --user $username --realm $realm --password $password
	let ha2 = gen_ha2 --method $method --uri $uri 
	let nc = "00000001"
	let cnonce = random chars -l 32
	let response = gen_response --ha1 $ha1 --nonce $auth_v.nonce --nc $nc --cnonce $cnonce --qop $qop --ha2 $ha2
	let hh1 = { username: $username, realm: $realm, nonce: $auth_v.nonce, uri: $uri, qop: $auth_v.qop, nc: $nc, cnonce: $cnonce, response: $response }
	let auth_header = $'Digest username="($username)", realm="($realm)", nonce="($auth_v.nonce)", uri="($uri)", cnonce="($cnonce)", nc=($nc), qop=($qop), response="($response)"'
	['Authorization',($auth_header) ]
}

# Usage:
#
# let username = "My username"
# let password = "My password"
# let full_url = "https://example.com/foo"
# 
# let auth_h = http auth digest -u $username -p $password $full_url
# http get -e --full  --headers $auth_h $full_url

