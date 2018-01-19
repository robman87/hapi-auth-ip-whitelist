import { Request, Server, ServerOptions } from 'hapi';
import { isEqual as ipIsEqual } from 'ip';
import { unauthorized } from 'boom';
const pkg = require('../package.json');

export const plugin = {
	name: pkg.name,
	version: pkg.version,
	pkg,
	register(server:Server, options:ServerOptions) {
		server.auth.scheme('ip-whitelist', ipWhitelistScheme)
	}
};

function ipWhitelistScheme(server:Server, whitelisted:string[]) {
	return {
		authenticate(request:Request, h:any) {
			const { remoteAddress } = request.info;

			const list = whitelisted instanceof Array ? whitelisted : [whitelisted];
			if (list.some(ip => ipIsEqual(ip, remoteAddress))) {
				return h.authenticated({ credentials: remoteAddress })
			}

			throw unauthorized(`${remoteAddress} is not a valid IP`)
		}
	}
}

