import { isEqual as ipIsEqual } from 'ip';
import { unauthorized } from 'boom';
import pkg from '../package.json';

export const plugin = {
	name: pkg.name,
	version: pkg.version,
	pkg,
	register(server:any, options:object) {
		server.auth.scheme('ip-whitelist', ipWhitelistScheme)
	}
};

function ipWhitelistScheme(server:any, whitelisted: string[]) {
	return {
		authenticate(request:any, h:any) {
			const { remoteAddress } = request.info;

			const list = whitelisted instanceof Array ? whitelisted : [whitelisted];
			if (list.some(ip => ipIsEqual(ip, remoteAddress))) {
				return h.authenticated({ credentials: remoteAddress })
			}

			throw unauthorized(`${remoteAddress} is not a valid IP`)
		}
	}
}

