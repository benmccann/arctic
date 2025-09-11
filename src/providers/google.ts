import { OAuth2Client, CodeChallengeMethod } from "../client.js";
import type { OAuth2Provider, OAuth2AuthorizationOptions, OAuth2ValidationOptions } from "../provider.js";

import type { OAuth2Tokens } from "../oauth2.js";

const authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
const tokenEndpoint = "https://oauth2.googleapis.com/token";
const tokenRevocationEndpoint = "https://oauth2.googleapis.com/revoke";

export class Google implements OAuth2Provider<["state", "codeVerifier", "scopes"], ["code", "codeVerifier"]> {
	private client: OAuth2Client;

	constructor(clientId: string, clientSecret: string, redirectURI: string) {
		this.client = new OAuth2Client(clientId, clientSecret, redirectURI);
	}

	public createAuthorizationURL(options: Pick<OAuth2AuthorizationOptions, "state" | "codeVerifier" | "scopes">): URL {
		const { state, codeVerifier, scopes = [] } = options;
		if (!state) throw new Error("state is required");
		if (!codeVerifier) throw new Error("codeVerifier is required");
		const url = this.client.createAuthorizationURLWithPKCE(
			authorizationEndpoint,
			state,
			CodeChallengeMethod.S256,
			codeVerifier,
			scopes
		);
		return url;
	}

	public async validateAuthorizationCode(options: Pick<OAuth2ValidationOptions, "code" | "codeVerifier">): Promise<OAuth2Tokens> {
		const { code, codeVerifier } = options;
		if (!code) throw new Error("code is required");
		if (!codeVerifier) throw new Error("codeVerifier is required");
		const tokens = await this.client.validateAuthorizationCode(tokenEndpoint, code, codeVerifier);
		return tokens;
	}

	public async refreshAccessToken(refreshToken: string): Promise<OAuth2Tokens> {
		const tokens = await this.client.refreshAccessToken(tokenEndpoint, refreshToken, []);
		return tokens;
	}

	public async revokeToken(token: string): Promise<void> {
		await this.client.revokeToken(tokenRevocationEndpoint, token);
	}
}
