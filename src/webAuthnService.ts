export interface CredentialRegistration {
    credentialId: ArrayBuffer;
    rawCredential: PublicKeyCredential;
}

export interface CredentialAssertion {
    assertion: PublicKeyCredential;
    prfResult: Uint8Array;
}

export class WebAuthnService {
    // Triggered by a user gesture (e.g. button click)
    async register(options: PublicKeyCredentialCreationOptions): Promise<CredentialRegistration> {
        try {
            const rawCredential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential;
            if (!rawCredential || !rawCredential.rawId) {
                throw new Error("Registration failed: No credential returned.");
            }
            return { credentialId: rawCredential.rawId, rawCredential };
        } catch (error) {
            throw new Error(`Registration error: ${(error as Error).message}`);
        }
    }

    async authenticate(options: PublicKeyCredentialRequestOptions): Promise<CredentialAssertion> {
        try {
            const assertion = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential;
            if (!assertion) {
                throw new Error("Authentication failed: No assertion returned.");
            }
            // Extract the PRF output from extension results.
            const clientExtResults = (assertion as any).getClientExtensionResults();
            if (!clientExtResults?.prf?.results?.first) {
                throw new Error("PRF result missing in the assertion.");
            }
            const prfResult: Uint8Array = new Uint8Array(clientExtResults.prf.results.first);
            return { assertion, prfResult };
        } catch (error) {
            throw new Error(`Authentication error: ${(error as Error).message}`);
        }
    }
}
