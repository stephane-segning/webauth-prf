// keyDerivationService.ts
export interface EncryptionKey {
    key: CryptoKey;
}

export class KeyDerivationService {
    async deriveKey(prfOutput: Uint8Array): Promise<EncryptionKey> {
        try {
            // Import the raw PRF output as a base key for HKDF.
            const baseKey = await crypto.subtle.importKey(
                "raw",
                prfOutput,
                { name: "HKDF" },
                false,
                ["deriveKey"]
            );

            // Derive a 256-bit AES-GCM key using HKDF.
            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    // Use a secure, application-specific salt (store/manage appropriately).
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    // Use context-specific info if needed.
                    info: new Uint8Array([1, 2, 3, 4]),
                },
                baseKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );

            return { key: derivedKey };
        } catch (error) {
            throw new Error(`Key derivation error: ${(error as Error).message}`);
        }
    }
}
