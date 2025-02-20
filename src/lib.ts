// index.ts - Main integration file
import { WebAuthnService } from "./webAuthnService";
import { KeyDerivationService } from "./keyDerivationService";
import { LocalDBService } from "./localDBService";

const domainNameId = "localhost";

// Helper functions to convert ArrayBuffer to Base64 and vice versa.
function arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

export async function main(): Promise<void> {
    document.getElementById("registerBtn")?.addEventListener("click", async () => {
        const webAuthnService = new WebAuthnService();
    
        const regOptions: PublicKeyCredentialCreationOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)).buffer,
            rp: { name: "Localhost, Inc", id: domainNameId },
            user: {
                // Use a secure, unique identifier for the user.
                id: crypto.getRandomValues(new Uint8Array(16)),
                name: "user@example.com",
                displayName: "User Example",
            },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 }, // ES256
                { type: "public-key", alg: -257 } // RS256
            ],
            timeout: 60000,
            authenticatorSelection: {
                authenticatorAttachment: "cross-platform",
                residentKey: "required",
            },
            extensions: {
                prf: { eval: { first: new Uint8Array(32).fill(1) } }, // Use a proper salt in production.
            },
        };
    
        try {
            const registration = await webAuthnService.register(regOptions);
            console.log("Credential registered:", registration.credentialId);
            // Convert credentialId (ArrayBuffer) to Base64 string and store in local storage.
            const credentialIdBase64 = arrayBufferToBase64(registration.credentialId);
            localStorage.setItem("credentialId", credentialIdBase64);
        } catch (error) {
            console.error("Error in process:", (error as Error).message);
            document.getElementById("error")!.textContent = (error as Error).message;
        }
    });
    
    document.getElementById("authenticateBtn")?.addEventListener("click", async () => {
        const webAuthnService = new WebAuthnService();
        const keyService = new KeyDerivationService();
        const localDB = new LocalDBService();
    
        // Retrieve the credentialId from local storage.
        const storedCredentialIdBase64 = localStorage.getItem("credentialId");
        if (!storedCredentialIdBase64) {
            console.error("No stored credentialId found.");
            document.getElementById("error")!.textContent = "No stored credentialId found.";
            return;
        }
        const storedCredentialId: ArrayBuffer = base64ToArrayBuffer(storedCredentialIdBase64);
    
        const authOptions: PublicKeyCredentialRequestOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)).buffer,
            allowCredentials: [{
                type: "public-key",
                id: storedCredentialId,
                //transports: ["usb", "nfc", "ble", "internal"],
            }],
            timeout: 60000,
            rpId: domainNameId,
            extensions: {
                prf: { eval: { first: new Uint8Array(32).fill(1) } }, // Use consistent salt as registration.
            },
        };
    
        try {
            const assertion = await webAuthnService.authenticate(authOptions);
            console.log("PRF output received:", assertion.prfResult);
    
            // Derive a symmetric encryption key from the PRF result.
            const encryptionKey = await keyService.deriveKey(assertion.prfResult);
            console.log("Symmetric key derived.");
    
            // Encrypt and decrypt sample data (e.g., for a local SQLite DB).
            const sampleData = "Sensitive Data for SQLite DB";
            const encryptedData = await localDB.encryptData(sampleData, encryptionKey);
            console.log("Encrypted data:", new Uint8Array(encryptedData));
    
            const decryptedData = await localDB.decryptData(encryptedData, encryptionKey);
            console.log("Decrypted data:", decryptedData);
        } catch (error) {
            console.error("Error in process:", (error as Error).message);
            document.getElementById("error")!.textContent = (error as Error).message;
        }
    });
}
