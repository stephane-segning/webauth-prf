import { WebAuthnService } from "./webAuthnService";
import { EncryptionKey, KeyDerivationService } from "./keyDerivationService";
import { LocalDBService } from "./localDBService";

const domainNameId = "localhost";

//  convert ArrayBuffer to Base64 and vice versa.
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

// Load messages from localStorage and display them
function loadMessages() {
    const messages = JSON.parse(localStorage.getItem("messages") || "[]");
    const messageList = document.querySelector("#messageList")!;
    messageList.innerHTML = messages.map((msg: string) => `<li>${msg}</li>`).join("");
}

// Save a message to localStorage
function saveMessage() {
    const input = document.querySelector<HTMLInputElement>("#messageInput")!;
    const message = input.value.trim();
    if (message) {
        const messages = JSON.parse(localStorage.getItem("messages") || "[]");
        messages.push(message);
        localStorage.setItem("messages", JSON.stringify(messages));
        input.value = "";
        loadMessages();
    }
}

// Register function
async function handleRegister(): Promise<void> {
    const webAuthnService = new WebAuthnService();
    
    const regOptions: PublicKeyCredentialCreationOptions = {
        challenge: crypto.getRandomValues(new Uint8Array(32)).buffer,
        rp: { name: "Localhost, Inc", id: domainNameId },
        user: {
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
            prf: { eval: { first: new Uint8Array(32).fill(1) } },
        },
    };

    try {
        const registration = await webAuthnService.register(regOptions);
        console.log("Credential registered:", registration.credentialId);
        
        // Convert credentialId to Base64 and store in local storage.
        const credentialIdBase64 = arrayBufferToBase64(registration.credentialId);
        localStorage.setItem("credentialId", credentialIdBase64);
    } catch (error) {
        console.error("Error in process:", (error as Error).message);
        document.getElementById("error")!.textContent = (error as Error).message;
    }
}

// Authenticate function
async function handleAuthenticate(): Promise<void> {
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

    // Retrieve the salt from local storage.
    const storedSaltBase64 = localStorage.getItem("registrationSalt");
    if (!storedSaltBase64) {
        console.error("No stored salt found.");
        document.getElementById("error")!.textContent = "No stored salt found.";
        return;
    }
    const storedSalt: ArrayBuffer = base64ToArrayBuffer(storedSaltBase64);

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
            prf: { eval: { first: new Uint8Array(32).fill(1) } },
        },
    };

    try {
        const assertion = await webAuthnService.authenticate(authOptions);
        console.log("PRF output received:", assertion.prfResult);

        // Use stored salt and PRF result in key derivation.
        const encryptionKey: EncryptionKey = {
            key: await keyService.deriveKey(assertion.prfResult, new Uint8Array(storedSalt)) 
        };
        console.log("Symmetric key derived.");

        // Encrypt and decrypt sample data.
        const sampleData = "Sensitive Data for SQLite DB";
        const encryptedData = await localDB.encryptData(sampleData, encryptionKey);
        console.log("Encrypted data:", new Uint8Array(encryptedData));

        const decryptedData = await localDB.decryptData(encryptedData, encryptionKey);
        console.log("Decrypted data:", decryptedData);

        // Load and display saved messages after successful authentication
        loadMessages();
    } catch (error) {
        console.error("Error in process:", (error as Error).message);
        document.getElementById("error")!.textContent = (error as Error).message;
    }
}


// Logout function
function handleLogout(): void {
    localStorage.removeItem("credentialId");  
    console.log("User logged out. Credential and messages removed.");
    document.getElementById("error")!.textContent = "Logged out successfully.";
}

// Main function to set up event listeners
export async function main(): Promise<void> {
    document.getElementById("registerBtn")?.addEventListener("click", handleRegister);
    document.getElementById("authenticateBtn")?.addEventListener("click", handleAuthenticate);
    document.getElementById("logoutBtn")?.addEventListener("click", handleLogout);
    document.getElementById("saveMessageBtn")?.addEventListener("click", saveMessage);
}
