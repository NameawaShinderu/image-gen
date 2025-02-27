"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";
import crypto from "crypto-js";

// Create a secure storage module that encrypts data before storing
const SecureStorage = {
  // Use the device fingerprint as part of the encryption key
  getDeviceFingerprint: () => {
    const nav = window.navigator;
    const screen = window.screen;
    const fingerprint = [
      nav.userAgent,
      screen.height,
      screen.width,
      nav.language,
      nav.platform,
      new Date().getTimezoneOffset()
    ].join('||');
    return crypto.SHA256(fingerprint).toString();
  },
  
  // Encrypt data before storing
  setItem: (key: string, value: string) => {
    const deviceKey = SecureStorage.getDeviceFingerprint();
    const encryptedValue = crypto.AES.encrypt(value, deviceKey).toString();
    sessionStorage.setItem(key, encryptedValue);
  },
  
  // Decrypt data after retrieving
  getItem: (key: string): string | null => {
    const encryptedValue = sessionStorage.getItem(key);
    if (!encryptedValue) return null;
    
    try {
      const deviceKey = SecureStorage.getDeviceFingerprint();
      const decryptedBytes = crypto.AES.decrypt(encryptedValue, deviceKey);
      return decryptedBytes.toString(crypto.enc.Utf8);
    } catch (e) {
      // If decryption fails (device changed or tampering), clear the storage
      sessionStorage.removeItem(key);
      return null;
    }
  },
  
  removeItem: (key: string) => {
    sessionStorage.removeItem(key);
  },
  
  clear: () => {
    sessionStorage.clear();
  }
};

interface TokenData {
  token: string;
  expiry: number;
}

export default function Login() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [isRegister, setIsRegister] = useState(false);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);
    const router = useRouter();

    // Check for existing session on load
    useEffect(() => {
      const checkSession = async () => {
        const tokenData = SecureStorage.getItem("tokenData");
        
        if (tokenData) {
          try {
            const parsedToken: TokenData = JSON.parse(tokenData);
            const currentTime = Math.floor(Date.now() / 1000);
            
            // If token is valid and not expired, redirect to dashboard
            if (parsedToken.token && parsedToken.expiry > currentTime) {
              router.push("/dashboard");
              return;
            }
            
            // If token is expired, try to refresh
            await refreshToken();
          } catch (err) {
            // Invalid token format, clear storage
            SecureStorage.clear();
          }
        }
      };
      
      checkSession();
    }, [router]);
    
    const refreshToken = async () => {
      try {
        const tokenData = SecureStorage.getItem("tokenData");
        if (!tokenData) return false;
        
        const parsedToken: TokenData = JSON.parse(tokenData);
        const storedUsername = SecureStorage.getItem("username");
        
        if (!storedUsername) return false;
        
        // Use HTTP-only cookie set by server for refresh token
        const response = await axios.post("http://localhost:8000/refresh-token", {
          username: storedUsername,
          refresh_token: "" // The refresh token is in the cookie
        }, {
          withCredentials: true // Important to include cookies
        });
        
        // Store new access token
        SecureStorage.setItem("username", storedUsername);
        SecureStorage.setItem("tokenData", JSON.stringify({
          token: response.data.token,
          expiry: response.data.expiry
        }));
        
        return true;
      } catch (error) {
        console.error("Token refresh failed:", error);
        SecureStorage.clear(); // Clear invalid session
        return false;
      }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");

        try {
            if (isRegister) {
                // Registration
                const salt = crypto.lib.WordArray.random(128/8).toString();
                const verifier = crypto.PBKDF2(password, salt, {
                    keySize: 256/32,
                    iterations: 600000
                }).toString();
                
                await axios.post("http://localhost:8000/register", {
                    username,
                    verifier,
                    salt
                });
                
                setError("Registration successful! Please login.");
                setIsRegister(false);
            } else {
                // Login
                const challengeRes = await axios.post("http://localhost:8000/challenge", { username });
                const challenge = challengeRes.data.challenge;
                
                const { verifier } = await axios.get(`http://localhost:8000/verifier/${username}`).then(res => res.data);
                const response = crypto.SHA256(challenge + verifier).toString();
                
                const loginRes = await axios.post("http://localhost:8000/login", {
                    username,
                    response
                }, {
                    withCredentials: true // Important to include cookies for refresh token
                });
                
                // Store access token in secure storage
                SecureStorage.setItem("username", username);
                SecureStorage.setItem("tokenData", JSON.stringify({
                  token: loginRes.data.token,
                  expiry: loginRes.data.expiry
                }));
                
                // Encrypt master password with a key derived from username+device fingerprint
                // before storing in session storage
                const encryptionKey = crypto.SHA256(username + SecureStorage.getDeviceFingerprint()).toString();
                const encryptedPassword = crypto.AES.encrypt(password, encryptionKey).toString();
                SecureStorage.setItem("encryptedMasterPassword", encryptedPassword);
                
                router.push("/dashboard");
            }
        } catch (error: any) {
            console.error("Authentication error:", error);
            setError(error.response?.data?.detail || "Authentication failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
          <div className="bg-white p-8 rounded-lg shadow-md w-96">
            <h1 className="text-2xl font-bold mb-6">
              {isRegister ? "Register" : "Login"}
            </h1>
            
            {error && (
              <div className={`border px-4 py-3 rounded mb-4 ${error.includes("successful") ? 
                "bg-green-100 border-green-400 text-green-700" : 
                "bg-red-100 border-red-400 text-red-700"}`}>
                {error}
              </div>
            )}
            
            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label className="block text-gray-700 mb-2" htmlFor="username">
                  Username
                </label>
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              
              <div className="mb-6">
                <label className="block text-gray-700 mb-2" htmlFor="password">
                  Master Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full p-2 border rounded"
                  required
                />
                <p className="text-sm text-gray-500 mt-1">
                  This password will be used to encrypt and decrypt your images.
                  {isRegister && " Remember it carefully as it cannot be recovered!"}
                </p>
              </div>
              
              <button
                type="submit"
                className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
                disabled={loading}
              >
                {loading ? "Processing..." : isRegister ? "Register" : "Login"}
              </button>
            </form>
            
            <div className="mt-4 text-center">
              <button
                onClick={() => setIsRegister(!isRegister)}
                className="text-blue-500 hover:underline"
              >
                {isRegister ? "Already have an account? Login" : "Need an account? Register"}
              </button>
            </div>
          </div>
        </div>
    );
}