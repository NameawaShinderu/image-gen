"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";
import crypto from "crypto-js";
/*
// Enhanced SecureStorage module with additional security features
const SecureStorage = {
  // Use a combination of factors for device fingerprinting
  getDeviceFingerprint: () => {
    // Get browser-specific information
    const nav = window.navigator;
    const screen = window.screen;
    const canvas = document.createElement('canvas');
    let canvasFingerprint = '';
    
    // Add canvas fingerprinting if supported (adds entropy)
    try {
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          canvasFingerprint = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) +
                             gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
        }
      }
    } catch (e) {
      // Ignore errors from canvas fingerprinting
    }
    
    // Combine multiple sources of entropy
    const fingerprint = [
      nav.userAgent,
      screen.height,
      screen.width,
      screen.colorDepth,
      nav.language,
      nav.platform,
      new Date().getTimezoneOffset(),
      !!nav.doNotTrack,
      !!window.indexedDB,
      !!window.localStorage,
      !!window.sessionStorage,
      canvasFingerprint
    ].join('||');
    
    // Use a strong hash
    return crypto.SHA256(fingerprint).toString();
  },
  
  // Generate a salted key for encrypting data
  getEncryptionKey: (additionalSalt = '') => {
    // Get stored salt or create one
    let salt = sessionStorage.getItem('_secureStorageSalt');
    if (!salt) {
      salt = crypto.lib.WordArray.random(128/8).toString();
      sessionStorage.setItem('_secureStorageSalt', salt);
    }
    
    // Combine device fingerprint with salt and additional salt
    const combinedKey = SecureStorage.getDeviceFingerprint() + salt + additionalSalt;
    return crypto.SHA256(combinedKey).toString();
  },


*/
// SecureStorage module for encrypted client-side storage
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

/*

  // Encrypt data before storing with an optional namespace
  setItem: (key: string, value: string, namespace = '') => {
    try {
      // Generate a unique IV for each encryption
      const iv = crypto.lib.WordArray.random(128/8);
      
      // Get the encryption key (possibly namespace-specific)
      const encryptionKey = SecureStorage.getEncryptionKey(namespace);
      
      // Encrypt the value
      const encrypted = crypto.AES.encrypt(value, encryptionKey, {
        iv: iv,
        mode: crypto.mode.CBC,
        padding: crypto.pad.Pkcs7
      });
      
      // Store IV with the encrypted data
      const storageValue = iv.toString() + '|' + encrypted.toString();
      sessionStorage.setItem(key, storageValue);
      
      // Add tamper detection
      const hash = crypto.SHA256(key + storageValue).toString();
      sessionStorage.setItem(`${key}_hash`, hash);
      
      return true;
    } catch (e) {
      console.error('SecureStorage encryption error:', e);
      return false;
    }
  },
*/
    // Encrypt data before storing
  setItem: (key: string, value: string) => {
    const deviceKey = SecureStorage.getDeviceFingerprint();
    const encryptedValue = crypto.AES.encrypt(value, deviceKey).toString();
    sessionStorage.setItem(key, encryptedValue);
  },
  


/*
// Decrypt data after retrieving
  getItem: (key: string, namespace = ''): string | null => {
    try {
      const storageValue = sessionStorage.getItem(key);
      if (!storageValue) return null;
      
      // Check for tampering
      const storedHash = sessionStorage.getItem(`${key}_hash`);
      const calculatedHash = crypto.SHA256(key + storageValue).toString();
      
      if (!storedHash || storedHash !== calculatedHash) {
        console.error('Possible tampering detected with storage item:', key);
        SecureStorage.removeItem(key);
        return null;
      }
      
      // Split IV and encrypted data
      const parts = storageValue.split('|');
      if (parts.length !== 2) {
        throw new Error('Invalid storage format');
      }
      
      const iv = parts[0];
      const encryptedText = parts[1];
      
      // Get the encryption key (possibly namespace-specific)
      const encryptionKey = SecureStorage.getEncryptionKey(namespace);
      
      // Decrypt the data
      const decryptedBytes = crypto.AES.decrypt(encryptedText, encryptionKey, {
        iv: crypto.enc.Hex.parse(iv),
        mode: crypto.mode.CBC,
        padding: crypto.pad.Pkcs7
      });
      
      return decryptedBytes.toString(crypto.enc.Utf8);
    } catch (e) {
      console.error('SecureStorage decryption error:', e);
      // Only remove on format errors, not decryption errors
      if (e.message !== 'Malformed UTF-8 data') {
        SecureStorage.removeItem(key);
      }
      return null;
    }
  },
  
  // Remove item and its hash
  removeItem: (key: string) => {
    sessionStorage.removeItem(key);
    sessionStorage.removeItem(`${key}_hash`);
  },
  
  // Clear all secure storage items
  clear: () => {
    sessionStorage.clear();
  },
  */
 
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

// Define interfaces for type safety
interface ImageItem {
  id: number;
  site_name: string;
}

interface TokenData {
  token: string;
  expiry: number;
}

export default function Dashboard() {
  const [images, setImages] = useState<ImageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [showSiteNameModal, setShowSiteNameModal] = useState(false);
  const [siteName, setSiteName] = useState("");
  const [currentFile, setCurrentFile] = useState<File | null>(null);
  const router = useRouter();

  // Check token expiration and try to refresh if needed
  const checkAndRefreshToken = async (): Promise<boolean> => {
    try {
      const tokenDataStr = SecureStorage.getItem("tokenData");
      if (!tokenDataStr) {
        router.push("/login");
        return false;
      }
      
      const tokenData: TokenData = JSON.parse(tokenDataStr);
      const currentTime = Math.floor(Date.now() / 1000);
      
      // If token is still valid, return true
      if (tokenData.expiry > currentTime) {
        return true;
      }
      
      // Otherwise, try to refresh the token
      const username = SecureStorage.getItem("username");
      if (!username) {
        router.push("/login");
        return false;
      }
      
      // The refresh token is in the HttpOnly cookie
      const response = await axios.post("http://localhost:8000/refresh-token", {
        username
      }, { 
        withCredentials: true 
      });
      
      // Store new token data
      SecureStorage.setItem("tokenData", JSON.stringify({
        token: response.data.token,
        expiry: response.data.expiry
      }));
      
      return true;
    } catch (error) {
      console.error("Token refresh failed:", error);
      SecureStorage.clear();
      router.push("/login");
      return false;
    }
  };
  
  // Get the master password by decrypting it
  const getMasterPassword = (): string | null => {
    const username = SecureStorage.getItem("username");
    if (!username) return null;
    
    const encryptedMasterPassword = SecureStorage.getItem("encryptedMasterPassword");
    if (!encryptedMasterPassword) return null;
    
    try {
      // Decrypt using derived key from username+device
      const encryptionKey = crypto.SHA256(username + SecureStorage.getDeviceFingerprint()).toString();
      const decryptedBytes = crypto.AES.decrypt(encryptedMasterPassword, encryptionKey);
      return decryptedBytes.toString(crypto.enc.Utf8);
    } catch (error) {
      console.error("Failed to decrypt master password");
      return null;
    }
  };

  useEffect(() => {
    const fetchImages = async () => {
      try {
        // Validate/refresh token first
        const isTokenValid = await checkAndRefreshToken();
        if (!isTokenValid) return;
        
        const username = SecureStorage.getItem("username");
        const tokenData = SecureStorage.getItem("tokenData");
        
        if (!username || !tokenData) {
          router.push("/login");
          return;
        }
        
        const { token } = JSON.parse(tokenData);
        
        // Use POST instead of GET with query parameters
        const response = await axios.post("http://localhost:8000/images", {
          username,
          token
        });

        setImages(response.data);
      } catch (error) {
        console.error("Error fetching images:", error);
        router.push("/login");
      } finally {
        setLoading(false);
      }
    };
    
    fetchImages();
  }, [router]);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!event.target.files?.[0]) return;
    setCurrentFile(event.target.files[0]);
    setShowSiteNameModal(true);
  };
  
  const handleUpload = async () => {
    if (!currentFile || !siteName) return;
    
    setUploading(true);
    setShowSiteNameModal(false);
    
    // Validate/refresh token first
    const isTokenValid = await checkAndRefreshToken();
    if (!isTokenValid) return;
    
    const username = SecureStorage.getItem("username");
    const tokenData = SecureStorage.getItem("tokenData");
    const masterPassword = getMasterPassword();
    
    if (!username || !tokenData || !masterPassword) {
      if (!masterPassword) {
        alert("Session expired. Please log in again to access your master password.");
        router.push("/login");
      }
      setUploading(false);
      return;
    }
    
    const { token } = JSON.parse(tokenData);
  
    try {
      // Create FormData payload
      const formData = new FormData();
      formData.append("username", username);
      formData.append("token", token);
      formData.append("password", masterPassword);
      formData.append("site_name", siteName);
      formData.append("file", currentFile);
  
      // Upload the image
      await axios.post("http://localhost:8000/upload-image", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
  
      // Refresh image list
      const response = await axios.post("http://localhost:8000/images", {
        username,
        token
      });
      
      setImages(response.data);
      alert("Image uploaded successfully!");
    } catch (error: any) {
      console.error("Upload failed:", error);
      alert(`Upload failed: ${error.response?.data?.detail || error.message}`);
    } finally {
      setUploading(false);
      setSiteName("");
      setCurrentFile(null);
    }
  };

  const handleDownload = async (imageId: number) => {
    // Validate/refresh token first
    const isTokenValid = await checkAndRefreshToken();
    if (!isTokenValid) return;
    
    const username = SecureStorage.getItem("username");
    const tokenData = SecureStorage.getItem("tokenData");
    const masterPassword = getMasterPassword();
  
    if (!masterPassword || !username || !tokenData) {
      if (!masterPassword) {
        alert("Session expired. Please log in again to access your master password.");
        router.push("/login");
      }
      return;
    }
  
    const { token } = JSON.parse(tokenData);
  
    try {
      // Send download request with image_id in the request body
      const response = await axios.post("http://localhost:8000/download", {
        username, 
        token,
        password: masterPassword,
        image_id: imageId  // Include as part of the request body
      });
  
      // Convert base64 to blob
      const binaryData = atob(response.data.image_data);
      const bytes = new Uint8Array(binaryData.length);
      for (let i = 0; i < binaryData.length; i++) {
        bytes[i] = binaryData.charCodeAt(i);
      }
      
      const blob = new Blob([bytes], { type: 'image/png' });
      
      // Create download
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = response.data.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error: any) {
      console.error("Download failed:", error);
      alert(`Download failed: ${error.response?.data?.detail || "Wrong password or corrupted file"}`);
    }
  };

//ASK JOSHI TO SEE THIS PART AND CHECK WHICH IS MORE SECURE
/*
  const handleDownload = async (imageId: number) => {
    // Validate/refresh token first
    const isTokenValid = await checkAndRefreshToken();
    if (!isTokenValid) return;
    
    const username = SecureStorage.getItem("username");
    const tokenData = SecureStorage.getItem("tokenData");
    const masterPassword = getMasterPassword();

    if (!masterPassword || !username || !tokenData) {
      if (!masterPassword) {
        alert("Session expired. Please log in again to access your master password.");
        router.push("/login");
      }
      return;
    }

    const { token } = JSON.parse(tokenData);

    try {
      // Get encrypted data from server using POST instead of GET
      const response = await axios.post("http://localhost:8000/download", {
        username, 
        token,
        password: masterPassword,
        image_id: imageId
      });

      // Convert base64 to blob
      const binaryData = atob(response.data.image_data);
      const bytes = new Uint8Array(binaryData.length);
      for (let i = 0; i < binaryData.length; i++) {
        bytes[i] = binaryData.charCodeAt(i);
      }
      
      const blob = new Blob([bytes], { type: 'image/png' });
      
      // Create download
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = response.data.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error: any) {
      console.error("Download failed:", error);
      alert("Download failed: Wrong password or corrupted file");
    }
  };

*/
  const handleLogout = async () => {
    try {
      const username = SecureStorage.getItem("username");
      const tokenData = SecureStorage.getItem("tokenData");
      
      if (username && tokenData) {
        const { token } = JSON.parse(tokenData);
        
        // Use POST instead of query parameters
        await axios.post("http://localhost:8000/logout", {
          username, 
          token
        }, {
          withCredentials: true // For clearing the refresh token cookie
        });
      }
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      // Clear all secure storage
      SecureStorage.clear();
      router.push("/login");
    }
  };

  // Modal for site name input
  const SiteNameModal = () => {
    if (!showSiteNameModal) return null;
    
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white p-6 rounded-lg shadow-lg w-96">
          <h2 className="text-xl font-semibold mb-4">Image Details</h2>
          <div className="mb-4">
            <label className="block text-gray-700 mb-2" htmlFor="siteName">
              Site Name (e.g., Facebook, Gmail)
            </label>
            <input
              id="siteName"
              type="text"
              value={siteName}
              onChange={(e) => setSiteName(e.target.value)}
              className="w-full p-2 border rounded"
              placeholder="Enter a name for this image"
              autoFocus
            />
          </div>
          <div className="flex justify-end space-x-3">
            <button
              onClick={() => {
                setShowSiteNameModal(false);
                setCurrentFile(null);
                setSiteName("");
              }}
              className="px-4 py-2 border rounded hover:bg-gray-100"
            >
              Cancel
            </button>
            <button
              onClick={handleUpload}
              disabled={!siteName}
              className={`px-4 py-2 rounded text-white ${
                siteName ? "bg-blue-500 hover:bg-blue-600" : "bg-blue-300 cursor-not-allowed"
              }`}
            >
              Upload
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center p-8">
      {/* Site Name Modal */}
      <SiteNameModal />
      
      <div className="w-full max-w-4xl">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Secure Image Vault</h1>
          <button 
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
          >
            Logout
          </button>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md mb-8">
          <h2 className="text-xl font-semibold mb-4">Upload New Image</h2>
          <div className="flex flex-col sm:flex-row items-center gap-4">
            <label className="flex-1 w-full">
              <div className={`bg-blue-50 border-2 border-dashed rounded-lg p-8 text-center cursor-pointer
                ${uploading ? 'border-gray-300' : 'border-blue-300 hover:bg-blue-100'}`}>
                <p className={uploading ? 'text-gray-500' : 'text-blue-500'}>
                  {uploading ? "Encrypting and Uploading..." : "Click to select an image"}
                </p>
                <input 
                  type="file" 
                  onChange={handleFileSelect} 
                  className="hidden" 
                  accept="image/*"
                  disabled={uploading}
                />
              </div>
            </label>
          </div>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Your Encrypted Images</h2>
          
          {loading ? (
            <p className="text-gray-500">Loading images...</p>
          ) : (
            <>
              {images.length === 0 ? (
                <p className="text-gray-500">No encrypted images found. Upload your first image above.</p>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {images.map((image, index) => (
                    <div key={index} className="border rounded-lg p-4 hover:shadow-md transition">
                      <div className="flex flex-col h-full justify-between">
                        <div className="mb-3">
                          <h3 className="font-medium">{image.site_name}</h3>
                          <p className="text-sm text-gray-500">Encrypted Image</p>
                        </div>
                        <button
                          onClick={() => handleDownload(image.id)}
                          className="bg-blue-500 text-white w-full px-3 py-2 rounded hover:bg-blue-600"
                        >
                          Decrypt & Download
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}